#include "quicsand_api.h"

#define MSQUIC 1

#ifdef QUICHE

#include <inttypes.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

#include <fcntl.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <ev.h>
#include <quiche.h>

#define LOCAL_CONN_ID_LEN 16

#define MAX_DATAGRAM_SIZE 1350

struct conn_io
{
    ev_timer timer;

    int sock;

    struct sockaddr_storage local_addr;
    socklen_t local_addr_len;

    quiche_conn *conn;
};

struct context
{
    struct conn_io *conn_io;

    struct ev_loop *loop;
    struct ev_io watcher;
    struct ev_timer timer;
    char *host;
    char *port;
    struct addrinfo *peer;
    quiche_config *config;
    uint8_t scid[LOCAL_CONN_ID_LEN];
};

#elif MSQUIC

#include <msquic.h>
#include <pthread.h>
#include <unistd.h>
#include <limits.h>
#include <arpa/inet.h>

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(P) (void)(P)
#endif

int connected = 0;
int streamStarted = 0;

struct context
{
    QUIC_API_TABLE *msquic;

    QUIC_REGISTRATION_CONFIG reg_config;
    QUIC_BUFFER alpn;
    uint64_t idle_timeout_ms;
    HQUIC registration;
    HQUIC configuration;
    union {
        struct client
        {
            HQUIC connection;
            HQUIC stream;
            size_t request_size;
        } c;
        struct server
        {
            HQUIC listener;
            QUIC_ADDR local_address;
        } s;
    };
    struct Buffer
    {
        QUIC_BUFFER *quic_buffer;
        pthread_mutex_t mutex;
        pthread_cond_t cond;
    } *recv_buff;
};

#elif LSQUIC

#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>

#include <ev.h>
#include <lsquic.h>

struct context {

    /* Common elements needed by both client and server: */
    enum {
        SERVER  = 1 << 0,
    }                           flags;
    int                         sock_fd;    /* socket */
    ev_io                       sock_w;     /* socket watcher */
    ev_timer                    timer;
    struct ev_loop             *loop;
    lsquic_engine_t            *engine;
    struct sockaddr_storage     local_sas;
    union
    {
        struct client
        {
            ev_io               stdin_w;    /* stdin watcher */
            struct lsquic_conn *conn;
            size_t              sz;         /* Size of bytes read is stored here */
            char                buf[0x100]; /* Read up to this many bytes */
        }   c;
    };   
};

#define MAX(a, b) ((a) > (b) ? (a) : (b))

#endif

context_t create_quic_context(mode_t mode) {
    #ifdef QUICHE

        printf("Using quiche\n");

        struct context *ctx = (struct context *)malloc(sizeof(struct context));

        ctx->config = quiche_config_new(0xbabababa);
        if (ctx->config == NULL)
        {
            fprintf(stderr, "failed to create config\n");
            exit(EXIT_FAILURE);
        }

        quiche_config_set_application_protos(ctx->config,
                                            (uint8_t *)"\x0ahq-interop\x05hq-29\x05hq-28\x05hq-27\x08http/0.9", 38);
        quiche_config_set_max_idle_timeout(ctx->config, 5000);
        quiche_config_set_max_recv_udp_payload_size(ctx->config, MAX_DATAGRAM_SIZE);
        quiche_config_set_max_send_udp_payload_size(ctx->config, MAX_DATAGRAM_SIZE);
        quiche_config_set_initial_max_data(ctx->config, 10000000);
        quiche_config_set_initial_max_stream_data_bidi_local(ctx->config, 1000000);
        quiche_config_set_initial_max_stream_data_uni(ctx->config, 1000000);
        quiche_config_set_initial_max_streams_bidi(ctx->config, 100);
        quiche_config_set_initial_max_streams_uni(ctx->config, 100);
        quiche_config_set_disable_active_migration(ctx->config, true);

        if (getenv("SSLKEYLOGFILE"))
        {
            quiche_config_log_keys(ctx->config);
        }
    
    #elif MSQUIC
    printf("Using msquic\n");
    struct context *ctx = (struct context *)malloc(sizeof(struct context));
    ctx->reg_config = (QUIC_REGISTRATION_CONFIG){"quicsand", QUIC_EXECUTION_PROFILE_LOW_LATENCY};
    ctx->alpn = (QUIC_BUFFER){sizeof("quicsand") - 1, (uint8_t *)"quicsand"};
    ctx->idle_timeout_ms = 1000;

    QUIC_STATUS status = QUIC_STATUS_SUCCESS;
    //
    // Open a handle to the library and get the API function table.
    //
    if (QUIC_FAILED(status = MsQuicOpen2(&ctx->msquic)))
    {
        printf("MsQuicOpen2 failed, 0x%x!\n", status);
        exit(EXIT_FAILURE);
    }

    //
    // Create a registration for the app's connections.
    //
    if (QUIC_FAILED(status = ctx->msquic->RegistrationOpen(&ctx->reg_config, &ctx->registration)))
    {
        printf("RegistrationOpen failed, 0x%x!\n", status);
        exit(EXIT_FAILURE);
    }

    // Ensure recvBuffer is initialized
    ctx->recv_buff = malloc(sizeof(*ctx->recv_buff));
    if (ctx->recv_buff == NULL)
    {
        printf("recv_buff allocation failed!\n");
        // Handle memory allocation failure
        exit(EXIT_FAILURE);
    }

    // Allocate memory for the destination buffer
    ctx->recv_buff->quic_buffer = NULL;
    if ((ctx->recv_buff->quic_buffer = (QUIC_BUFFER *)malloc(sizeof(QUIC_BUFFER))) == NULL)
    {
        printf("recv_buff allocation failed!\n");
        // Handle memory allocation failure
        exit(EXIT_FAILURE);
    }
    ctx->recv_buff->quic_buffer->Length = 0;
    pthread_mutex_init(&ctx->recv_buff->mutex, NULL);
    pthread_cond_init(&ctx->recv_buff->cond, NULL);
    printf("recvBuffer allocated\n");

    //
    // Configures the idle timeout.
    //
    QUIC_SETTINGS settings = {0};
    settings.IdleTimeoutMs = ctx->idle_timeout_ms;
    settings.IsSet.IdleTimeoutMs = TRUE;

    QUIC_CREDENTIAL_CONFIG cred_config;
    memset(&cred_config, 0, sizeof(cred_config));

    if (mode == QUIC_CLIENT) {
        cred_config.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
        cred_config.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
    }
    else if (mode == QUIC_SERVER) {
        settings.ServerResumptionLevel = QUIC_SERVER_RESUME_AND_ZERORTT;
        settings.IsSet.ServerResumptionLevel = TRUE;
        settings.PeerBidiStreamCount = 1;
        settings.IsSet.PeerBidiStreamCount = TRUE;

        cred_config.Flags = QUIC_CREDENTIAL_FLAG_NONE;
        cred_config.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;

        QUIC_CERTIFICATE_FILE CertFile;
        char cwd[PATH_MAX];
        char cert_path[PATH_MAX];
        char key_path[PATH_MAX];
        if (getcwd(cwd, sizeof(cwd)) == NULL)
        {
            perror("getcwd() error");
            exit(EXIT_FAILURE);
        }
        strcpy(cert_path, cwd);
        strcpy(key_path, cwd);
        strcat(cert_path, "/certs/quicsand-server.pem");
        strcat(key_path, "/certs/key.pem");
        CertFile.CertificateFile = cert_path;
        CertFile.PrivateKeyFile = key_path;
        fprintf(stderr, "cert_path: %s\n", cert_path);
        fprintf(stderr, "key_path: %s\n", key_path);
        cred_config.CertificateFile = &CertFile;
    } 
    else {
        printf("Invalid mode\n");
        exit(EXIT_FAILURE);
    }

    // Allocate/initialize the configuration object, with the configured ALPN
    // and settings.
    //
    if (QUIC_FAILED(status = ctx->msquic->ConfigurationOpen(ctx->registration, &ctx->alpn, 1, &settings, sizeof(settings), NULL, &ctx->configuration)))
    {
        printf("ConfigurationOpen failed, 0x%x!\n", status);
        exit(EXIT_FAILURE);
    }

    //
    // Loads the TLS credential part of the configuration. This is required even
    // on client side, to indicate if a certificate is required or not.
    //
    if (QUIC_FAILED(status = ctx->msquic->ConfigurationLoadCredential(ctx->configuration, &cred_config)))
    {
        printf("ConfigurationLoadCredential failed, 0x%x!\n", status);
        exit(EXIT_FAILURE);
    }

    #elif LSQUIC
    printf("Using lsquic\n");
    #endif
    return (context_t) ctx;
}

void bind_addr(context_t context, char* ip, int port) {
    fprintf(stderr, "Binding to %s:%d\n", ip, port);
    #ifdef QUICHE
        struct context *ctx = (struct context *)context;

        const struct addrinfo hints = {
        .ai_family = PF_UNSPEC,
        .ai_socktype = SOCK_DGRAM,
        .ai_protocol = IPPROTO_UDP};

        if (getaddrinfo(ip, port, &hints, &ctx->peer) != 0)
        {
            perror("failed to resolve host");
            exit(EXIT_FAILURE);
        }
    #elif MSQUIC
    struct context *ctx = (struct context *)context;

    QUIC_ADDR address = {0};
    if (inet_pton(QUIC_ADDRESS_FAMILY_INET, ip, &address.Ipv4.sin_addr) <= 0) {
        perror("inet_pton");
        exit(EXIT_FAILURE);
    }
    address.Ipv4.sin_family = QUIC_ADDRESS_FAMILY_INET;
    address.Ipv4.sin_port = htons(port);
    ctx->s.local_address = address;

    #elif LSQUIC
    #endif
}

connection_t open_connection(context_t context, char* ip, int port) {
    #ifdef QUICHE
    struct context *ctx = (struct context *)context;

    int sock = socket(ctx->peer->ai_family, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        perror("failed to create socket");
        exit(EXIT_FAILURE);
    }

    if (fcntl(sock, F_SETFL, O_NONBLOCK) != 0)
    {
        perror("failed to make socket non-blocking");
        exit(EXIT_FAILURE);
    }

    int rng = open("/dev/urandom", O_RDONLY);
    if (rng < 0)
    {
        perror("failed to open /dev/urandom");
        exit(EXIT_FAILURE);
    }

    ssize_t rand_len = read(rng, &ctx->scid, sizeof(ctx->scid));
    if (rand_len < 0)
    {
        perror("failed to create connection ID");
        exit(EXIT_FAILURE);
    }

    ctx->conn_io = malloc(sizeof(*ctx->conn_io));
    if (ctx->conn_io == NULL)
    {
        fprintf(stderr, "failed to allocate connection IO\n");
        exit(EXIT_FAILURE);
    }

    ctx->conn_io->local_addr_len = sizeof(ctx->conn_io->local_addr);
    if (getsockname(sock, (struct sockaddr *)&ctx->conn_io->local_addr,
                    &ctx->conn_io->local_addr_len) != 0)
    {
        perror("failed to get local address of socket");
        exit(EXIT_FAILURE);
    };

    quiche_conn *conn = quiche_connect(ctx->host, (const uint8_t *)ctx->scid, sizeof(ctx->scid),
                                       (struct sockaddr *)&ctx->conn_io->local_addr,
                                       ctx->conn_io->local_addr_len,
                                       ctx->peer->ai_addr, ctx->peer->ai_addrlen, ctx->config);

    if (conn == NULL)
    {
        fprintf(stderr, "failed to create connection\n");
        exit(EXIT_FAILURE);
    }

    ctx->conn_io->sock = sock;
    ctx->conn_io->conn = conn;
    return (connection_t) ctx->conn_io;
    #elif MSQUIC
    struct context *ctx = (struct context *)context;
    QUIC_STATUS status;

    if (QUIC_FAILED(status = ctx->msquic->ConnectionOpen(ctx->registration, (QUIC_LISTENER_CALLBACK_HANDLER)NULL, NULL, &ctx->c.connection)))
    {
        printf("ConnectionOpen failed, 0x%x!\n", status);
        exit(EXIT_FAILURE);
    }

    printf("[conn][%p] Connecting...\n", (void *)ctx->c.connection);

    //
    // Start the connection to the server.
    //
    if (QUIC_FAILED(status = ctx->msquic->ConnectionStart(ctx->c.connection, ctx->configuration, QUIC_ADDRESS_FAMILY_INET, ip, (uint16_t)port)))
    {
        printf("ConnectionStart failed, 0x%x!\n", status);
        exit(EXIT_FAILURE);
    }

    printf("[conn][%p] Started\n", (void *)ctx->c.connection);
    return (connection_t) ctx->c.connection;
    #elif LSQUIC
    struct context *ctx = (struct context *)context;
    #endif
}

void close_connection(context_t context, connection_t connection) {
    
}

stream_t open_stream(context_t context, connection_t connection) {
    stream_t stream = malloc(sizeof(stream_t));
    return stream;
}

void close_stream(context_t context, connection_t connection, stream_t stream) {
    
}

void send_data(context_t context, connection_t connection, char* data, int len) {
    
}

char* recv_data(context_t context, connection_t connection,int buffer_size, time_t timeout) {
    return NULL;
}

void set_listen(context_t context) {
    #ifdef QUICHE
    struct context *ctx = (struct context *)context;
    #elif MSQUIC
    struct context *ctx = (struct context *)context;
    QUIC_STATUS status = QUIC_STATUS_SUCCESS;
    if (QUIC_FAILED(status = ctx->msquic->ListenerOpen(ctx->registration, (QUIC_LISTENER_CALLBACK_HANDLER)NULL, NULL, &ctx->s.listener)))
    {
        printf("ListenerOpen failed, 0x%x!\n", status);
        exit(EXIT_FAILURE);
    }
    printf("Listener opened.\n");
    #elif LSQUIC
    struct context *ctx = (struct context *)context;
    #endif
}

connection_t accept_connection(context_t context, time_t timeout) {
    connection_t connection = malloc(sizeof(connection_t));
    return connection;
}

stream_t accept_stream(context_t context, connection_t connection, time_t timeout) {
    stream_t stream = malloc(sizeof(stream_t));
    return stream;
}