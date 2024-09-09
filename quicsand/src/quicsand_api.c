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
#include <ev.h>
#include <time.h>

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(P) (void)(P)
#endif

#ifndef NULL
#define NULL (void *)0
#endif


#define MAX_STREAMS 50
#define MAX_CONNECTIONS 50

typedef struct {
    HQUIC stream;
    uint64_t stream_id;
    int established;
    pthread_mutex_t lock;
    pthread_cond_t cond;
} stream_info_t;

typedef struct stream_node{
    stream_info_t *stream_info;
    struct stream_node *prev;
    struct stream_node *next;
} stream_node_t;

typedef struct {
    HQUIC connection;
    stream_node_t *streams;
    stream_node_t *new_stream;
    size_t stream_count;
    int connected;
    pthread_mutex_t lock;
    pthread_cond_t cond;
} connection_info_t;

typedef struct connection_node { 
    connection_info_t *connection_info;
    struct connection_node *prev;
    struct connection_node *next;
} connection_node_t;

typedef struct {
    struct context *ctx;
    connection_info_t *connection_info;
} ctx_conn_t;

typedef struct {
    struct context *ctx;
    connection_info_t *connection_info;
    stream_info_t *stream_info;
} ctx_strm_t;

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
            QUIC_ADDR local_address;
        } c;
        struct server
        {
            HQUIC listener;
            QUIC_ADDR local_address;
        } s;
    };
    struct Buffer
    {
        QUIC_BUFFER *buffers;
        pthread_mutex_t lock;
        pthread_cond_t cond;
    } recv_buff;

    connection_node_t *connections;
    size_t connection_count;
    connection_node_t *new_connection;
    pthread_mutex_t lock;
    pthread_cond_t cond;
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

/*
    auxillary functions
*/

#ifdef QUICHE
#elif MSQUIC

stream_node_t* push_stream(stream_node_t *head, stream_info_t *stream_info) {
    stream_node_t *current = head;
    while (current->next != NULL) {
        current = current->next;
    }
    current->next = (stream_node_t *)malloc(sizeof(stream_node_t));
    current->next->stream_info = stream_info;
    current->next->next = NULL;
    return current->next;
}

connection_node_t* push_connection(connection_node_t *head, connection_info_t *connection_info) {
    connection_node_t *current = head;
    while (current->next != NULL) {
        current = current->next;
    }
    current->next = (connection_node_t *)malloc(sizeof(connection_node_t));
    current->next->connection_info = connection_info;
    current->next->next = NULL;
    return current->next;
}

connection_info_t* find_connection(connection_node_t *head, HQUIC connection) {
    connection_node_t *current = head;
    while (current != NULL) {
        if (current->connection_info->connection == connection) {
            return current->connection_info;
        }
        current = current->next;
    }
    return (connection_info_t*)NULL;
}

stream_info_t* find_stream(stream_node_t **head, HQUIC stream) {
    stream_node_t *current = *head;
    while (current != NULL) {
        if (current->stream_info->stream == stream) {
            return current->stream_info;
        }
        current = current->next;
    }
    return (stream_info_t*)NULL;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_STREAM_CALLBACK)
        QUIC_STATUS
    QUIC_API
    stream_callback(
        _In_ HQUIC stream,
        _In_opt_ void *context,
        _Inout_ QUIC_STREAM_EVENT *event)
{
    ctx_strm_t *ctx_strm = (ctx_strm_t *)context;
    struct context *ctx = ctx_strm->ctx;
    connection_info_t *connection_info = ctx_strm->connection_info;
    stream_info_t *stream_info = ctx_strm->stream_info;
    switch (event->Type)
    {
    case QUIC_STREAM_EVENT_START_COMPLETE:
        //
        // The start of the stream has completed. The app MUST set the callback
        // handler before returning.
        //
        pthread_mutex_lock(&connection_info->lock);
        stream_info->established = 1;
        printf("[strm][%p] Start complete\n", (void *)stream);
        pthread_cond_signal(&connection_info->cond);
        pthread_mutex_unlock(&connection_info->lock);
        break;
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        //
        // A previous StreamSend call has completed, and the context is being
        // returned back to the app.
        //
        free(event->SEND_COMPLETE.ClientContext);
        printf("[strm][%p] Data sent\n", (void *)stream);
        break;
    case QUIC_STREAM_EVENT_RECEIVE:
        //
        // Data was received from the peer on the stream.
        //
        pthread_mutex_lock(&ctx->recv_buff.lock);
        printf("[strm][%p] Data received\n", (void *)stream);
        printf("Data: %.*s\n", (int)event->RECEIVE.TotalBufferLength, event->RECEIVE.Buffers[0].Buffer);
        *ctx->recv_buff.buffers = *event->RECEIVE.Buffers;
        pthread_cond_signal(&ctx->recv_buff.cond);
        pthread_mutex_unlock(&ctx->recv_buff.lock);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        //
        // The peer gracefully shut down its send direction of the stream.
        //
        printf("[strm][%p] Peer shut down\n", (void *)stream);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        //
        // The peer aborted its send direction of the stream.
        //
        printf("[strm][%p] Peer aborted\n", (void *)stream);
        ctx->msquic->StreamShutdown(stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        //
        // Both directions of the stream have been shut down and MsQuic is done
        // with the stream. It can now be safely cleaned up.
        //
        printf("[strm][%p] All done\n", (void *)stream);
        ctx->msquic->StreamClose(stream);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_CONNECTION_CALLBACK)
        QUIC_STATUS
    QUIC_API
    connection_callback(
        _In_ HQUIC connection,
        _In_opt_ void *context,
        _Inout_ QUIC_CONNECTION_EVENT *event)
{
    ctx_conn_t *ctx_conn = (ctx_conn_t *)context;
    struct context *ctx = ctx_conn->ctx;
    connection_info_t *connection_info = ctx_conn->connection_info;
    switch (event->Type)
    {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        //
        // The handshake has completed for the connection.
        //
        pthread_mutex_lock(&ctx->lock);
        connection_info->connected = 1;
        connection_node_t *connection_node = push_connection(ctx->connections, connection_info);
        ctx->new_connection = connection_node;
        printf("[conn][%p] Connected\n", (void *)connection);
        pthread_cond_signal(&ctx->cond);
        pthread_mutex_unlock(&ctx->lock);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        //
        // The connection has been shut down by the transport. Generally, this
        // is the expected way for the connection to shut down with this
        // protocol, since we let idle timeout kill the connection.
        //
        if (event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status == QUIC_STATUS_CONNECTION_IDLE)
        {
            printf("[conn][%p] Successfully shut down on idle.\n", (void *)connection);
        }
        else
        {
            printf("[conn][%p] Shut down by transport, 0x%x\n", (void *)connection, event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
        }
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        //
        // The connection was explicitly shut down by the peer.
        //
        printf("[conn][%p] Shut down by peer, 0x%llu\n", (void *)connection, (unsigned long long)event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        //
        // The connection has completed the shutdown process and is ready to be
        // safely cleaned up.
        //
        printf("[conn][%p] All done\n", (void *)connection);
        if (!event->SHUTDOWN_COMPLETE.AppCloseInProgress)
        {
            ctx->msquic->ConnectionClose(connection);
        }
        break;
    case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
        //
        // A resumption ticket (also called New Session Ticket or NST) was
        // received from the server.
        //
        printf("[conn][%p] Resumption ticket received (%u bytes):\n", (void *)connection, event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength);
        for (uint32_t i = 0; i < event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength; i++)
        {
            printf("%.2X", (uint8_t)event->RESUMPTION_TICKET_RECEIVED.ResumptionTicket[i]);
        }
        printf("\n");
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        //
        // The peer has started/created a new stream. The app MUST set the
        // callback handler before returning.
        //
        printf("connection_info: %p\n", connection_info);
        pthread_mutex_lock(&connection_info->lock);
        printf("[strm][%p] Peer started\n", (void *)event->PEER_STREAM_STARTED.Stream);
        stream_info_t *stream_info = (stream_info_t *)malloc(sizeof(stream_info_t));
        stream_info->stream = event->PEER_STREAM_STARTED.Stream;
        stream_info->established = 1;
        stream_node_t *stream_node = push_stream(connection_info->streams, stream_info);
        connection_info->new_stream = stream_node;
        ctx_strm_t *ctx_strm = (ctx_strm_t *)malloc(sizeof(ctx_strm_t));
        ctx_strm->ctx = ctx;
        ctx_strm->connection_info = connection_info;
        ctx_strm->stream_info = stream_info;
        pthread_cond_signal(&connection_info->cond);
        pthread_mutex_unlock(&connection_info->lock);
        ctx->msquic->SetCallbackHandler(event->PEER_STREAM_STARTED.Stream, (void *)stream_callback, ctx_strm);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

//
// The server's callback for listener events from MsQuic.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
    _Function_class_(QUIC_LISTENER_CALLBACK)
        QUIC_STATUS
    QUIC_API
    listener_callback(
        _In_ HQUIC listener,
        _In_opt_ void *context,
        _Inout_ QUIC_LISTENER_EVENT *event)
{
    UNREFERENCED_PARAMETER(listener);
    struct context *ctx = (struct context *)context;
    QUIC_STATUS status = QUIC_STATUS_NOT_SUPPORTED;
    printf("Listener callback\n");
    switch (event->Type)
    {
    case QUIC_LISTENER_EVENT_NEW_CONNECTION:
        //
        // A new connection is being attempted by a client. For the handshake to
        // proceed, the server must provide a configuration for QUIC to use. The
        // app MUST set the callback handler before returning.
        //

        pthread_mutex_lock(&ctx->lock);
    
        pthread_cond_signal(&ctx->cond);

        ctx_conn_t *ctx_conn = (ctx_conn_t *)malloc(sizeof(ctx_conn_t));
        connection_info_t *connection_info = (connection_info_t *)malloc(sizeof(connection_info_t));
        ctx->new_connection = (connection_node_t *)malloc(sizeof(connection_node_t));
        connection_info->connection = event->NEW_CONNECTION.Connection;
        connection_info->connected = 1;
        connection_info->streams = (stream_node_t *)malloc(sizeof(stream_node_t));
        connection_info->streams->stream_info = NULL;
        connection_info->streams->prev = NULL;
        connection_info->streams->next = NULL;
        connection_info->stream_count = 0;
        ctx->new_connection->connection_info = connection_info;
        ctx_conn->connection_info = connection_info;
        ctx_conn->ctx = ctx;


        printf("[list][%p] New Connection\n", (void *)listener);

        pthread_mutex_unlock(&ctx->lock);

        ctx->msquic->SetCallbackHandler(event->NEW_CONNECTION.Connection, (void *)connection_callback, ctx_conn);
        status = ctx->msquic->ConnectionSetConfiguration(event->NEW_CONNECTION.Connection, ctx->configuration);
        break;
    case QUIC_LISTENER_EVENT_STOP_COMPLETE:
        //
        // The listener has been stopped and can now be safely cleaned up.
        //
        printf("[list][%p] Stop Complete\n", (void *)listener);
        break;
    default:
        printf("[list][%p] Unknown Event: %d\n", (void *)listener, event->Type);
        break;
    }
    return status;
}


#elif LSQUIC
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
    ctx->idle_timeout_ms = 10000;

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

    // Allocate memory for the destination buffer
    ctx->recv_buff.buffers = (QUIC_BUFFER *)malloc(sizeof(QUIC_BUFFER));
    ctx->recv_buff.lock = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
    ctx->recv_buff.cond = (pthread_cond_t)PTHREAD_COND_INITIALIZER;

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
        settings.PeerBidiStreamCount = MAX_STREAMS;
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
    } else {
        printf("Invalid mode\n");
        exit(EXIT_FAILURE);
    }

    ctx->connections = (connection_node_t *)malloc(sizeof(connection_node_t));
    ctx->connections->connection_info = NULL;
    ctx->connections->prev = NULL;
    ctx->connections->next = NULL;
    ctx->connection_count = 0;
    ctx->new_connection = NULL;
    ctx->lock = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
    ctx->cond = (pthread_cond_t)PTHREAD_COND_INITIALIZER;

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

    if (inet_pton(QUIC_ADDRESS_FAMILY_INET, ip, &ctx->s.local_address.Ipv4.sin_addr) <= 0) {
        perror("inet_pton");
        exit(EXIT_FAILURE);
    }
    printf("Ip address: %d\n", ctx->s.local_address.Ipv4.sin_addr.s_addr);
    ctx->s.local_address.Ipv4.sin_family = QUIC_ADDRESS_FAMILY_INET;
    ctx->s.local_address.Ipv4.sin_port = htons(port);

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

    connection_info_t *connection_info = (connection_info_t *)malloc(sizeof(connection_info_t));
    connection_info->connected = 0;
    connection_info->streams = (stream_node_t *)malloc(sizeof(stream_node_t));
    connection_info->stream_count = 0;
    connection_info->lock = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
    connection_info->cond = (pthread_cond_t)PTHREAD_COND_INITIALIZER;
    ctx_conn_t *ctx_conn = (ctx_conn_t *)malloc(sizeof(ctx_conn_t));
    ctx_conn->ctx = ctx;
    ctx_conn->connection_info = connection_info;
    if (QUIC_FAILED(status = ctx->msquic->ConnectionOpen(ctx->registration, connection_callback, ctx_conn, &connection_info->connection)))
    {
        printf("ConnectionOpen failed, 0x%x!\n", status);
        exit(EXIT_FAILURE);
    }
    printf("[conn][%p] Connecting...\n", (void *)&connection_info->connection);

    //
    // Start the connection to the server.
    //
    if (QUIC_FAILED(status = ctx->msquic->ConnectionStart(connection_info->connection, ctx->configuration, QUIC_ADDRESS_FAMILY_INET, ip, (uint16_t)port)))
    {
        printf("ConnectionStart failed, 0x%x!\n", status);
        exit(EXIT_FAILURE);
    }
    printf("[conn][%p] Started\n", (void *)&connection_info->connection);
    
    pthread_mutex_lock(&ctx->lock);
    if (connection_info->connected == 0)
    {
        printf("Waiting for connection\n");
        pthread_cond_wait(&ctx->cond, &ctx->lock);
    }
    pthread_mutex_unlock(&ctx->lock);
    push_connection(ctx->connections, connection_info);
    printf("Connection established\n");
    return (connection_t) connection_info;
    #elif LSQUIC
    struct context *ctx = (struct context *)context;
    #endif
}

void close_connection(context_t context, connection_t connection) {
    #ifdef QUICHE
    struct context *ctx = (struct context *)context;
    #elif MSQUIC
    struct context *ctx = (struct context *)context;
    connection_info_t *connection_info = (connection_info_t *)connection;
    QUIC_STATUS status = QUIC_STATUS_SUCCESS;
    if (QUIC_FAILED(status = ctx->msquic->ConnectionShutdown(connection_info->connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0)))
    {
        printf("ConnectionShutdown failed, 0x%x!\n", status);
        exit(EXIT_FAILURE);
    }
    #elif LSQUIC
    struct context *ctx = (struct context *)context;
    #endif
}

stream_t open_stream(context_t context, connection_t connection) {
    #ifdef QUICHE
    struct context *ctx = (struct context *)context;
    #elif MSQUIC
    struct context *ctx = (struct context *)context;
    HQUIC stream;
    connection_info_t *connection_info = (connection_info_t *)connection;
    stream_info_t *stream_info = (stream_info_t *)malloc(sizeof(stream_info_t));
    stream_info->established = 0;
    ctx_strm_t *ctx_strm = (ctx_strm_t *)malloc(sizeof(ctx_strm_t));
    ctx_strm->ctx = ctx;
    ctx_strm->connection_info = connection_info;
    ctx_strm->stream_info = stream_info;
    //
    // Create/allocate a new bidirectional stream. The stream is just allocated
    // and no QUIC stream identifier is assigned until it's started.
    //
    QUIC_STATUS status = QUIC_STATUS_SUCCESS;
    if (QUIC_FAILED(status = ctx->msquic->StreamOpen(connection_info->connection, QUIC_STREAM_OPEN_FLAG_NONE, stream_callback, ctx_strm, &stream)))
    {
        printf("StreamOpen failed, 0x%x!\n", status);
        exit(EXIT_FAILURE);
    }
    //
    // Starts the bidirectional stream. By default, the peer is not notified of
    // the stream being started until data is sent on the stream.
    //
    if (QUIC_FAILED(status = ctx->msquic->StreamStart(stream, QUIC_STREAM_START_FLAG_NONE)))
    {
        printf("StreamStart failed, 0x%x!\n", status);
        ctx->msquic->StreamClose(stream);
        exit(EXIT_FAILURE);
    }
    pthread_mutex_lock(&connection_info->lock);
    if (stream_info->established == 0)
    {
        printf("Waiting for stream\n");
        pthread_cond_wait(&connection_info->cond, &connection_info->lock);
    }
    pthread_mutex_unlock(&connection_info->lock);
    uint64_t stream_id;
    uint32_t buffer_len = sizeof(stream_id);
    if (QUIC_FAILED(status = ctx->msquic->GetParam(stream, QUIC_PARAM_STREAM_ID, &buffer_len, &stream_id)))
    {
        printf("GetParam failed, 0x%x!\n", status);
        exit(EXIT_FAILURE);
    }
    printf("[strm][%p] Starting... Stream ID: %llu\n", (void *)stream, (unsigned long long)stream_id);
    stream_info->stream = stream;
    stream_info->stream_id = stream_id;
    stream_node_t *stream_node = push_stream(connection_info->streams, stream_info);
    connection_info->new_stream = stream_node;
    return (stream_t) stream_info;
    #elif LSQUIC
    struct context *ctx = (struct context *)context;
    #endif
}

void close_stream(context_t context, connection_t connection, stream_t stream) {
    #ifdef QUICHE
    struct context *ctx = (struct context *)context;
    #elif MSQUIC
    struct context *ctx = (struct context *)context;
    stream_info_t *stream_info = (stream_info_t *)stream;
    QUIC_STATUS status = QUIC_STATUS_SUCCESS;
    if (QUIC_FAILED(status = ctx->msquic->StreamShutdown(stream_info->stream, QUIC_STREAM_SHUTDOWN_FLAG_NONE, 0)))
    {
        printf("StreamShutdown failed, 0x%x!\n", status);
        exit(EXIT_FAILURE);
    }
    #elif LSQUIC
    struct context *ctx = (struct context *)context;
    #endif
}

void send_data(context_t context, connection_t connection, stream_t stream, char* data, int len) {
    #ifdef QUICHE
    struct context *ctx = (struct context *)context;
    #elif MSQUIC
    struct context *ctx = (struct context *)context;
    QUIC_STATUS status = QUIC_STATUS_SUCCESS;
    stream_info_t *stream_info = (stream_info_t *)stream;
    connection_info_t *connection_info = (connection_info_t *)connection;

    uint8_t *send_buffer_raw;
    QUIC_BUFFER *send_buffer;
    //
    // Allocates and builds the buffer to send over the stream.
    //
    send_buffer_raw = (uint8_t *)malloc(sizeof(QUIC_BUFFER) + sizeof(data));
    if (send_buffer_raw == NULL)
    {
        printf("send_buffer allocation failed!\n");
        status = QUIC_STATUS_OUT_OF_MEMORY;
        exit(EXIT_FAILURE);
    }

    send_buffer = (QUIC_BUFFER *)send_buffer_raw;
    send_buffer->Buffer = data;
    send_buffer->Length = (uint32_t)strlen(data);

    printf("[strm][%p] Sending data...\n", (void *)stream_info->stream);
    printf("Data to send: %s\n", send_buffer->Buffer);
    //
    // Sends the buffer over the stream. Note the FIN flag is passed along with
    // the buffer. This indicates this is the last buffer on the stream and the
    // the stream is shut down (in the send direction) immediately after.
    //
    if (QUIC_FAILED(status = ctx->msquic->StreamSend(stream_info->stream, send_buffer, 1, QUIC_SEND_FLAG_FIN, send_buffer)))
    {
        printf("StreamSend failed, 0x%x!\n", status);
        free(send_buffer_raw);
        exit(EXIT_FAILURE);
    }
    #elif LSQUIC
    struct context *ctx = (struct context *)context;
    #endif
    
}

char* recv_data(context_t context, connection_t connection, int buffer_size, time_t timeout) {
    #ifdef QUICHE
    struct context *ctx = (struct context *)context;
    #elif MSQUIC
    printf("Receiving data\n");
    struct context *ctx = (struct context *)context;
    pthread_mutex_lock(&ctx->recv_buff.lock);
    if (ctx->recv_buff.buffers == NULL)
    {
        if (timeout == 0)
        {
            pthread_cond_wait(&ctx->recv_buff.cond, &ctx->recv_buff.lock);
        }
        else
        {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += timeout;
            pthread_cond_timedwait(&ctx->recv_buff.cond, &ctx->recv_buff.lock, &ts);
            printf("Timed out\n");
        }
    }
    printf("recv_data: %s\n", ctx->recv_buff.buffers->Buffer);
    pthread_mutex_unlock(&ctx->recv_buff.lock);
    return (char *)ctx->recv_buff.buffers->Buffer;
    #elif LSQUIC
    struct context *ctx = (struct context *)context;
    #endif
}

void set_listen(context_t context) {
    #ifdef QUICHE
    struct context *ctx = (struct context *)context;
    #elif MSQUIC
    struct context *ctx = (struct context *)context;
    QUIC_STATUS status = QUIC_STATUS_SUCCESS;
    if (QUIC_FAILED(status = ctx->msquic->ListenerOpen(ctx->registration, listener_callback, ctx, &ctx->s.listener)))
    {
        printf("ListenerOpen failed, 0x%x!\n", status);
        exit(EXIT_FAILURE);
    }
    printf("Listener opened.\n");
    if (QUIC_FAILED(status = ctx->msquic->ListenerStart(ctx->s.listener, &ctx->alpn, 1, &ctx->s.local_address)))
    {
        printf("ListenerStart failed, 0x%x!\n", status);
        exit(EXIT_FAILURE);
    }
    printf("Listener started.\n");

    #elif LSQUIC
    struct context *ctx = (struct context *)context;
    #endif
}

connection_t accept_connection(context_t context, time_t timeout) {
    #ifdef QUICHE
    #elif MSQUIC
    struct context *ctx = (struct context *)context;

    // Lock the mutex to wait for a connection
    pthread_mutex_lock(&ctx->lock);

    // Wait for the listener_callback to signal a new connection
    if (timeout == 0) {
        // Wait indefinitely
        pthread_cond_wait(&ctx->cond, &ctx->lock);
    } else {
        // Wait with a timeout (convert time_t to timespec)
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += timeout;
        pthread_cond_timedwait(&ctx->cond, &ctx->lock, &ts);
    }

    printf("New connection accepted\n");

    // Unlock the mutex
    pthread_mutex_unlock(&ctx->lock);
    return (connection_t)ctx->new_connection->connection_info;
    #elif LSQUIC
    #endif
}

stream_t accept_stream(context_t context, connection_t connection, time_t timeout) {
    #ifdef QUICHE
    #elif MSQUIC
    struct context *ctx = (struct context *)context;
    connection_info_t *connection_info = (connection_info_t *)connection;
    printf("connection_info: %p\n", connection_info);
    // Lock the mutex to wait for a connection
    pthread_mutex_lock(&connection_info->lock);

    // Wait for the listener_callback to signal a new connection
    if (timeout == 0) {
        // Wait indefinitely
        printf("Waiting for stream\n");
        pthread_cond_wait(&connection_info->cond, &connection_info->lock);
    } else {
        // Wait with a timeout (convert time_t to timespec)
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += timeout;
        pthread_cond_timedwait(&connection_info->cond, &connection_info->lock, &ts);
    }

    printf("New stream accepted\n");

    // Unlock the mutex
    pthread_mutex_unlock(&connection_info->lock);
    return (stream_t)connection_info->new_stream->stream_info;
    #endif
}