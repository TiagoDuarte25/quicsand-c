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

int connected = 0;
int streamStarted = 0;

#define MAX_STREAMS 50
#define MAX_CONNECTIONS 50

typedef struct {
    HQUIC stream;
    uint64_t stream_id;
} stream_info_t;

typedef struct {
    HQUIC connection;
    stream_info_t streams[MAX_STREAMS];
    size_t stream_count;
} connection_info_t;

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
            int connected;
            connection_info_t connections[MAX_CONNECTIONS];
            size_t connection_count;
            size_t request_size;
        } c;
        struct server
        {
            int listening;
            HQUIC listener;
            QUIC_ADDR local_address;
            pthread_mutex_t lock;
            pthread_cond_t cond;
            connection_info_t new_connection;
            stream_info_t new_stream;
        } s;
    };
    struct Buffer
    {
        QUIC_BUFFER *quic_buffer;
        pthread_mutex_t mutex;
        pthread_cond_t cond;
    } *recv_buff;
    struct ev_loop *loop;
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

int find_stream(connection_info_t *connection_info, uint64_t stream_id) {
    for (size_t i = 0; i < connection_info->stream_count; i++)
    {
        if (connection_info->streams[i].stream_id == stream_id)
        {
            return 1;
        }
    }
    return 0;
}

// The callback function that will be called periodically
void check_listening_cb(EV_P_ ev_timer *w, int revents) {
    struct context *ctx = (struct context *)w->data;
    if (ctx->s.listening == 0) {
        printf("Variable is now free! Stopping the loop.\n");
        ev_break(EV_A_ EVBREAK_ALL); // Stop the event loop
    } else {
        printf("Variable is still not free. Continuing...\n");
    }
}

void check_connected_cb(EV_P_ ev_timer *w, int revents) {
    struct context *ctx = (struct context *)w->data;
    if (ctx->c.connected == 1) {
        printf("Variable is now free! Stopping the loop.\n");
        ev_break(EV_A_ EVBREAK_ALL); // Stop the event loop
    }
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
    struct context *ctx = (struct context *)context;
    switch (event->Type)
    {
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
        printf("[strm][%p] Data received\n", (void *)stream);
        printf("Data: %s\n", event->RECEIVE.Buffers->Buffer);
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
    struct context *ctx = (struct context *)context;
    switch (event->Type)
    {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        //
        // The handshake has completed for the connection.
        //
        ctx->c.connected = 1;
        printf("[conn][%p] Connected\n", (void *)connection);
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
        printf("[strm][%p] Peer started\n", (void *)event->PEER_STREAM_STARTED.Stream);
        ctx->msquic->SetCallbackHandler(event->PEER_STREAM_STARTED.Stream, (void *)stream_callback, ctx);
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

        pthread_mutex_lock(&ctx->s.lock);

        ctx->s.new_connection.connection = event->NEW_CONNECTION.Connection;
        ctx->s.new_connection.stream_count = 0;
    
        pthread_cond_signal(&ctx->s.cond);

        printf("[list][%p] New Connection\n", (void *)listener);

        pthread_mutex_unlock(&ctx->s.lock);

        ctx->msquic->SetCallbackHandler(event->NEW_CONNECTION.Connection, (void *)connection_callback, ctx);
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
    ctx->loop = EV_DEFAULT;

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
        ctx->c.connected = 0;
        ctx->c.connection_count = 0;
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

        ctx->s.listening = 0;
        ctx->s.lock = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
        ctx->s.cond = (pthread_cond_t)PTHREAD_COND_INITIALIZER;  
    } else {
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

    connection_info_t *connection_info = &ctx->c.connections[ctx->c.connection_count++];
    if (QUIC_FAILED(status = ctx->msquic->ConnectionOpen(ctx->registration, connection_callback, ctx, &connection_info->connection)))
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
    
    // ev_timer timer_watcher;
    // ctx->c.connected = 1;
    // timer_watcher.data = ctx;
    // ev_timer_init(&timer_watcher, check_connected_cb, 0., 1.);
    // ev_timer_start(ctx->loop, &timer_watcher);

    // ev_run(ctx->loop, 0);

    while (!ctx->c.connected)
    {
        // Wait for connection to be established
    }

    connection_info->stream_count = 0;
    return (connection_t) connection_info;
    #elif LSQUIC
    struct context *ctx = (struct context *)context;
    #endif
}

void close_connection(context_t context, connection_t connection) {
    
}

stream_t open_stream(context_t context, connection_t connection) {
    #ifdef QUICHE
    struct context *ctx = (struct context *)context;
    #elif MSQUIC
    struct context *ctx = (struct context *)context;
    HQUIC stream;
    connection_info_t *connection_info = (connection_info_t *)connection;
    //
    // Create/allocate a new bidirectional stream. The stream is just allocated
    // and no QUIC stream identifier is assigned until it's started.
    //
    QUIC_STATUS status = QUIC_STATUS_SUCCESS;
    if (QUIC_FAILED(status = ctx->msquic->StreamOpen(connection_info->connection, QUIC_STREAM_OPEN_FLAG_NONE, stream_callback, ctx, &stream)))
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
    uint64_t stream_id;
    uint32_t buffer_len = sizeof(stream_id);
    if (QUIC_FAILED(status = ctx->msquic->GetParam(stream, QUIC_PARAM_STREAM_ID, &buffer_len, &stream_id)))
    {
        printf("GetParam failed, 0x%x!\n", status);
        exit(EXIT_FAILURE);
    }
    printf("[strm][%p] Starting... Stream ID: %llu\n", (void *)stream, (unsigned long long)stream_id);
    stream_info_t *stream_info = &connection_info->streams[connection_info->stream_count++];
    stream_info->stream = stream;
    stream_info->stream_id = stream_id;
    #elif LSQUIC
    struct context *ctx = (struct context *)context;
    #endif
    return (stream_t) stream_info;
}

void close_stream(context_t context, connection_t connection, stream_t stream) {
    
}

void send_data(context_t context, connection_t connection, stream_t stream, char* data, int len) {
    #ifdef QUICHE
    struct context *ctx = (struct context *)context;
    #elif MSQUIC
    struct context *ctx = (struct context *)context;
    QUIC_STATUS status = QUIC_STATUS_SUCCESS;
    stream_info_t *stream_info = (stream_info_t *)stream;
    connection_info_t *connection_info = (connection_info_t *)connection;

    if (find_stream(connection_info, stream_info->stream_id) == 0)
    {
        printf("Stream not found\n");
        exit(EXIT_FAILURE);
    }

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
    return NULL;
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
    ctx->s.listening = 1;

    // ev_timer timer_watcher;
    // timer_watcher.data = ctx;
    // ev_timer_init(&timer_watcher, check_listening_cb, 0., 1.);
    // ev_timer_start(ctx->loop, &timer_watcher);

    // printf("Starting the event loop...\n");

    // ev_run(ctx->loop, 0);
    #elif LSQUIC
    struct context *ctx = (struct context *)context;
    #endif
}

connection_t accept_connection(context_t context, time_t timeout) {
    #ifdef QUICHE
    #elif MSQUIC
    struct context *ctx = (struct context *)context;

    // Lock the mutex to wait for a connection
    pthread_mutex_lock(&ctx->s.lock);

    // Wait for the listener_callback to signal a new connection
    if (timeout == 0) {
        // Wait indefinitely
        pthread_cond_wait(&ctx->s.cond, &ctx->s.lock);
    } else {
        // Wait with a timeout (convert time_t to timespec)
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += timeout;
        pthread_cond_timedwait(&ctx->s.cond, &ctx->s.lock, &ts);
    }

    printf("New connection accepted\n");

    // Unlock the mutex
    pthread_mutex_unlock(&ctx->s.lock);
    return (connection_t)&ctx->s.new_connection;
    #elif LSQUIC
    #endif
}

stream_t accept_stream(context_t context, connection_t connection, time_t timeout) {
    // TODO
    return (stream_t)NULL;
}