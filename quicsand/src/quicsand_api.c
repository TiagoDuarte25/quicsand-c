#include "quicsand_api.h"
#include <errno.h>
#include <log.h>

quic_error_code_t quic_error = QUIC_SUCCESS;

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
#include <arpa/inet.h>
#include <uthash.h>

#include <pthread.h>
#include <glib.h>

#include <ev.h>
#include <quiche.h>

#define LOCAL_CONN_ID_LEN 16

#define MAX_DATAGRAM_SIZE 1350

#define MAX_TOKEN_LEN \
    sizeof("quiche") - 1 + \
    sizeof(struct sockaddr_storage) + \
    QUICHE_MAX_CONN_ID_LEN

struct connections {
    int sock;

    struct sockaddr_strorage *local_addr;
    socklen_t local_addr_len;

    struct conn_io *h;

    quiche_config *config;

    struct conn_io *last_conn_io;
    struct conn_io *new_conn_io;
    pthread_mutex_t lock;
    pthread_cond_t cond;
};

struct conn_io {
    ev_timer timer;

    int read_fd;
    int write_fd;

    int sock;

    uint8_t cid[LOCAL_CONN_ID_LEN];

    quiche_conn *conn;

    struct sockaddr_storage peer_addr;
    socklen_t peer_addr_len;

    struct sockaddr_storage local_addr;
    socklen_t local_addr_len;

    UT_hash_handle hh;

    struct stream_io *h;
    struct stream_io *last_stream_io;
    struct stream_io *new_stream_io;
    pthread_mutex_t lock;
    pthread_cond_t cond;

    GQueue *stream_io_queue;
    GMutex queue_mutex;
    GCond queue_cond;

    bool acked;
};

struct stream_io {
    uint64_t stream_id;

    struct buffer *recv_buf;

    pthread_mutex_t lock;
    pthread_cond_t cond;

    UT_hash_handle hh;
};

struct buffer {
    uint8_t *buf;
    size_t len;
    size_t off;
};

struct context
{
    struct connections *conns;
    struct ev_loop *loop;
    struct ev_io watcher;
    char *hostname;
    quiche_config *config;

    GQueue *conn_io_queue;
    GMutex queue_mutex;
    GCond queue_cond;
};

struct timeout_args {
    struct context *ctx;
    struct conn_io *conn_io;
};

#elif MSQUIC

#include <msquic.h>
#include <pthread.h>
#include <unistd.h>
#include <limits.h>
#include <arpa/inet.h>
#include <ev.h>
#include <time.h>
#include <uthash.h>
#include <glib.h>

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
    BOOLEAN can_send;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    struct Buffer
    {
        void *buffer;
        uint64_t total_buffer_length;
        uint64_t absolute_offset;
    } recv_buff;

    UT_hash_handle hh;
} stream_info_t;

typedef struct {
    HQUIC connection;
    GQueue *stream_queue;
    GMutex queue_mutex;
    GCond queue_cond;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int connected;

    uint8_t cid[20];

    UT_hash_handle hh;
    stream_info_t *h;
} connection_info_t;

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

    GQueue *conn_queue;
    GMutex queue_mutex;
    GCond queue_cond;
    pthread_mutex_t lock;
    pthread_cond_t cond;

    connection_info_t *h;
};
#endif

#ifdef MSQUIC

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
        log_trace("[strm][%p] start complete", (void *)stream);
        break;
    case QUIC_STREAM_EVENT_RECEIVE:
        log_trace("[strm][%p] data received", (void *)stream);

        int total_buffer_length = event->RECEIVE.TotalBufferLength;

        pthread_mutex_lock(&stream_info->lock);
        // Reallocate memory for the recv_buff.buffer to accommodate the new buffer
        void *new_buffer = realloc(stream_info->recv_buff.buffer, stream_info->recv_buff.total_buffer_length + total_buffer_length);
        if (new_buffer == NULL) {
            // Handle memory allocation failure
            log_error("failed to reallocate memory for the recv_buff.buffer");
            return QUIC_STATUS_OUT_OF_MEMORY;
        }
        stream_info->recv_buff.buffer = new_buffer;

        // Copy the received data into the newly allocated space
        memcpy((uint8_t *)stream_info->recv_buff.buffer + stream_info->recv_buff.total_buffer_length, event->RECEIVE.Buffers->Buffer, total_buffer_length);
        stream_info->recv_buff.total_buffer_length += total_buffer_length;
        stream_info->recv_buff.absolute_offset = event->RECEIVE.AbsoluteOffset;
        pthread_cond_signal(&stream_info->cond);
        pthread_mutex_unlock(&stream_info->lock);
        break;  
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        pthread_mutex_lock(&stream_info->lock);
        stream_info->can_send = TRUE;
        pthread_cond_signal(&stream_info->cond);
        pthread_mutex_unlock(&stream_info->lock);
        log_trace("[strm][%p] data sent", (void *)stream);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        log_trace("[strm][%p] peer shut down", (void *)stream);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        pthread_mutex_lock(&stream_info->lock);
        pthread_cond_signal(&stream_info->cond);
        pthread_mutex_unlock(&stream_info->lock);
        ctx->msquic->StreamShutdown(stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        log_trace("[strm][%p] peer aborted", (void *)stream);
        break;
    case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
        pthread_mutex_lock(&stream_info->lock);
        pthread_cond_signal(&stream_info->cond);
        pthread_mutex_unlock(&stream_info->lock);
        log_trace("[strm][%p] peer receive aborted", (void *)stream);
        break;
    case QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE:
        pthread_mutex_lock(&stream_info->lock);
        pthread_cond_signal(&stream_info->cond);
        pthread_mutex_unlock(&stream_info->lock);
        log_trace("[strm][%p] send shutdown complete", (void *)stream);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        pthread_mutex_lock(&stream_info->lock);
        pthread_cond_signal(&stream_info->cond);
        pthread_mutex_unlock(&stream_info->lock);
        HASH_DELETE(hh, connection_info->h, stream_info);
        log_trace("[strm][%p] all done", (void *)stream);
        break;
    case QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE:
        log_trace("[strm][%p] ideal send buffer size: %u", (void *)stream, event->IDEAL_SEND_BUFFER_SIZE.ByteCount);
        break;
    case QUIC_STREAM_EVENT_PEER_ACCEPTED:
        log_trace("[strm][%p] peer accepted", (void *)stream);
        break;
    case QUIC_STREAM_EVENT_CANCEL_ON_LOSS:
        log_trace("[strm][%p] cancel on loss", (void *)stream);
        break;
    default:
        log_trace("[strm][%p] unknown event type: %d", (void *)stream, event->Type);
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
        log_trace("[conn][%p] connected", (void *)connection);
        pthread_mutex_lock(&ctx->lock);
        connection_info->connection = connection;
        connection_info->connected = 1;
        pthread_cond_signal(&ctx->cond);
        pthread_mutex_unlock(&ctx->lock);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        log_trace("[conn][%p] shutdown initiated by transport, 0x%x", (void *)connection, event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
        if (event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status == QUIC_STATUS_CONNECTION_IDLE)
        {
            log_trace("[conn][%p] successfully shut down on idle.", (void *)connection);
        }
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        log_trace("[conn][%p] shutdown initiated by peer, 0x%llu", (void *)connection, (unsigned long long)event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        log_trace("[conn][%p] shutdown complete", (void *)connection);
        HASH_DELETE(hh, ctx->h, connection_info);
        if (!event->SHUTDOWN_COMPLETE.AppCloseInProgress)
        {
            ctx->msquic->ConnectionClose(connection);      
        }
        break;
    case QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED:
        log_trace("[conn][%p] local address changed", (void *)connection);
        break;
    case QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED:
        log_trace("[conn][%p] peer address changed", (void *)connection);
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        log_trace("[strm][%p] peer started", (void *)event->PEER_STREAM_STARTED.Stream);
        stream_info_t *stream_info = (stream_info_t *)malloc(sizeof(stream_info_t));
        stream_info->stream = event->PEER_STREAM_STARTED.Stream;
        stream_info->recv_buff.buffer = (void *)malloc(sizeof(void *));
        if (stream_info->recv_buff.buffer == NULL) {
            log_error("failed to allocate memory for the recv_buff.buffers array");
            return QUIC_STATUS_OUT_OF_MEMORY;
        }
        stream_info->recv_buff.total_buffer_length = 0;
        stream_info->recv_buff.absolute_offset = 0;
        stream_info->lock = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
        stream_info->cond = (pthread_cond_t)PTHREAD_COND_INITIALIZER;
        stream_info->can_send = TRUE;
        g_mutex_lock(&connection_info->queue_mutex);
        g_queue_push_tail(connection_info->stream_queue, stream_info);
        g_cond_signal(&connection_info->queue_cond);
        g_mutex_unlock(&connection_info->queue_mutex);
        ctx_strm_t *ctx_strm = (ctx_strm_t *)malloc(sizeof(ctx_strm_t));
        ctx_strm->connection_info = connection_info;
        ctx_strm->stream_info = stream_info;
        pthread_mutex_lock(&connection_info->lock);
        pthread_cond_signal(&connection_info->cond);
        pthread_mutex_unlock(&connection_info->lock);
        ctx->msquic->SetCallbackHandler(event->PEER_STREAM_STARTED.Stream, (void *)stream_callback, ctx_strm);
        break;
    case QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE:
        log_trace("[conn][%p] streams available", (void *)connection);
        break;
    case QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS:
        log_trace("[conn][%p] peer needs streams", (void *)connection);
        break;
    case QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED:
        log_trace("[conn][%p] ideal processor changed", (void *)connection);
        break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED:
        log_trace("[conn][%p] datagram state changed", (void *)connection);
        break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED:
        log_trace("[conn][%p] datagram received", (void *)connection);
        break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED:
        log_trace("[conn][%p] datagram send state changed", (void *)connection);
        break;
    case QUIC_CONNECTION_EVENT_RESUMED:
        log_trace("[conn][%p] resumed", (void *)connection);
        break;
    case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
        log_trace("[conn][%p] resumption ticket received (%u bytes):", (void *)connection, event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength);
        for (uint32_t i = 0; i < event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength; i++)
        {
            printf("%.2X", (uint8_t)event->RESUMPTION_TICKET_RECEIVED.ResumptionTicket[i]);
        }
        printf("\n");
        break;
    case QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED:
        log_trace("[conn][%p] peer certificate received", (void *)connection);
        break;
    default:
        log_trace("[conn][%p] unknown event type: %d", (void *)connection, event->Type);
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
    switch (event->Type)
    {
    case QUIC_LISTENER_EVENT_NEW_CONNECTION:
        //
        // A new connection is being attempted by a client. For the handshake to
        // proceed, the server must provide a configuration for QUIC to use. The
        // app MUST set the callback handler before returning.
        //

        // pointers allocation
        ctx_conn_t *ctx_conn = (ctx_conn_t *)malloc(sizeof(ctx_conn_t));
        connection_info_t *connection_info = (connection_info_t *)malloc(sizeof(connection_info_t));
        connection_info->h = NULL;
        connection_info->lock = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
        connection_info->cond = (pthread_cond_t)PTHREAD_COND_INITIALIZER;
        g_mutex_lock(&ctx->queue_mutex);
        g_queue_push_tail(ctx->conn_queue, connection_info);
        g_cond_signal(&ctx->queue_cond);
        g_mutex_unlock(&ctx->queue_mutex);
        connection_info->stream_queue = g_queue_new();
        g_mutex_init(&connection_info->queue_mutex);
        g_cond_init(&connection_info->queue_cond);
        // set the callback handler
        ctx_conn->connection_info = connection_info;
        ctx_conn->ctx = ctx;
        ctx->msquic->SetCallbackHandler(event->NEW_CONNECTION.Connection, (void *)connection_callback, ctx_conn);
        status = ctx->msquic->ConnectionSetConfiguration(event->NEW_CONNECTION.Connection, ctx->configuration);

        log_trace("[list][%p] new connection\n", (void *)listener);
        break;
    case QUIC_LISTENER_EVENT_STOP_COMPLETE:
        //
        // The listener has been stopped and can now be safely cleaned up.
        //
        log_trace("[list][%p] stop complete\n", (void *)listener);
        break;
    default:
        log_trace("[list][%p] unknown event: %d", (void *)listener, event->Type);
        break;
    }
    return status;
}
#elif QUICHE


static void client_timeout_cb(EV_P_ ev_timer *w, int revents);
static void server_timeout_cb(EV_P_ ev_timer *w, int revents);
static void client_recv_cb(EV_P_ ev_io *w, int revents);

static void debug_log(const char *line, void *argp) {
    fprintf(stderr, "%s\n", line);
}

static void flush_egress(struct ev_loop *loop, struct conn_io *conn_io) {
    uint8_t out[MAX_DATAGRAM_SIZE];

    quiche_send_info send_info;

    while (1) {
        pthread_mutex_lock(&conn_io->lock);
        ssize_t written = quiche_conn_send(conn_io->conn, out, sizeof(out),
                                           &send_info);
        pthread_mutex_unlock(&conn_io->lock);

        if (written == QUICHE_ERR_DONE) {
            log_trace("done writing");
            break;
        }

        if (written < 0) {
            log_error("failed to create packet: %zd", written);
            return;
        }

        pthread_mutex_lock(&conn_io->lock);
        ssize_t sent = sendto(conn_io->sock, out, written, 0,
                              (struct sockaddr *) &send_info.to,
                              send_info.to_len);
        pthread_mutex_unlock(&conn_io->lock);
        if (sent != written) {
            log_error("failed to send packet: %zd, expected: %zd, error: %s", sent, written, strerror(errno));
            return;
        }

        log_trace("flush_egress: sent %zd bytes", sent);
    }
    if (quiche_conn_is_closed(conn_io->conn)) {
        quiche_conn_free(conn_io->conn);
        free(conn_io);
        pthread_mutex_unlock(&conn_io->lock);
        return;
    }
    // double t = quiche_conn_timeout_as_nanos(conn_io->conn) / 1e9f;
    // conn_io->timer.repeat = t;
    // ev_timer_again(loop, &conn_io->timer);
}

static void mint_token(const uint8_t *dcid, size_t dcid_len,
                       struct sockaddr_storage *addr, socklen_t addr_len,
                       uint8_t *token, size_t *token_len) {
    memcpy(token, "quiche", sizeof("quiche") - 1);
    memcpy(token + sizeof("quiche") - 1, addr, addr_len);
    memcpy(token + sizeof("quiche") - 1 + addr_len, dcid, dcid_len);

    *token_len = sizeof("quiche") - 1 + addr_len + dcid_len;
}

static bool validate_token(const uint8_t *token, size_t token_len,
                           struct sockaddr_storage *addr, socklen_t addr_len,
                           uint8_t *odcid, size_t *odcid_len) {
    if ((token_len < sizeof("quiche") - 1) ||
         memcmp(token, "quiche", sizeof("quiche") - 1)) {
        return false;
    }

    token += sizeof("quiche") - 1;
    token_len -= sizeof("quiche") - 1;

    if ((token_len < addr_len) || memcmp(token, addr, addr_len)) {
        log_error("failed to validate address");
        return false;
    }

    token += addr_len;
    token_len -= addr_len;

    if (*odcid_len < token_len) {
        log_error("failed to validate odcid");
        return false;
    }

    memcpy(odcid, token, token_len);
    *odcid_len = token_len;

    return true;
}

static uint8_t *gen_cid(uint8_t *cid, size_t cid_len) {
    int rng = open("/dev/urandom", O_RDONLY);
    if (rng < 0) {
        log_error("failed to open /dev/urandom");
        return NULL;
    }

    ssize_t rand_len = read(rng, cid, cid_len);
    if (rand_len < 0) {
        log_error("failed to create connection ID");
        return NULL;
    }

    return cid;
}

static struct conn_io *create_conn(struct context *ctx, uint8_t *scid, size_t scid_len,
                                   uint8_t *odcid, size_t odcid_len,
                                   struct sockaddr *local_addr,
                                   socklen_t local_addr_len,
                                   struct sockaddr_storage *peer_addr,
                                   socklen_t peer_addr_len)
{
    struct connections *conns = ctx->conns;
    struct conn_io *conn_io = malloc(sizeof(struct conn_io));
    if (conn_io == NULL) {
        log_error("failed to allocate connection IO");
        return NULL;
    }

    if (scid_len != LOCAL_CONN_ID_LEN) {
        log_error("invalid connection ID length: %zu", scid_len);
        return NULL;
    }

    memcpy(conn_io->cid, scid, LOCAL_CONN_ID_LEN);

    quiche_conn *conn = quiche_accept(conn_io->cid, LOCAL_CONN_ID_LEN,
                                      odcid, odcid_len,
                                      local_addr,
                                      local_addr_len,
                                      (struct sockaddr *) peer_addr,
                                      peer_addr_len,
                                      conns->config);

    if (conn == NULL) {
        log_error("failed to create connection");
        free(conn_io);
        return NULL;
    }
    conn_io->sock = conns->sock;
    conn_io->conn = conn;

    memcpy(&conn_io->peer_addr, peer_addr, peer_addr_len);
    conn_io->peer_addr_len = peer_addr_len;

    conn_io->stream_io_queue = g_queue_new();
    g_mutex_init(&conn_io->queue_mutex);
    g_cond_init(&conn_io->queue_cond);
    log_trace("created connection %p", (void *)conn_io);

    return conn_io;
}

static void *conn_recv_cb(void *timeout_args) {
    struct timeout_args *args = timeout_args;
    struct context *ctx = args->ctx;
    struct connections *conns = ctx->conns;
    struct conn_io *conn_io = args->conn_io;

    uint8_t buf[65535];
    uint8_t out[MAX_DATAGRAM_SIZE];

    while (1) {
        struct sockaddr_storage peer_addr = conn_io->peer_addr;
        socklen_t peer_addr_len = conn_io->peer_addr_len;

        ssize_t length;
        // Read the packet data
        if (read(conn_io->read_fd, &length, sizeof(length)) < 0) {
            log_error("[conn] [%p] failed to read: %s", conn_io, strerror(errno));
            continue;
        }

        ssize_t r = read(conn_io->read_fd, buf, length);

        if (r < 0) {
            log_error("[conn] [%p] failed to read: %s", conn_io, strerror(errno));
            continue;
        }

        uint8_t type;
        uint32_t version;

        uint8_t scid[QUICHE_MAX_CONN_ID_LEN];
        size_t scid_len = sizeof(scid);

        uint8_t dcid[QUICHE_MAX_CONN_ID_LEN];
        size_t dcid_len = sizeof(dcid);

        uint8_t odcid[QUICHE_MAX_CONN_ID_LEN];
        size_t odcid_len = sizeof(odcid);

        uint8_t token[MAX_TOKEN_LEN];
        size_t token_len = sizeof(token);

        int rc = quiche_header_info(buf, r, LOCAL_CONN_ID_LEN, &version,
                                    &type, scid, &scid_len, dcid, &dcid_len,
                                    token, &token_len);
        if (rc < 0) {
            log_error("[conn] [%p] failed to parse header: %d", conn_io, rc);
            continue;
        }

        log_trace("[conn] [%p] parsed header: version=%u, type=%u, scid_len=%zu, dcid_len=%zu, token_len=%zu",
               conn_io, version, type, scid_len, dcid_len, token_len);

        quiche_recv_info recv_info = {
            (struct sockaddr *)&conn_io->peer_addr,
            conn_io->peer_addr_len,

            (struct sockaddr *)&conns->local_addr,
            conns->local_addr_len,
        };
        
        ssize_t done = quiche_conn_recv(conn_io->conn, buf, r, &recv_info);
        if (done < 0) {
            log_error("[conn] [%p] failed to process packet: %zd", conn_io, done);
            continue;
        }

        pthread_mutex_lock(&conn_io->lock);
        pthread_cond_signal(&conn_io->cond);
        pthread_mutex_unlock(&conn_io->lock);

        log_trace("[conn] [%p] connection: recv %zd bytes", conn_io, done);

        if (quiche_conn_is_established(conn_io->conn)) {
            printf("[conn] [%p] connection: established\n", (void *)conn_io);
            uint64_t s = 0;
            
            quiche_stream_iter *readable = quiche_conn_readable(conn_io->conn);

            while (quiche_stream_iter_next(readable, &s)) {
                log_trace("[conn] [%p] stream %" PRIu64 " is readable", conn_io, s);

                bool fin = false;
                uint64_t error_code;
                ssize_t recv_len = quiche_conn_stream_recv(conn_io->conn, s,
                                                           buf, sizeof(buf),
                                                           &fin, &error_code);
                if (recv_len < 0) {
                    break;
                }
                struct stream_io *stream_io;
                HASH_FIND(hh, conn_io->h, &s, sizeof(s), stream_io);
                if (stream_io == NULL) {
                    log_trace("[conn] [%p] stream %p not found", conn_io, (void *)stream_io);
                    log_trace("buf: %s", buf);
                    if (strcmp((char *)buf, "open stream") == 0) {
                        stream_io = malloc(sizeof(struct stream_io));
                        if (stream_io == NULL) {
                            log_error("[conn] [%p] failed to allocate stream IO", conn_io);
                            return NULL;
                        }
                        stream_io->stream_id = s;
                        stream_io->recv_buf = malloc(sizeof(struct buffer));
                        stream_io->recv_buf->buf = NULL;
                        stream_io->recv_buf->len = 0;
                        stream_io->lock = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
                        stream_io->cond = (pthread_cond_t)PTHREAD_COND_INITIALIZER;
                        HASH_ADD(hh, conn_io->h, stream_id, sizeof(uint64_t), stream_io);
                        g_mutex_lock(&conn_io->queue_mutex);
                        g_queue_push_tail(conn_io->stream_io_queue, stream_io);
                        g_cond_signal(&conn_io->queue_cond);
                        g_mutex_unlock(&conn_io->queue_mutex);
                        quiche_conn_stream_send(conn_io->conn, s, (uint8_t *)"stream opened", sizeof("stream opened"), false, &error_code);
                        flush_egress(ctx->loop, conn_io);
                    }
                } else {
                    log_trace("[conn] [%p] stream %p found", conn_io, (void *)stream_io);
                    pthread_mutex_lock(&stream_io->lock);
                    if (stream_io->recv_buf->buf != NULL) {
                        // add new bytes to the buffer
                        stream_io->recv_buf->buf = realloc(stream_io->recv_buf->buf, stream_io->recv_buf->len + recv_len);
                        memcpy(stream_io->recv_buf->buf + stream_io->recv_buf->len, buf, recv_len);
                        stream_io->recv_buf->len += recv_len;
                    } else {
                        stream_io->recv_buf->buf = malloc(recv_len);
                        stream_io->recv_buf->len = recv_len;
                        memcpy(stream_io->recv_buf->buf, buf, recv_len);
                    }
                    pthread_cond_signal(&stream_io->cond);
                    pthread_mutex_unlock(&stream_io->lock);
                }
            }

            quiche_stream_iter_free(readable);
        }
        flush_egress(ctx->loop, conn_io);
    }
}

static void read_socket_cb(EV_P_ ev_io *w, int revents) 
{
    struct context *ctx = w->data;
    struct connections *conns = ctx->conns;
    uint8_t buf[65535];
    uint8_t out[MAX_DATAGRAM_SIZE];
    while (1) {
        struct conn_io *conn_io, *tmp;
        struct sockaddr_storage peer_addr;
        socklen_t peer_addr_len = sizeof(peer_addr);
        memset(&peer_addr, 0, peer_addr_len);

        ssize_t read = recvfrom(conns->sock, buf, sizeof(buf), 0,
                                (struct sockaddr *) &peer_addr,
                                &peer_addr_len);

        if (read < 0) {
            if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
                break;
            }

            log_error("[conn] [%p] failed to read, closing connection: %s", conn_io, strerror(errno));
            return;
        }

        uint8_t type;
        uint32_t version;

        uint8_t scid[QUICHE_MAX_CONN_ID_LEN];
        size_t scid_len = sizeof(scid);

        uint8_t dcid[QUICHE_MAX_CONN_ID_LEN];
        size_t dcid_len = sizeof(dcid);

        uint8_t odcid[QUICHE_MAX_CONN_ID_LEN];
        size_t odcid_len = sizeof(odcid);

        uint8_t token[MAX_TOKEN_LEN];
        size_t token_len = sizeof(token);
        log_warn("token: %p", token);

        int rc = quiche_header_info(buf, read, LOCAL_CONN_ID_LEN, &version,
                                    &type, scid, &scid_len, dcid, &dcid_len,
                                    token, &token_len);
        if (rc < 0) {
            log_error("[conn] [%p] failed to parse header: %d", conn_io, rc);
            continue;
        }

        log_trace("[conn] [%p] Parsed header: version=%u, type=%u, scid_len=%zu, dcid_len=%zu, token_len=%zu",
               conn_io, version, type, scid_len, dcid_len, token_len);

        
        HASH_FIND(hh, conns->h, dcid, dcid_len, conn_io);

        if (conn_io == NULL) {
            if (type != 1) {
                log_error("[conn] [%p] packet is not initial", conn_io);
                continue;
            }
            log_trace("[conn] [%p] connection not found, creating one", conn_io);
            if (!quiche_version_is_supported(version)) {
                log_trace("[conn] [%p] version negotiation", conn_io);

                ssize_t written = quiche_negotiate_version(scid, scid_len,
                                                           dcid, dcid_len,
                                                           out, sizeof(out));

                if (written < 0) {
                    log_error("[conn] [%p] failed to create version negotiation packet: %zd", conn_io, written);
                    continue;
                }

                ssize_t sent = sendto(conns->sock, out, written, 0,
                                      (struct sockaddr *) &peer_addr,
                                      peer_addr_len);
                if (sent != written) {
                    log_error("[conn] [%p] failed to send", conn_io);
                    continue;
                }

                log_trace("[conn] [%p] negotiation packet: sent %zd bytes", conn_io, sent);
                continue;
            }

            if (token_len == 0) {
                log_trace("[conn] [%p] stateless retry", conn_io);
                log_warn("peer_addr %s:%d", inet_ntoa(((struct sockaddr_in *)&peer_addr)->sin_addr), ntohs(((struct sockaddr_in *)&peer_addr)->sin_port));
                mint_token(dcid, dcid_len, &peer_addr, peer_addr_len,
                           token, &token_len);

                uint8_t new_cid[LOCAL_CONN_ID_LEN];

                if (gen_cid(new_cid, LOCAL_CONN_ID_LEN) == NULL) {
                    continue;
                }

                ssize_t written = quiche_retry(scid, scid_len,
                                               dcid, dcid_len,
                                               new_cid, LOCAL_CONN_ID_LEN,
                                               token, token_len,
                                               version, out, sizeof(out));

                if (written < 0) {
                    log_trace("[conn] [%p] failed to create retry packet: %zd", conn_io, written);
                    continue;
                }

                ssize_t sent = sendto(conns->sock, out, written, 0,
                                      (struct sockaddr *) &peer_addr,
                                      peer_addr_len);
                if (sent != written) {
                    log_error("[conn] [%p] failed to send", conn_io);
                    continue;
                }

                log_trace("[conn] [%p] retry packet: sent %zd bytes", conn_io, sent);
                continue;
            }

            if (!validate_token(token, token_len, &peer_addr, peer_addr_len,
                               odcid, &odcid_len)) {
                log_error("[conn] [%p] invalid address validation token", conn_io);
                continue;
            }

            conn_io = create_conn(ctx, dcid, dcid_len, odcid, odcid_len,
                                  (struct sockaddr *)&conns->local_addr, conns->local_addr_len,
                                  &peer_addr, peer_addr_len);

            if (conn_io == NULL) {
                continue;
            }
            
            int pipefd[2];
            if (pipe(pipefd) < 0) {
                log_error("[conn] [%p] failed to create pipe: %s", conn_io, strerror(errno));
                return;
            }
            conn_io->read_fd = pipefd[0];
            conn_io->write_fd = pipefd[1];

            struct timeout_args *timeout_args = malloc(sizeof(struct timeout_args));
            timeout_args->ctx = ctx;
            timeout_args->conn_io = conn_io;

            g_mutex_lock(&ctx->queue_mutex);
            g_queue_push_tail(ctx->conn_io_queue, conn_io);
            g_cond_signal(&ctx->queue_cond);
            g_mutex_unlock(&ctx->queue_mutex);

            pthread_t thread_id;
            struct timeout_args *args = malloc(sizeof(struct timeout_args));
            args->ctx = ctx;
            args->conn_io = conn_io;
            if (pthread_create(&thread_id, NULL, conn_recv_cb, args) != 0) {
                log_error("[conn] [%p] failed to create event loop thread", conn_io);
                return;
            }
            pthread_detach(thread_id);

            HASH_ADD(hh, conns->h, cid, LOCAL_CONN_ID_LEN, conn_io);
        } 
        log_trace("[conn] [%p] connection: write %zd", conn_io, read);
        if (write(conn_io->write_fd, &read, sizeof(read)) < 0) {
            log_error("[conn] [%p] failed to write packet length: %s", conn_io, strerror(errno));
            return;
        }
        if (write(conn_io->write_fd, buf, read) < 0) {
            log_error("[conn] [%p] failed to write packet: %s", conn_io, strerror(errno));
            return;
        }
    }
}

static void client_recv_cb(EV_P_ ev_io *w, int revents) {
    struct conn_io *conn_io = w->data;
    uint8_t buf[65535];
    while (1) {
        struct sockaddr_storage peer_addr;
        socklen_t peer_addr_len = sizeof(peer_addr);
        memset(&peer_addr, 0, peer_addr_len);

        ssize_t read = recvfrom(conn_io->sock, buf, sizeof(buf), 0,
                                (struct sockaddr *) &peer_addr,
                                &peer_addr_len);

        if (read < 0) {
            if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
                break;
            }

            log_error("failed to read: %s", strerror(errno));
            return;
        }

        log_trace("recv %zd bytes", read);

        uint8_t type;
        uint32_t version;

        uint8_t scid[QUICHE_MAX_CONN_ID_LEN];
        size_t scid_len = sizeof(scid);

        uint8_t dcid[QUICHE_MAX_CONN_ID_LEN];
        size_t dcid_len = sizeof(dcid);

        uint8_t odcid[QUICHE_MAX_CONN_ID_LEN];
        size_t odcid_len = sizeof(odcid);

        uint8_t token[MAX_TOKEN_LEN];
        size_t token_len = sizeof(token);

        int rc = quiche_header_info(buf, read, LOCAL_CONN_ID_LEN, &version,
                                    &type, scid, &scid_len, dcid, &dcid_len,
                                    token, &token_len);

        log_trace("Parsed header: version=%u, type=%u, scid_len=%zu, dcid_len=%zu, token_len=%zu",
               version, type, scid_len, dcid_len, token_len);

        quiche_recv_info recv_info = {
            (struct sockaddr *) &peer_addr,
            peer_addr_len,

            (struct sockaddr *) &conn_io->local_addr,
            conn_io->local_addr_len,
        };

        if (conn_io == NULL) {
            log_error("connection not found");
            return;
        }
        pthread_mutex_lock(&conn_io->lock);
        ssize_t done = quiche_conn_recv(conn_io->conn, buf, read, &recv_info);
        pthread_cond_signal(&conn_io->cond);
        pthread_mutex_unlock(&conn_io->lock);

        if (done < 0) {
            log_error("failed to process packet");
            continue;
        }

        log_trace("connection %p: recv %zd bytes", conn_io, done);
    }

    log_trace("done reading");

    if (quiche_conn_is_closed(conn_io->conn)) {
        log_trace("connection closed");

        ev_break(EV_A_ EVBREAK_ONE);
        return;
    }

    flush_egress(loop, conn_io);

    if (quiche_conn_is_established(conn_io->conn)) {
        uint64_t s = 0;

        quiche_stream_iter *readable = quiche_conn_readable(conn_io->conn);

        while (quiche_stream_iter_next(readable, &s)) {
            log_trace("stream %" PRIu64 " is readable", s);

            bool fin = false;
            uint64_t error_code;
            ssize_t recv_len = quiche_conn_stream_recv(conn_io->conn, s,
                                                       buf, sizeof(buf),
                                                       &fin, &error_code);
            if (recv_len < 0) {
                break;
            }

            struct stream_io *stream_io;
            HASH_FIND(hh, conn_io->h, &s, sizeof(s), stream_io);
            if (stream_io == NULL) {
                log_trace("stream not found");
                if (strcmp((char *)buf, "stream opened") == 0) {
                    pthread_mutex_lock(&conn_io->lock);
                    conn_io->new_stream_io = malloc(sizeof(struct stream_io));
                    pthread_cond_signal(&conn_io->cond);
                    pthread_mutex_unlock(&conn_io->lock);
                }
            } else {
                log_trace("stream %p found", (void *)stream_io);
                if (stream_io->recv_buf->buf == NULL) {
                    stream_io->recv_buf->buf = malloc(recv_len);
                    if (stream_io->recv_buf->buf == NULL) {
                        log_error("failed to allocate buffer");
                        return;
                    }
                    stream_io->recv_buf->len = recv_len;
                    memcpy(stream_io->recv_buf->buf, buf, recv_len);
                } else {
                    // add new bytes to the buffer
                    stream_io->recv_buf->buf = realloc(stream_io->recv_buf->buf, stream_io->recv_buf->len + recv_len);
                    memcpy(stream_io->recv_buf->buf + stream_io->recv_buf->len, buf, recv_len);
                    stream_io->recv_buf->len += recv_len;
                }
                pthread_mutex_lock(&stream_io->lock);
                pthread_cond_signal(&stream_io->cond);
                pthread_mutex_unlock(&stream_io->lock);
            }
            if (fin) {
                const uint8_t error_code;
                if (quiche_conn_close(conn_io->conn, true, 0, &error_code, sizeof(error_code)) < 0) {
                    log_error("failed to close connection");
                    return;
                }
            }
        }

        quiche_stream_iter_free(readable);
    }
}

static void server_timeout_cb(EV_P_ ev_timer *w, int revents) {
    struct timeout_args *args = w->data;
    struct context *ctx = args->ctx;
    struct conn_io *conn_io = args->conn_io;
    struct connections *conns = ctx->conns;

    quiche_conn_on_timeout(conn_io->conn);

    log_trace("timeout");

    flush_egress(loop, conn_io);

    if (quiche_conn_is_closed(conn_io->conn)) {
        quiche_stats stats;
        quiche_path_stats path_stats;

        quiche_conn_stats(conn_io->conn, &stats);
        quiche_conn_path_stats(conn_io->conn, 0, &path_stats);

        log_trace("connection closed, recv=%zu sent=%zu lost=%zu retrans=%zu rtt=%" PRIu64 "ns",
               stats.recv, stats.sent, stats.lost, stats.retrans, path_stats.rtt);

        struct stream_io *stream_io, *tmp;
        HASH_ITER(hh, conn_io->h, stream_io, tmp) {
            pthread_mutex_lock(&stream_io->lock);
            pthread_cond_signal(&stream_io->cond);
            pthread_mutex_unlock(&stream_io->lock);
        }
        HASH_DELETE(hh, conns->h, conn_io);

        ev_timer_stop(loop, &conn_io->timer);
        quiche_conn_free(conn_io->conn);
        free(conn_io);
        conn_io = NULL;

        return;
    }

    // iter the connection streams and unblock the waiting threads
    struct stream_io *stream_io, *tmp;
    HASH_ITER(hh, conn_io->h, stream_io, tmp) {
        pthread_mutex_lock(&stream_io->lock);
        pthread_cond_signal(&stream_io->cond);
        pthread_mutex_unlock(&stream_io->lock);
    }
}

void client_timeout_cb(EV_P_ ev_timer *w, int revents) {
    struct timeout_args *args = w->data;
    struct context *ctx = args->ctx;
    struct conn_io *conn_io = args->conn_io;

    quiche_conn_on_timeout(conn_io->conn);

    log_trace("timeout");

    flush_egress(loop, conn_io);

    if (quiche_conn_is_closed(conn_io->conn)) {
        quiche_stats stats;
        quiche_path_stats path_stats;

        quiche_conn_stats(conn_io->conn, &stats);
        quiche_conn_path_stats(conn_io->conn, 0, &path_stats);

        log_trace("connection closed, recv=%zu sent=%zu lost=%zu retrans=%zu rtt=%" PRIu64 "ns",
               stats.recv, stats.sent, stats.lost, stats.retrans, path_stats.rtt);
        quiche_conn_free(conn_io->conn);
        struct stream_io *stream_io, *tmp;
        HASH_ITER(hh, conn_io->h, stream_io, tmp) {
            pthread_mutex_lock(&stream_io->lock);
            pthread_cond_signal(&stream_io->cond);
            pthread_mutex_unlock(&stream_io->lock);
        }
        HASH_DELETE(hh, ctx->conns->h, conn_io);
        free(conn_io);
        conn_io = NULL;
        ev_break(EV_A_ EVBREAK_ONE);
        return;
    }

    
}

void *event_loop_thread(void *arg) {
    struct context *ctx = (struct context *)arg;
    ev_run(ctx->loop, 0);
    return NULL;
}

#endif

context_t create_quic_context(char *cert_path, char *key_path) {
    #ifdef QUICHE
        quic_error = QUIC_SUCCESS;

        struct context *ctx = (struct context *)malloc(sizeof(struct context));

        ctx->config = quiche_config_new(QUICHE_PROTOCOL_VERSION);
        if (ctx->config == NULL)
        {
            log_error("failed to create config");
            quic_error = QUIC_ERROR_ALLOCATION_FAILED;
            return NULL;
        }

        if(cert_path && key_path) {
            quiche_config_load_cert_chain_from_pem_file(ctx->config, cert_path);
            quiche_config_load_priv_key_from_pem_file(ctx->config, key_path);
        } else {
            quiche_config_verify_peer(ctx->config, false);
        }

        quiche_enable_debug_logging(debug_log, NULL);

        // quiche_config_set_application_protos(ctx->config,
        //                                     (uint8_t *)"\x0ahq-interop\x05hq-29\x05hq-28\x05hq-27\x08http/0.9", 38);
        // I want ALPN that use h3
        quiche_config_set_application_protos(ctx->config,
                                            (uint8_t *)"\x05hq-29\x05hq-28\x05hq-27", 15);
        // quiche_config_set_max_idle_timeout(ctx->config, 10000000);
        quiche_config_set_max_recv_udp_payload_size(ctx->config, MAX_DATAGRAM_SIZE);
        quiche_config_set_max_send_udp_payload_size(ctx->config, MAX_DATAGRAM_SIZE);
        quiche_config_set_initial_max_data(ctx->config, 10000000);
        quiche_config_set_initial_max_stream_data_bidi_local(ctx->config, 1000000);
        quiche_config_set_initial_max_stream_data_bidi_remote(ctx->config, 1000000);
        quiche_config_set_initial_max_streams_bidi(ctx->config, 100);
        quiche_config_set_cc_algorithm(ctx->config, QUICHE_CC_RENO);

        ctx->conns = (struct connections *)malloc(sizeof(struct connections));
        if (ctx->conns == NULL)
        {
            log_error("failed to allocate connections");
            quic_error = QUIC_ERROR_ALLOCATION_FAILED;
            return NULL;
        }
        ctx->conns->config = ctx->config;
        ctx->conns->new_conn_io = NULL;
        ctx->conns->last_conn_io = NULL;
        ctx->conns->h = NULL;
        ctx->conns->lock = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
        ctx->conns->cond = (pthread_cond_t)PTHREAD_COND_INITIALIZER;

        ctx->conn_io_queue = g_queue_new();
        g_mutex_init(&ctx->queue_mutex);
        g_cond_init(&ctx->queue_cond);

        log_debug("context created: %p", (void *)ctx);
        return (context_t) ctx;
    #elif MSQUIC
    struct context *ctx = (struct context *)malloc(sizeof(struct context));
    ctx->reg_config = (QUIC_REGISTRATION_CONFIG){"quicsand", QUIC_EXECUTION_PROFILE_LOW_LATENCY};
    ctx->alpn = (QUIC_BUFFER){sizeof("wq-vvv-NN") - 1, (uint8_t *)"wq-vvv-NN"};
    ctx->idle_timeout_ms = 0;

    QUIC_STATUS status = QUIC_STATUS_SUCCESS;
    //
    // Open a handle to the library and get the API function table.
    //
    if (QUIC_FAILED(status = MsQuicOpen2(&ctx->msquic)))
    {
        log_error("failed to open MsQuic, 0x%x", status);
        quic_error = QUIC_ERROR_INITIALIZATION_FAILED;
        return NULL;
    }

    //
    // Create a registration for the app's connections.
    //
    if (QUIC_FAILED(status = ctx->msquic->RegistrationOpen(&ctx->reg_config, &ctx->registration)))
    {
        log_error("failed to open registration, 0x%x", status);
        quic_error = QUIC_ERROR_INITIALIZATION_FAILED;
        return NULL;
    }

    //
    // Configures the idle timeout.
    //
    QUIC_SETTINGS settings = {0};
    settings.IdleTimeoutMs = ctx->idle_timeout_ms;
    settings.IsSet.IdleTimeoutMs = TRUE;
    // settings.IsSet.StreamMultiReceiveEnabled = 1; // Enable Stream Multi Receive
    // settings.StreamMultiReceiveEnabled = 1;

    QUIC_CREDENTIAL_CONFIG cred_config;
    memset(&cred_config, 0, sizeof(cred_config));

    if (!cert_path || !key_path) {
        cred_config.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
        cred_config.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
    }
    else {
        settings.ServerResumptionLevel = QUIC_SERVER_RESUME_AND_ZERORTT;
        settings.IsSet.ServerResumptionLevel = TRUE;
        settings.PeerBidiStreamCount = MAX_STREAMS;
        settings.IsSet.PeerBidiStreamCount = TRUE;

        cred_config.Flags = QUIC_CREDENTIAL_FLAG_NONE;
        cred_config.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;

        QUIC_CERTIFICATE_FILE CertFile;
        CertFile.CertificateFile = cert_path;
        CertFile.PrivateKeyFile = key_path;
        cred_config.CertificateFile = &CertFile;
    }
    ctx->h = NULL;
    ctx->conn_queue = g_queue_new();
    g_mutex_init(&ctx->queue_mutex);
    g_cond_init(&ctx->queue_cond);
    ctx->lock = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
    ctx->cond = (pthread_cond_t)PTHREAD_COND_INITIALIZER;

    // Allocate/initialize the configuration object, with the configured ALPN
    // and settings.
    //
    if (QUIC_FAILED(status = ctx->msquic->ConfigurationOpen(ctx->registration, &ctx->alpn, 1, &settings, sizeof(settings), NULL, &ctx->configuration)))
    {
        log_error("failed to open configuration, 0x%x", status);
        quic_error = QUIC_ERROR_INITIALIZATION_FAILED;
        return NULL;
    }

    //
    // Loads the TLS credential part of the configuration. This is required even
    // on client side, to indicate if a certificate is required or not.
    //
    if (QUIC_FAILED(status = ctx->msquic->ConfigurationLoadCredential(ctx->configuration, &cred_config)))
    {
        log_error("failed to load credential, 0x%x", status);
        quic_error = QUIC_ERROR_TLS_ERROR;
        return NULL;
    }
    return (context_t) ctx;
    #endif
}

int bind_addr(context_t context, char* ip, int port) {
    #ifdef QUICHE
    struct context *ctx = (struct context *)context;
    
    const struct addrinfo hints = {
        .ai_family = PF_UNSPEC,
        .ai_socktype = SOCK_DGRAM,
        .ai_protocol = IPPROTO_UDP
    };

    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%d", port);
    struct addrinfo *local;
    if (getaddrinfo(ip, port_str, &hints, &local) != 0) {
        log_error("failed to resolve host: %s", strerror(errno));
        return -1;
    }

    if ((ctx->conns->sock = socket(local->ai_family, SOCK_DGRAM, 0)) < 0)
    {
        log_error("failed to create socket: %s", strerror(errno));
        return -1;
    }

    if (fcntl(ctx->conns->sock, F_SETFL, O_NONBLOCK) != 0)
    {
        log_error("failed to make socket non-blocking: %s", strerror(errno));
        return -1;
    }

    if (bind(ctx->conns->sock, local->ai_addr, local->ai_addrlen) < 0)
    {
        log_error("failed to bind socket: %s", strerror(errno));
        return -1;
    }

    memcpy(&ctx->conns->local_addr, local->ai_addr, local->ai_addrlen);
    ctx->conns->local_addr_len = local->ai_addrlen;

    //print binded address
    char host[NI_MAXHOST];
    char service[NI_MAXSERV];
    if (getnameinfo(local->ai_addr, local->ai_addrlen, host, NI_MAXHOST, service, NI_MAXSERV, 0) == 0)
    {
        log_debug("bound to %s:%s", host, service);
    }
    else
    {
        log_error("failed to get name info for local address: %s", strerror(errno));
        return -1;
    }
    
    return 0;

    #elif MSQUIC
    struct context *ctx = (struct context *)context;

    if (inet_pton(QUIC_ADDRESS_FAMILY_INET, ip, &ctx->s.local_address.Ipv4.sin_addr) <= 0) {
        log_error("failed to parse IP address: %s", strerror(errno));
        quic_error = QUIC_ERROR_INVALID_IP_ADDRESS;
        return -1;
    }
    ctx->s.local_address.Ipv4.sin_family = QUIC_ADDRESS_FAMILY_INET;
    ctx->s.local_address.Ipv4.sin_port = htons(port);
    #endif
}

connection_t open_connection(context_t context, char* ip, int port) {
    #ifdef QUICHE
    struct context *ctx = (struct context *)context;

    log_debug("opening connection to %s:%d", ip, port);

    char *host = "quicsand-api-server"; 

    struct addrinfo *peer = NULL;
    struct sockaddr_in addr4;

    log_debug("bind local address");
    // Check if the IP is IPv4 or IPv6 and set up the addrinfo structure accordingly
    if (inet_pton(AF_INET, ip, &addr4.sin_addr) == 1) {
        addr4.sin_family = AF_INET;
        addr4.sin_port = htons(port);

        peer = (struct addrinfo *)malloc(sizeof(struct addrinfo));
        if (peer == NULL) {
            perror("failed to allocate memory for addrinfo");
            return NULL;
        }

        peer->ai_family = AF_INET;
        peer->ai_socktype = SOCK_DGRAM;
        peer->ai_protocol = IPPROTO_UDP;
        peer->ai_addrlen = sizeof(struct sockaddr_in);
        peer->ai_addr = (struct sockaddr *)malloc(sizeof(struct sockaddr_in));
        if (peer->ai_addr == NULL) {
            perror("failed to allocate memory for sockaddr_in");
            free(peer);
            return NULL;
        }
        memcpy(peer->ai_addr, &addr4, sizeof(struct sockaddr_in));
        peer->ai_next = NULL;
    }
    log_debug("local address bound");

    int sock = socket(peer->ai_family, SOCK_DGRAM, 0);
    if (sock < 0) {
        log_error("failed to create socket: %s", strerror(errno));
        return NULL;
    }

    if (fcntl(sock, F_SETFL, O_NONBLOCK) != 0) {
        log_error("failed to make socket non-blocking: %s", strerror(errno));
        return NULL;
    }
    log_debug("socket created");

    struct conn_io *conn_io = (struct conn_io *)malloc(sizeof(struct conn_io));
    if (conn_io == NULL)
    {
        log_error("failed to allocate connection IO");
        return NULL;
    }

    uint8_t scid[LOCAL_CONN_ID_LEN];
    gen_cid(scid, LOCAL_CONN_ID_LEN);

    ctx->conns->local_addr_len = sizeof(ctx->conns->local_addr);
    if (getsockname(sock, (struct sockaddr *)&ctx->conns->local_addr,
                    &ctx->conns->local_addr_len) != 0)
    {
        log_error("failed to get local address: %s", strerror(errno));
        return NULL;
    }

    memcpy(&conn_io->local_addr, &ctx->conns->local_addr, ctx->conns->local_addr_len);
    conn_io->local_addr_len = ctx->conns->local_addr_len;

    quiche_conn *conn = quiche_connect(host, (const uint8_t *) scid, sizeof(scid),
                                       (struct sockaddr *) &ctx->conns->local_addr,
                                       ctx->conns->local_addr_len,
                                       peer->ai_addr, peer->ai_addrlen, ctx->config);

    if (conn == NULL) {
        log_error("failed to create connection");
        return NULL;
    }

    conn_io->sock = sock;
    conn_io->conn = conn;
    conn_io->lock = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
    conn_io->cond = (pthread_cond_t)PTHREAD_COND_INITIALIZER;
    memcpy(&conn_io->peer_addr, peer->ai_addr, peer->ai_addrlen);
    conn_io->peer_addr_len = peer->ai_addrlen;
    conn_io->h = NULL;
    conn_io->new_stream_io = NULL;
    conn_io->last_stream_io = NULL;

    // Create a new event loop
    ctx->loop = ev_loop_new(EVFLAG_AUTO);

    ev_io_init(&ctx->watcher, client_recv_cb, sock, EV_READ);
    ev_io_start(ctx->loop, &ctx->watcher);
    ctx->watcher.data = conn_io;

    // ev_init(&conn_io->timer, client_timeout_cb);
    // struct timeout_args *args = malloc(sizeof(struct timeout_args));
    // args->ctx = ctx;
    // args->conn_io = conn_io;
    // conn_io->timer.data = args;

    flush_egress(ctx->loop, conn_io);

    // Create a new thread for the event loop
    pthread_t thread_id;
    if (pthread_create(&thread_id, NULL, event_loop_thread, ctx) != 0) {
        log_error("failed to create event loop thread");
        return NULL;
    }

    HASH_ADD(hh, ctx->conns->h, cid, LOCAL_CONN_ID_LEN, conn_io);

    while (!quiche_conn_is_established(conn_io->conn)) {
        if (quiche_conn_is_closed(conn_io->conn)) {
            log_error("connection closed");
            return NULL;
        }
    }
    
    log_debug("connection established");

    return (connection_t) conn_io;
    #elif MSQUIC
    log_debug("opening connection");
    struct context *ctx = (struct context *)context;
    QUIC_STATUS status;

    connection_info_t *connection_info = (connection_info_t *)malloc(sizeof(connection_info_t));
    connection_info->connected = 0;
    connection_info->h = NULL;
    connection_info->stream_queue = g_queue_new();
    g_mutex_init(&connection_info->queue_mutex);
    g_cond_init(&connection_info->queue_cond);
    connection_info->lock = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
    connection_info->cond = (pthread_cond_t)PTHREAD_COND_INITIALIZER;

    ctx_conn_t *ctx_conn = (ctx_conn_t *)malloc(sizeof(ctx_conn_t));
    ctx_conn->ctx = ctx;
    ctx_conn->connection_info = connection_info;
    if (QUIC_FAILED(status = ctx->msquic->ConnectionOpen(ctx->registration, connection_callback, ctx_conn, &connection_info->connection)))
    {
        log_error("failed to open connection, 0x%x!", status);
        quic_error = QUIC_ERROR_CONNECTION_FAILED;
        return NULL;
    }

    //
    // Start the connection to the server.
    //
    if (QUIC_FAILED(status = ctx->msquic->ConnectionStart(connection_info->connection, ctx->configuration, QUIC_ADDRESS_FAMILY_INET, ip, (uint16_t)port)))
    {
        log_error("failed to start connection, 0x%x!", status);
        quic_error = QUIC_ERROR_CONNECTION_FAILED;
        return NULL;
    }
    
    pthread_mutex_lock(&ctx->lock);
    if (!connection_info->connected)
    {
        log_debug("waiting for connection to be established");
        pthread_cond_wait(&ctx->cond, &ctx->lock);
    }
    pthread_mutex_unlock(&ctx->lock);

    //get cid from connection
    int32_t cid_len = sizeof(connection_info->cid);
    if (QUIC_FAILED(status = ctx->msquic->GetParam(connection_info->connection, QUIC_PARAM_CONN_ORIG_DEST_CID, &cid_len, connection_info->cid))) {
        log_error("failed to get connection local cid, 0x%x!", status);
        quic_error = QUIC_ERROR_CONNECTION_FAILED;
        return NULL;
    }
    // Convert binary CID to hexadecimal for logging
    char cid_hex[2 * cid_len + 1]; // Hex representation + null terminator
    for (uint32_t i = 0; i < cid_len; i++) {
        snprintf(&cid_hex[i * 2], 3, "%02x", (unsigned char)connection_info->cid[i]);
    }

    log_trace("connection established, cid: %s", cid_hex);

    HASH_ADD(hh, ctx->h, connection, sizeof(HQUIC), connection_info);

    return (connection_t) connection_info;
    #endif
}

int close_connection(context_t context, connection_t connection) {
    #ifdef QUICHE
    log_debug("closing connection");
    struct context *ctx = (struct context *)context;
    struct conn_io *conn_io = (struct conn_io *)connection;
    pthread_mutex_lock(&conn_io->lock);
    uint8_t error_code;
    size_t error_len = sizeof(error_code);
    quiche_conn_close(conn_io->conn, true, 0, &error_code, error_len);
    pthread_mutex_unlock(&conn_io->lock);
    flush_egress(ctx->loop, conn_io);
    quiche_conn_free(conn_io->conn);
    HASH_DELETE(hh, ctx->conns->h, conn_io);
    free(conn_io);
    return 0;
    #elif MSQUIC
    struct context *ctx = (struct context *)context;
    connection_info_t *connection_info = connection;
    
    ctx->msquic->ConnectionShutdown(connection_info->connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
    // pthread_mutex_lock(&ctx->lock);
    // if (connection_info) {
    //     pthread_cond_wait(&ctx->cond, &ctx->lock);
    // }
    // pthread_mutex_unlock(&ctx->lock);
    return 0;
    #endif
}

stream_t open_stream(context_t context, connection_t connection) {
    #ifdef QUICHE
    log_debug("open stream");
    struct context *ctx = (struct context *)context;
    struct conn_io *conn_io = (struct conn_io *)connection;
    struct connections *conns = ctx->conns;
    struct stream_io *stream_io = NULL;

    if (!quiche_conn_is_closed(conn_io->conn)) {
        const static uint8_t r[] = "open stream";
        uint64_t error_code;

        if (quiche_conn_stream_send(conn_io->conn, 4, r, sizeof(r), false, &error_code) < 0) {
            log_error("failed to send message: %" PRIu64 "", error_code);
            quic_error = QUIC_ERROR_SEND_FAILED;
            return NULL;
        }
        log_debug("open stream message sent");
        flush_egress(ctx->loop, conn_io);
        
        log_debug("waiting for new stream");
        pthread_mutex_lock(&conn_io->lock);
        while (conn_io->new_stream_io == conn_io->last_stream_io) {
            pthread_cond_wait(&conn_io->cond, &conn_io->lock);
        }
        stream_io = conn_io->new_stream_io;
        pthread_mutex_unlock(&conn_io->lock);
        conn_io->last_stream_io = stream_io;
        stream_io->stream_id = 4;
        stream_io->recv_buf = malloc(sizeof(struct buffer));
        stream_io->recv_buf->buf = NULL;
        stream_io->recv_buf->len = 0;
        stream_io->lock = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
        stream_io->cond = (pthread_cond_t)PTHREAD_COND_INITIALIZER;

        HASH_ADD(hh, conn_io->h, stream_id, sizeof(uint64_t), stream_io);
    }

    log_debug("stream opened: %p", (void *)stream_io);

    return (stream_t) stream_io;
    #elif MSQUIC
    log_debug("opening stream");
    struct context *ctx = (struct context *)context;
    HQUIC stream;
    connection_info_t *connection_info = connection;
    
    stream_info_t *stream_info = (stream_info_t *)malloc(sizeof(stream_info_t));

    // Allocate memory for the data buffer
    stream_info->recv_buff.buffer = (void *)malloc(sizeof(void *));
    if (stream_info->recv_buff.buffer == NULL) {
        // Handle memory allocation failure
        log_error("failed to allocate memory for stream buffer");
        quic_error = QUIC_ERROR_ALLOCATION_FAILED;
        return NULL;
    }
    stream_info->recv_buff.total_buffer_length = 0;
    stream_info->recv_buff.absolute_offset = 0;
    stream_info->lock = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
    stream_info->cond = (pthread_cond_t)PTHREAD_COND_INITIALIZER;
    stream_info->can_send = TRUE;

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
        log_error("failed to open stream, 0x%x!", status);
        quic_error = QUIC_ERROR_STREAM_FAILED;
        return NULL;
    }

    //
    // Starts the bidirectional stream. By default, the peer is not notified of
    // the stream being started until data is sent on the stream.
    //
    if (QUIC_FAILED(status = ctx->msquic->StreamStart(stream, QUIC_STREAM_START_FLAG_IMMEDIATE)))
    {
        log_error("failed to start stream, 0x%x!", status);
        quic_error = QUIC_ERROR_STREAM_FAILED;
        ctx->msquic->StreamClose(stream);
        return NULL;
    }
    
    uint64_t stream_id;
    uint32_t buffer_len = sizeof(stream_id);
    if (QUIC_FAILED(status = ctx->msquic->GetParam(stream, QUIC_PARAM_STREAM_ID, &buffer_len, &stream_id)))
    {
        log_error("failed to get stream id, 0x%x!", status);
        quic_error = QUIC_ERROR_STREAM_FAILED;
        return NULL;
    }
    log_debug("[strm][%p] stream id: %llu\n", (void *)stream, (unsigned long long)stream_id);
    stream_info->stream = stream;
    stream_info->stream_id = stream_id;
    char data[256];
    ssize_t len = recv_data(context, connection, (stream_t) stream_info, data, 256, 0);
    if (strcmp(data, "STREAM HSK") == 0) {
        log_debug("stream established");
    }
    HASH_ADD(hh, connection_info->h, stream, sizeof(HQUIC), stream_info);
    return (stream_t) stream_info;
    #endif
}

int close_stream(context_t context, connection_t connection, stream_t stream) {
    #ifdef QUICHE
    log_debug("closing stream");
    struct context *ctx = (struct context *)context;
    struct conn_io *conn_io = (struct conn_io *)connection;
    struct stream_io *stream_io = (struct stream_io *)stream;
    pthread_mutex_lock(&conn_io->lock);
    uint64_t error_code;
    quiche_conn_stream_send(conn_io->conn, stream_io->stream_id, "EOS", strlen("EOS"), true, &error_code);
    pthread_mutex_unlock(&conn_io->lock);
    flush_egress(ctx->loop, conn_io);
    quiche_conn_stream_shutdown(conn_io->conn, stream_io->stream_id, true, 0);
    HASH_DELETE(hh, conn_io->h, stream_io);
    free(stream_io);
    return 0;
    #elif MSQUIC
    struct context *ctx = (struct context *)context;
    stream_info_t *stream_info = stream;
    connection_info_t *connection_info = connection;
    ctx->msquic->StreamSend(stream_info->stream, NULL, 0, QUIC_SEND_FLAG_FIN, NULL);
    #endif
}

int send_data(context_t context, connection_t connection, stream_t stream, void* data, int len) {
    #ifdef QUICHE
    log_debug("sending data");
    struct context *ctx = (struct context *)context;
    struct conn_io *conn_io = (struct conn_io *)connection;
    struct stream_io *stream_io = (struct stream_io *)stream;
    if (!quiche_conn_is_closed(conn_io->conn)) {
        uint64_t error_code;
        
        // check if data can be sent on the stream
        // Wait until the stream has enough capacity to send data
        pthread_mutex_lock(&conn_io->lock);
        ssize_t cap;
        while (cap = quiche_conn_stream_capacity(conn_io->conn, stream_io->stream_id) < len) {
            log_debug("stream is blocked, waiting for capacity: %lld", cap);
            pthread_cond_wait(&conn_io->cond, &conn_io->lock);
        }
        if (quiche_conn_stream_send(conn_io->conn, stream_io->stream_id, data, len, false, &error_code) < 0) {
            log_error("failed to send message: %" PRIu64 "", error_code);
            quic_error = QUIC_ERROR_SEND_FAILED;
            pthread_mutex_unlock(&conn_io->lock);
            return -1;
        }
        pthread_mutex_unlock(&conn_io->lock);
        flush_egress(ctx->loop, conn_io);
    } else {
        log_error("connection is closed");
        return -1;
    }

    log_debug("data sent");

    return 0;

    #elif MSQUIC
    log_debug("sending data");
    struct context *ctx = (struct context *)context;
    QUIC_STATUS status = QUIC_STATUS_SUCCESS;
    connection_info_t *connection_info = connection;
    stream_info_t *stream_info = stream;

    uint8_t *send_buffer_raw;
    QUIC_BUFFER *send_buffer;
    //
    // Allocates and builds the buffer to send over the stream.
    //
    send_buffer_raw = (uint8_t *)malloc(sizeof(QUIC_BUFFER) + sizeof(data));
    if (send_buffer_raw == NULL)
    {
        log_error("failed to allocate send buffer");
        status = QUIC_STATUS_OUT_OF_MEMORY;
        quic_error = QUIC_ERROR_ALLOCATION_FAILED;
        return -1;
    }

    send_buffer = (QUIC_BUFFER *)send_buffer_raw;
    send_buffer->Buffer = data;
    send_buffer->Length = (uint32_t)len;
    
    //
    // Sends the buffer over the stream. Note the FIN flag is passed along with
    // the buffer. This indicates this is the last buffer on the stream and the
    // the stream is shut down (in the send direction) immediately after.
    //
    stream_info->can_send = FALSE;
    if (QUIC_FAILED(status = ctx->msquic->StreamSend(stream_info->stream, send_buffer, 1, QUIC_SEND_FLAG_NONE, send_buffer)))
    {
        log_error("send stream failed, 0x%x!", status);
        free(send_buffer_raw);
        return -1;
    }

    pthread_mutex_lock(&stream_info->lock);
    if (stream_info->can_send == FALSE) {
        log_debug("waiting for data to be sent");
        pthread_cond_wait(&stream_info->cond, &stream_info->lock);
    }
    pthread_mutex_unlock(&stream_info->lock);
    log_debug("sent %d bytes", len);
    #endif
    
}

ssize_t recv_data(context_t context, connection_t connection, stream_t stream, void* buf, ssize_t n_bytes, time_t timeout) {
    #ifdef QUICHE
    struct context *ctx = (struct context *)context;
    struct conn_io *conn_io = (struct conn_io *)connection;
    struct stream_io *stream_io = (struct stream_io *)stream;
    ssize_t to_read = 0;

    log_debug("receiving data");

    if (!quiche_conn_is_closed(conn_io->conn)) {
        struct stream_io *stream_io_check;
        HASH_FIND(hh, conn_io->h, &stream_io->stream_id, sizeof(stream_io->stream_id), stream_io_check);
        if (stream_io_check == NULL) {
            log_error("stream not found");
            return -1;
        }
        pthread_mutex_lock(&stream_io->lock);
        if (stream_io->recv_buf->len == 0) {
            if (timeout == 0) {    
                log_debug("waiting for data");
                pthread_cond_wait(&stream_io->cond, &stream_io->lock);
            } else {
                struct timespec ts;
                clock_gettime(CLOCK_REALTIME, &ts);
                ts.tv_sec += timeout;
                int ret = pthread_cond_timedwait(&stream_io->cond, &stream_io->lock, &ts);
                if (ret == ETIMEDOUT) {
                    log_debug("timed out");
                    pthread_mutex_unlock(&stream_io->lock);
                    return -1; // Indicate timeout
                }
            }
        }

        if (quiche_conn_is_closed(conn_io->conn)) {
            log_error("connection is closed");
            pthread_mutex_unlock(&stream_io->lock);
            return -1;
        }

        // Calculate the amount of data to read
        to_read = stream_io->recv_buf->len;
        if (to_read > n_bytes) {
            to_read = n_bytes;
        } else if (to_read == 0) {
            log_debug("no data available");
            pthread_mutex_unlock(&stream_io->lock);
            return 0; // No data available
        }

        // Copy data to the buffer
        size_t copied = 0;
        struct buffer *current_buffer = stream_io->recv_buf;
        size_t copy_size = current_buffer->len < (to_read - copied) ? current_buffer->len : (to_read - copied);
        memcpy((uint8_t *)buf + copied, current_buffer->buf, copy_size);
        copied += copy_size;

        // Update the buffer state
        if (copy_size < current_buffer->len) {
            // There is still data left in the current buffer
            memmove(current_buffer->buf, current_buffer->buf + copy_size, current_buffer->len - copy_size);
            current_buffer->len -= copy_size;
        } else {
            // Remove the current buffer
            current_buffer->buf = NULL;
            current_buffer->len = 0;
        }
        pthread_mutex_unlock(&stream_io->lock);
    }

    return to_read;
    #elif MSQUIC
    log_debug("receiving data");

    struct context *ctx = (struct context *)context;
    connection_info_t *connection_info = connection;
    stream_info_t *stream_info = stream;

    pthread_mutex_lock(&stream_info->lock);

    if (stream_info->recv_buff.total_buffer_length == 0) {
        // Wait for data to be available
        if (timeout == 0) {
            log_debug("waiting for data");
            pthread_cond_wait(&stream_info->cond, &stream_info->lock);
        } else {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += timeout;
            int ret = pthread_cond_timedwait(&stream_info->cond, &stream_info->lock, &ts);
            if (ret == ETIMEDOUT) {
                log_debug("timed out");
                pthread_mutex_unlock(&stream_info->lock);
                return -1; // Indicate timeout
            }
        }
    }

    if (stream_info->stream == NULL) {
        log_error("stream is closed");
        pthread_mutex_unlock(&stream_info->lock);
        return -1;
    }

    // Calculate the amount of data to read
    ssize_t to_read = stream_info->recv_buff.total_buffer_length;
    if (to_read > n_bytes) {
        to_read = n_bytes;
    } else if (to_read == 0) {
        log_debug("no data available");
        pthread_mutex_unlock(&stream_info->lock);
        return 0; // No data available
    }
    memcpy(buf, stream_info->recv_buff.buffer, to_read);
    memmove(stream_info->recv_buff.buffer, stream_info->recv_buff.buffer + to_read, stream_info->recv_buff.total_buffer_length - to_read);
    stream_info->recv_buff.total_buffer_length -= to_read;
    pthread_mutex_unlock(&stream_info->lock); 
    return to_read;
    #endif
}

int set_listen(context_t context) {
    #ifdef QUICHE
    struct context *ctx = (struct context *)context;

    ctx->loop = ev_default_loop(0);

    ev_io_init(&ctx->watcher, read_socket_cb, ctx->conns->sock, EV_READ);
    ev_io_start(ctx->loop, &ctx->watcher);
    ctx->watcher.data = ctx;

    // Create a new thread for the event loop
    pthread_t thread_id;
    if (pthread_create(&thread_id, NULL, event_loop_thread, ctx) != 0) {
        log_error("failed to create event loop thread");
        return -1;
    }
    return 0;
    #elif MSQUIC
    log_debug("setting listener");
    struct context *ctx = (struct context *)context;
    QUIC_STATUS status = QUIC_STATUS_SUCCESS;
    if (QUIC_FAILED(status = ctx->msquic->ListenerOpen(ctx->registration, listener_callback, ctx, &ctx->s.listener)))
    {
        log_error("listener open failed, 0x%x!", status);
        quic_error = QUIC_ERROR_INITIALIZATION_FAILED;
        return -1;
    }

    if (QUIC_FAILED(status = ctx->msquic->ListenerStart(ctx->s.listener, &ctx->alpn, 1, &ctx->s.local_address)))
    {
        log_error("listener start failed, 0x%x!", status);
        quic_error = QUIC_ERROR_ADDRESS_NOT_AVAILABLE;
        return -1;
    }
    log_debug("listening");
    return 0;
    #endif
}

connection_t accept_connection(context_t context, time_t timeout) {
    #ifdef QUICHE
    struct context *ctx = (struct context *)context;
    log_debug("accepting connection");

    struct conn_io *conn_io = NULL;

    g_mutex_lock(&ctx->queue_mutex);
    while (g_queue_is_empty(ctx->conn_io_queue)) {
        log_debug("waiting for new connection");
        g_cond_wait(&ctx->queue_cond, &ctx->queue_mutex);
    }
    conn_io = g_queue_pop_head(ctx->conn_io_queue);
    g_mutex_unlock(&ctx->queue_mutex);

    while (!quiche_conn_is_established(conn_io->conn))
    {
        if (quiche_conn_is_closed(conn_io->conn))
        {
            log_error("connection closed");
            free(conn_io);
            return NULL;
        }
    }

    log_debug("new connection accepted");

    return (connection_t) conn_io;

    #elif MSQUIC
    log_debug("accepting connection");
    struct context *ctx = (struct context *)context;
    connection_info_t *connection_info = NULL; 

    // Lock the mutex to wait for a connection
    g_mutex_lock(&ctx->queue_mutex);
    while (g_queue_is_empty(ctx->conn_queue)) {
        log_debug("waiting for new connection");
        g_cond_wait(&ctx->queue_cond, &ctx->queue_mutex);
    }
    connection_info = g_queue_pop_head(ctx->conn_queue);
    g_mutex_unlock(&ctx->queue_mutex);

    log_warn("connection received");

    // Wait for the connection to be established
    pthread_mutex_lock(&connection_info->lock);
    if (!connection_info->connected) {
        log_debug("waiting for connection to be established");
        pthread_cond_wait(&connection_info->cond, &connection_info->lock);
    }
    pthread_mutex_unlock(&connection_info->lock);

    HASH_ADD(hh, ctx->h, connection, sizeof(HQUIC), connection_info);

    log_debug("new connection accepted");
    return (connection_t)connection_info;
    #endif
}

stream_t accept_stream(context_t context, connection_t connection, time_t timeout) {
    #ifdef QUICHE
    struct context *ctx = (struct context *)context;
    struct conn_io *conn_io = (struct conn_io *)connection;
    struct stream_io *stream_io = NULL;

    log_debug("accepting stream");
    g_mutex_lock(&conn_io->queue_mutex);
    while (g_queue_is_empty(conn_io->stream_io_queue)) {
        log_debug("waiting for new stream");
        g_cond_wait(&conn_io->queue_cond, &conn_io->queue_mutex);
    }
    stream_io = g_queue_pop_head(conn_io->stream_io_queue);
    g_mutex_unlock(&conn_io->queue_mutex);

    log_debug("new stream accepted");

    return (stream_t) stream_io;
    #elif MSQUIC
    log_debug("accepting stream");
    struct context *ctx = (struct context *)context;
    connection_info_t *connection_info = connection;
    stream_info_t *stream_info = NULL;
    
    // Lock the mutex to wait for a connection
    g_mutex_lock(&connection_info->queue_mutex);
    while (g_queue_is_empty(connection_info->stream_queue)) {
        log_debug("waiting for new stream");
        g_cond_wait(&connection_info->queue_cond, &connection_info->queue_mutex);
    }
    stream_info = g_queue_pop_head(connection_info->stream_queue);
    g_mutex_unlock(&connection_info->queue_mutex);

    char* data = "STREAM HSK";
    send_data(context, (connection_t)connection, (stream_t)stream_info, data, 11);
    HASH_ADD(hh, connection_info->h, stream, sizeof(HQUIC), stream_info);

    log_debug("new stream accepted");
    return (stream_t)stream_info;
    #endif
}

char* quic_error_message(quic_error_code_t quic_error) {
    switch (quic_error) {
        case QUIC_SUCCESS:
            return "success";
        case QUIC_ERROR_INVALID_ARGUMENT:
            return "invalid argument";
        case QUIC_ERROR_CONNECTION_FAILED:
            return "connection failed";
        case QUIC_ERROR_STREAM_FAILED:
            return "stream failed";
        case QUIC_ERROR_SEND_FAILED:
            return "failed to send data";
        case QUIC_ERROR_RECV_FAILED:
            return "failed to receive data";
        case QUIC_ERROR_TIMEOUT:
            return "operation timed out";
        case QUIC_ERROR_ALLOCATION_FAILED:
            return "allocation failed";
        case QUIC_ERROR_UNKNOWN:
            return "unknown error";
        default:
            return "unknown error";
    }
    
}