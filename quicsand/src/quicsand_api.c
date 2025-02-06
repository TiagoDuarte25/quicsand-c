#include "quicsand_api.h"
#include <errno.h>
#include <log.h>
#include <poll.h>

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

#include <sys/socket.h>
#include <sys/un.h>

#include <ev.h>
#include <quiche.h>

#define LOCAL_CONN_ID_LEN 16

#define MAX_DATAGRAM_SIZE 1450

#define MAX_TOKEN_LEN \
    sizeof("quiche") - 1 + \
    sizeof(struct sockaddr_storage) + \
    QUICHE_MAX_CONN_ID_LEN

struct connections {
    int sock;

    struct sockaddr_strorage *local_addr;
    socklen_t local_addr_len;

    struct conn_io *h;

    GHashTable *connections;

    quiche_config *config;
};

struct conn_io {
    ev_timer timer;

    int sock;

    uint8_t cid[LOCAL_CONN_ID_LEN];

    quiche_conn *conn;

    struct sockaddr_storage peer_addr;
    socklen_t peer_addr_len;

    struct sockaddr_storage local_addr;
    socklen_t local_addr_len;

    UT_hash_handle hh;

    GHashTable *streams;

    GQueue *stream_io_queue;
    GMutex queue_mutex;
    GCond queue_cond;

    pthread_t conn_thread;
    pthread_mutex_t mutex;
    pthread_cond_t cond;

    int stream_count;
};

struct stream_io {
    ssize_t stream_id;

    struct buffer *recv_buf;

    pthread_t w_thread;
    int c_fd;
    int s_fd;
    int a_fd;
    struct sockaddr_un addr;
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

struct stream_ctx {
    struct context *ctx;
    struct conn_io *conn_io;
    struct stream_io *stream_io;
};

struct timeout_args {
    struct context *ctx;
    struct conn_io *conn_io;
};

#define NUM_FLUSH_WORKERS 4  // Number of worker threads

typedef struct {
    struct conn_io *conn_io;
} FlushTask;

// Global GQueue for connections needing flush_egress
GQueue *flush_queue;
GMutex queue_mutex;
GCond queue_cond;

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
#include <sys/socket.h>
#include <sys/un.h>


#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(P) (void)(P)
#endif

#ifndef NULL
#define NULL (void *)0
#endif

#define MAX_STREAMS 20000
#define MAX_CONNECTIONS 50

typedef struct {
    HQUIC stream;
    uint64_t stream_id;

    UT_hash_handle hh;
    pthread_t w_thread;
    int c_fd;
    int s_fd;
    int a_fd;
    struct sockaddr_un addr;
    int buffer_count;

    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int ready; 

    // to clear
    size_t bytes_received;
    size_t bytes_written;
} stream_info_t;

typedef struct {
    HQUIC connection;
    GQueue *stream_queue;
    GMutex queue_mutex;
    GCond queue_cond;
    uint8_t cid[20];
    UT_hash_handle hh;
    stream_info_t *h;
    struct context *ctx;
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

    connection_info_t *h;
};
#endif

#ifdef MSQUIC

void* accept_unix_socket(void * args) {
    stream_info_t *stream_info = (stream_info_t *)args;

    if((stream_info->a_fd = accept(stream_info->s_fd, NULL, NULL)) < 0) {
        return NULL;
    }
    return (void *)&stream_info->a_fd;
}

void* connect_unix_socket(void * args) {
    stream_info_t *stream_info = (stream_info_t *)args;

    if (connect(stream_info->c_fd, (struct sockaddr *)&stream_info->addr, sizeof(struct sockaddr_un)) < 0) {
        log_error("failed to connect to unix socket");
        quic_error = QUIC_ERROR_STREAM_FAILED;
        return NULL;
    }

    return (void *)&stream_info->c_fd;
}

void * stream_write(void *arg) {
    
    ctx_strm_t *ctx_strm = (ctx_strm_t *)arg;
    stream_info_t *stream_info = ctx_strm->stream_info;
    struct context *ctx = ctx_strm->ctx;
    char buffer[65536];

    stream_info->bytes_received = 0;
    stream_info->bytes_written = 0;

    while (1) {
        int len = read(stream_info->a_fd, buffer, sizeof(buffer));
        log_trace("[strm][%p] stream_write: read %d bytes", (void *)stream_info->stream, len);
        if (len < 0) {
            log_error("failed to read from unix socket: %s", strerror(errno));
            return NULL;
        }
        if (len == 0) {
            log_trace("[strm][%p] stream_write: EOF");
            if (stream_info == NULL) {
                log_trace("stream_write: stream_info is NULL");
                return NULL;
            }
            pthread_mutex_lock(&stream_info->mutex);
            log_trace("[strm][%p] stream_write: shutting down stream %p gracefully", (void *)stream_info->stream , stream_info->stream);
            ctx->msquic->StreamShutdown(stream_info->stream, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0);
            pthread_mutex_unlock(&stream_info->mutex);
            return NULL;
        }
        
        log_trace("[strm][%p] stream_write: preparing to send %d bytes", (void *)stream_info->stream , len);
        QUIC_BUFFER *send_buffer = malloc(sizeof(QUIC_BUFFER));
        if (!send_buffer) {
            log_error("failed to allocate memory for send_buffer");
            return NULL;
        }
        send_buffer->Buffer = malloc(len);
        if (!send_buffer->Buffer) {
            log_error("failed to allocate memory for send_buffer->Buffer");
            free(send_buffer);
            return NULL;
        }
        memcpy(send_buffer->Buffer, buffer, len);
        send_buffer->Length = len;
        
        pthread_mutex_lock(&stream_info->mutex);
        stream_info->buffer_count++;
        stream_info->ready = 0;
        log_trace("[strm][%p] stream_write: sending %d bytes on stream %p", (void *)stream_info->stream , len, stream_info->stream);
        QUIC_STATUS status = ctx->msquic->StreamSend(stream_info->stream, send_buffer, 1, QUIC_SEND_FLAG_NONE, send_buffer);
        pthread_mutex_unlock(&stream_info->mutex);
        if (QUIC_FAILED(status)) {
            log_error("send stream failed, 0x%x!", status);
            // free(send_buffer);
            return NULL;
        }
        pthread_mutex_lock(&stream_info->mutex);
        if (stream_info->ready == 0) {
            log_trace("stream_write: waiting for stream %p to be ready", stream_info->stream);  
            pthread_cond_wait(&stream_info->cond, &stream_info->mutex);
        }  
        log_trace("[strm][%p] stream_write: sent %d bytes", (void *)stream_info->stream, len);
        pthread_mutex_unlock(&stream_info->mutex);
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
    ctx_strm_t *ctx_strm = (ctx_strm_t *)context;
    struct context *ctx = ctx_strm->ctx;
    connection_info_t *connection_info = ctx_strm->connection_info;
    stream_info_t *stream_info = ctx_strm->stream_info;
    switch (event->Type)
    {
    case QUIC_STREAM_EVENT_START_COMPLETE:
        pthread_mutex_lock(&stream_info->mutex);
        log_trace("[conn][%p][strm][%p] start complete", (void*)connection_info->connection, (void *)stream);
        pthread_mutex_unlock(&stream_info->mutex);
        break;
    case QUIC_STREAM_EVENT_RECEIVE:
        
        // write to the unix socket if can't send block until it can
        pthread_mutex_lock(&stream_info->mutex);
        log_trace("[conn][%p][strm][%p] data receive", (void*)connection_info->connection, (void *)stream);

        int len = event->RECEIVE.TotalBufferLength;

        int sndbuf;
        socklen_t optlen = sizeof(sndbuf);
        if (getsockopt(stream_info->a_fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, &optlen) == -1) {
            log_error("getsockopt failed: %s", strerror(errno));
        }
        
        stream_info->bytes_received += len;

        size_t total_bytes_written = 0;
        
        for (int i = 0; i < event->RECEIVE.BufferCount; i++) {
            size_t buffer_bytes_written = 0;
            while (buffer_bytes_written < event->RECEIVE.Buffers[i].Length) {
                struct pollfd pfd;
                pfd.fd = stream_info->a_fd;
                pfd.events = POLLOUT;

                int poll_result = poll(&pfd, 1, -1); // Wait indefinitely until the socket is writable
                if (poll_result < 0) {
                    log_error("poll failed: %s", strerror(errno));
                    pthread_mutex_unlock(&stream_info->mutex);
                    return -1;
                }

                if (pfd.revents & POLLOUT) {
                    size_t bytes_to_write = event->RECEIVE.Buffers[i].Length - buffer_bytes_written;
                    if (bytes_to_write > sndbuf) {
                        bytes_to_write = sndbuf;
                    }
                    ssize_t bytes_written = write(stream_info->a_fd, event->RECEIVE.Buffers[i].Buffer + buffer_bytes_written, bytes_to_write);
                    if (bytes_written < 0) {
                        log_error("write failed: %s", strerror(errno));
                        pthread_mutex_unlock(&stream_info->mutex);
                        return -1;
                    }
                    buffer_bytes_written += bytes_written;
                    total_bytes_written += bytes_written;
                }
            }
        }
        pthread_mutex_unlock(&stream_info->mutex);
        break;  
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        pthread_mutex_lock(&stream_info->mutex);
        stream_info->ready = 1;
        pthread_cond_signal(&stream_info->cond);
        pthread_mutex_unlock(&stream_info->mutex);
        log_trace("[conn][%p][strm][%p] send complete", (void*)connection_info->connection, (void *)stream);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        pthread_mutex_lock(&stream_info->mutex);
        log_trace("[conn][%p][strm][%p] peer send shutdown", (void*)connection_info->connection, (void *)stream);
        shutdown(stream_info->a_fd, SHUT_WR);
        pthread_mutex_unlock(&stream_info->mutex);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        pthread_mutex_lock(&stream_info->mutex);
        ctx->msquic->StreamShutdown(stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        log_trace("[conn][%p][strm][%p] peer send aborted", (void*)connection_info->connection, (void *)stream);
        pthread_mutex_unlock(&stream_info->mutex);
        break;
    case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
        pthread_mutex_lock(&stream_info->mutex);
        log_trace("[conn][%p][strm][%p] peer receive aborted", (void*)connection_info->connection, (void *)stream);
        ctx->msquic->StreamClose(stream);
        pthread_mutex_unlock(&stream_info->mutex);
        break;
    case QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE:
        pthread_mutex_lock(&stream_info->mutex);
        log_trace("[conn][%p][strm][%p] send shutdown complete", (void*)connection_info->connection, (void *)stream);
        pthread_mutex_unlock(&stream_info->mutex);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        log_trace("[conn][%p][strm] all done", (void*)connection_info->connection);
        HASH_DELETE(hh, connection_info->h, stream_info);
        if (stream_info->a_fd >= 0) {
            shutdown(stream_info->a_fd, SHUT_RDWR);
            close(stream_info->a_fd);
            stream_info->a_fd = -1;
        }
        if (stream_info->c_fd >= 0) {
            shutdown(stream_info->c_fd, SHUT_RDWR);
            close(stream_info->c_fd);
            stream_info->c_fd = -1;
        }
        if (stream_info->s_fd >= 0) {
            shutdown(stream_info->s_fd, SHUT_RDWR);
            close(stream_info->s_fd);
            stream_info->s_fd = -1;
        }
        unlink(stream_info->addr.sun_path);
        free(stream_info);
        break;
    case QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE:
        log_trace("[strm][%p] ideal send buffer size: %u", (void *)stream, event->IDEAL_SEND_BUFFER_SIZE.ByteCount);
        break;
    case QUIC_STREAM_EVENT_PEER_ACCEPTED:
        log_trace("[conn][%p][strm][%p] peer accepted", (void*)connection_info->connection, (void *)stream);
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
        log_trace("[conn][%p] connection established", (void *)connection_info->connection);
        g_mutex_lock(&ctx->queue_mutex);
        g_queue_push_tail(ctx->conn_queue, connection_info);
        g_cond_signal(&ctx->queue_cond);
        g_mutex_unlock(&ctx->queue_mutex);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        log_trace("[conn][%p] shutdown initiated by transport, 0x%x", (void *)connection, event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
        if (event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status == QUIC_STATUS_CONNECTION_IDLE)
        {
            log_trace("[conn][%p] successfully shut down on idle.", (void *)connection);
        }
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        g_mutex_lock(&connection_info->queue_mutex);
        g_queue_push_tail(connection_info->stream_queue, NULL);
        g_cond_signal(&connection_info->queue_cond);
        g_mutex_unlock(&connection_info->queue_mutex);
        log_trace("[conn][%p] shutdown initiated by peer, 0x%llu", (void *)connection, (unsigned long long)event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        log_trace("[conn][%p] shutdown complete", (void *)connection);
        HASH_DELETE(hh, ctx->h, connection_info);
        if (!event->SHUTDOWN_COMPLETE.AppCloseInProgress)
        {
            log_trace("[conn][%p] app close not in progress", (void *)connection);
            ctx->msquic->ConnectionClose(connection);  
            free(connection_info);  
        }
        break;
    case QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED:
        log_trace("[conn][%p] local address changed", (void *)connection);
        break;
    case QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED:
        log_trace("[conn][%p] peer address changed", (void *)connection);
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        stream_info_t *stream_info = (stream_info_t *)malloc(sizeof(stream_info_t));
        stream_info->stream = event->PEER_STREAM_STARTED.Stream;
        stream_info->s_fd = -1;
        stream_info->c_fd = -1;
        stream_info->a_fd = -1;

        stream_info->buffer_count = 0;

        stream_info->mutex = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
        stream_info->cond = (pthread_cond_t)PTHREAD_COND_INITIALIZER;
        stream_info->ready = 0;

        int s_fd, c_fd;
        if ((s_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
            log_error("failed to create unix socket");
            quic_error = QUIC_ERROR_STREAM_FAILED;
            return -1;
        }

        log_trace("server socket created with fd: %d", s_fd);

        if ((c_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
            log_error("failed to create unix socket");
            quic_error = QUIC_ERROR_STREAM_FAILED;
            return -1;
        }

        log_trace("client socket created with fd: %d", c_fd);

        struct sockaddr_un addr;

        addr.sun_family = AF_UNIX;
        char * path = "/tmp/quicsand-sockets/";
        char * sun_path = malloc(strlen(path) + 10);
        sprintf(sun_path, "%s%d", path, s_fd);
        strcpy(addr.sun_path, sun_path);

        log_trace("server socket path: %s", addr.sun_path);


        // Create directory if it does not exist
        if (mkdir(path, 0777) && errno != EEXIST) {
            log_error("failed to create directory: %s", strerror(errno));
            quic_error = QUIC_ERROR_STREAM_FAILED;
            close(c_fd);
            close(s_fd);
            return -1;
        }

        if (bind(s_fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) < 0) {
            log_error("failed to bind unix socket");
            quic_error = QUIC_ERROR_STREAM_FAILED;
            return -1;
        }

        if (listen(s_fd, 1) < 0) {
            log_error("failed to listen on unix socket");
            quic_error = QUIC_ERROR_STREAM_FAILED;
            return -1;
        }

        stream_info->s_fd = s_fd;
        stream_info->c_fd = c_fd;
        stream_info->addr = addr;

        pthread_t accept_thread, connect_thread;
        pthread_create(&accept_thread, NULL, accept_unix_socket, (void *)stream_info);
        pthread_create(&connect_thread, NULL, connect_unix_socket, (void *)stream_info);

        pthread_join(accept_thread, NULL);
        pthread_join(connect_thread, NULL);

        ctx_strm_t *ctx_strm = (ctx_strm_t *)malloc(sizeof(ctx_strm_t));
        ctx_strm->ctx = ctx;
        ctx_strm->connection_info = connection_info;
        ctx_strm->stream_info = stream_info;

        pthread_create(&stream_info->w_thread, NULL, stream_write, (void *)ctx_strm);
        pthread_detach(stream_info->w_thread);

        g_mutex_lock(&connection_info->queue_mutex);
        g_queue_push_tail(connection_info->stream_queue, stream_info);
        g_cond_signal(&connection_info->queue_cond);
        g_mutex_unlock(&connection_info->queue_mutex);
        ctx->msquic->SetCallbackHandler(stream_info->stream, (void *)stream_callback, ctx_strm);
        log_trace("[strm][%p] peer started", (void *)event->PEER_STREAM_STARTED.Stream);
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
        connection_info->connection = event->NEW_CONNECTION.Connection;
        connection_info->h = NULL;
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

// Helper function to convert uint64_t to a pointer
static inline gpointer uint64_to_ptr(uint64_t key) {
    return (gpointer)(uintptr_t)key;
}

// Helper function to convert a pointer back to uint64_t
static inline uint64_t ptr_to_uint64(gconstpointer ptr) {
    return (uint64_t)(uintptr_t)ptr;
}

// Function to free stream_io objects when removing from hash table
void free_stream_io(gpointer value) {
    struct stream_io *s = (struct stream_io *)value;
    printf("Freeing stream_io with id: %ld\n", s->stream_id);
    free(s);
}

// Custom hash function for uint64_t keys
guint hash_uint64(gconstpointer key) {
    uint64_t k = ptr_to_uint64(key);
    return (guint)(k ^ (k >> 32)); // Simple hash for 64-bit key
}

// Custom equality function for uint64_t keys
gboolean equal_uint64(gconstpointer a, gconstpointer b) {
    return ptr_to_uint64(a) == ptr_to_uint64(b);
}

void* client_recv_cb(void *arg);
void* stream_write(void *arg);
void* accept_unix_socket(void *args);
void* connect_unix_socket(void *args);
void* flush_egress(void *arg);
void* flush_egress_thread(struct conn_io *conn_io);
void* read_socket_cb(void *arg);

// run flush_egress in a separate thread
void* flush_egress_thread(struct conn_io *conn_io) {
    pthread_t pthread;
    pthread_create(&pthread, NULL, flush_egress, (void*)conn_io);
    pthread_detach(pthread);
    return NULL;
}

void* flush_egress(void *arg) {
    struct conn_io *conn_io = (struct conn_io *)arg;
    uint8_t out[MAX_DATAGRAM_SIZE];

    quiche_send_info send_info;

    while (1) {
        log_warn("flush_egress: waiting for data");
        pthread_mutex_lock(&conn_io->mutex);
        ssize_t written = quiche_conn_send(conn_io->conn, out, sizeof(out),
                                           &send_info);
        pthread_mutex_unlock(&conn_io->mutex);

        if (written == QUICHE_ERR_DONE) {
            log_trace("done writing");
            break;
        }

        if (written < 0) {
            log_error("failed to create packet: %zd", written);
            return NULL;
        }

        pthread_mutex_lock(&conn_io->mutex);
        ssize_t sent = sendto(conn_io->sock, out, written, 0,
                              (struct sockaddr *) &send_info.to,
                              send_info.to_len);
        pthread_mutex_unlock(&conn_io->mutex);
        if (sent != written) {
            log_error("failed to send packet: %zd, expected: %zd, error: %s", sent, written, strerror(errno));
            return NULL;
        }

        log_trace("flush_egress: sent %zd bytes", sent);
    }
    return NULL;
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

    memset(conn_io, 0, sizeof(struct conn_io));

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

    conn_io->streams = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, free_stream_io);
    if (conn_io->streams == NULL) {
        log_error("failed to create hash table for streams");
        free(conn_io);
        return NULL;
    }

    memcpy(&conn_io->peer_addr, peer_addr, peer_addr_len);
    conn_io->peer_addr_len = peer_addr_len;

    conn_io->stream_io_queue = g_queue_new();
    g_mutex_init(&conn_io->queue_mutex);
    g_cond_init(&conn_io->queue_cond);

    conn_io->mutex = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
    conn_io->cond = (pthread_cond_t)PTHREAD_COND_INITIALIZER;

    log_trace("created connection %p", (void *)conn_io);

    return conn_io;
}

void* read_socket_cb(void *arg) 
{
    struct context *ctx = (struct context *)arg;
    struct connections *conns = ctx->conns;
    uint8_t buf[65535];
    uint8_t out[MAX_DATAGRAM_SIZE];
    while (1) {
        struct conn_io *conn_io;
        struct sockaddr_storage peer_addr;
        socklen_t peer_addr_len = sizeof(peer_addr);
        memset(&peer_addr, 0, peer_addr_len);
        ssize_t read = recvfrom(conns->sock, buf, sizeof(buf), 0,
                                (struct sockaddr *) &peer_addr,
                                &peer_addr_len);

        if (read < 0) {
            if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
                continue;
            }
            else {
                log_error("failed to read, error: %s", strerror(errno));
                return NULL;
            }
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

        int rc = quiche_header_info(buf, read, LOCAL_CONN_ID_LEN, &version,
                                    &type, scid, &scid_len, dcid, &dcid_len,
                                    token, &token_len);
        if (rc < 0) {
            log_error("[conn] failed to parse header: %d", rc);
            continue;
        }

        log_trace("[conn] Parsed header: version=%u, type=%u, scid_len=%zu, dcid_len=%zu, token_len=%zu", version, type, scid_len, dcid_len, token_len);
        
        conn_io = g_hash_table_lookup(conns->connections, dcid);

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
                log_error("[conn] [%p] failed to create connection", conn_io);
                continue;
            }

            g_mutex_lock(&ctx->queue_mutex);
            g_queue_push_tail(ctx->conn_io_queue, conn_io);
            g_cond_signal(&ctx->queue_cond);
            g_mutex_unlock(&ctx->queue_mutex);

            g_hash_table_insert(conns->connections, dcid, conn_io);
        }

        log_trace("[conn] [%p] found connection", conn_io);

        if (conn_io == NULL) {
            log_error("[conn] conn_io is NULL");
            continue;
        }

        quiche_recv_info recv_info = {
            (struct sockaddr *)&peer_addr,
            peer_addr_len,

            (struct sockaddr *)&conns->local_addr,
            conns->local_addr_len,
        };

        pthread_mutex_lock(&conn_io->mutex);
        ssize_t done = quiche_conn_recv(conn_io->conn, buf, read, &recv_info);
        pthread_cond_signal(&conn_io->cond);
        if (done < 0) {
            log_error("[conn] [%p] failed to process packet: %zd", conn_io, done);
            continue;
        }
        log_trace("[conn] [%p] recv %zd bytes", conn_io, done);
        pthread_mutex_unlock(&conn_io->mutex);

        flush_egress_thread(conn_io);

        pthread_mutex_lock(&conn_io->mutex);
        if (quiche_conn_is_draining(conn_io->conn)) {
            g_mutex_lock(&conn_io->queue_mutex);
            g_queue_push_tail(conn_io->stream_io_queue, NULL);
            g_cond_signal(&conn_io->queue_cond);
            g_mutex_unlock(&conn_io->queue_mutex);
            log_trace("[conn] [%p] connection draining", conn_io);
            pthread_mutex_unlock(&conn_io->mutex);
            continue;
        } else {
            log_trace("[conn] [%p] connection not draining", conn_io);
        }

        if (quiche_conn_is_established(conn_io->conn)) {
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
                    continue;
                }

                struct stream_io *stream_io = g_hash_table_lookup(conn_io->streams, uint64_to_ptr(s));

                if (fin) {
                    if (stream_io == NULL) {
                        continue;
                    }
                    stream_io->stream_id = -1;
                    log_trace("stream %" PRIu64 " is finished", s);
                    close(stream_io->a_fd);
                    close(stream_io->c_fd);
                    close(stream_io->s_fd);
                    unlink(stream_io->addr.sun_path);
                    log_trace("stream %" PRIu64 " closed", s);
                    continue;
                }

                if (stream_io == NULL) {
                    log_trace("[conn] [%p] stream %p not found", conn_io, (void *)stream_io);
                    log_trace("buf: %s", buf);
                    stream_io = malloc(sizeof(struct stream_io));
                    if (stream_io == NULL) {
                        log_error("[conn] [%p] failed to allocate stream IO", conn_io);
                        continue;
                    }
                    stream_io->stream_id = (ssize_t)s;

                    int s_fd, c_fd;
                    if ((s_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
                        log_error("failed to create unix socket");
                        quic_error = QUIC_ERROR_STREAM_FAILED;
                        continue;
                    }

                    log_trace("server socket created");

                    if ((c_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
                        log_error("failed to create unix socket");
                        quic_error = QUIC_ERROR_STREAM_FAILED;
                        pthread_mutex_unlock(&conn_io->mutex);
                        continue;
                    }

                    struct sockaddr_un addr;

                    addr.sun_family = AF_UNIX;
                    char * path = "/tmp/quicsand-sockets/";
                    char * sun_path = malloc(strlen(path) + 20);
                    sprintf(sun_path, "%s%d_%ld", path, s_fd, stream_io->stream_id); // Include stream_id in the path
                    strcpy(addr.sun_path, sun_path);

                    log_trace("server socket path: %s", addr.sun_path);

                    // Create directory if it does not exist
                    if (mkdir(path, 0777) && errno != EEXIST) {
                        log_error("failed to create directory: %s", strerror(errno));
                        quic_error = QUIC_ERROR_STREAM_FAILED;
                        free(sun_path);
                        close(c_fd);
                        close(s_fd);
                        continue;
                    }

                    log_trace("created directory");

                    unlink(sun_path);

                    if (bind(s_fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) < 0) {
                        log_error("failed to bind unix socket");
                        quic_error = QUIC_ERROR_STREAM_FAILED;
                        continue;
                    }

                    if (listen(s_fd, 1) < 0) {
                        log_error("failed to listen on unix socket");
                        quic_error = QUIC_ERROR_STREAM_FAILED;
                        continue;
                    }

                    stream_io->s_fd = s_fd;
                    stream_io->c_fd = c_fd;
                    stream_io->addr = addr;

                    pthread_t accept_thread, connect_thread;
                    pthread_create(&accept_thread, NULL, accept_unix_socket, (void *)stream_io);
                    pthread_create(&connect_thread, NULL, connect_unix_socket, (void *)stream_io);

                    pthread_join(accept_thread, NULL);
                    pthread_join(connect_thread, NULL);

                    struct stream_ctx *stream_ctx = malloc(sizeof(struct stream_ctx));
                    stream_ctx->ctx = ctx;
                    stream_ctx->conn_io = conn_io;
                    stream_ctx->stream_io = stream_io;

                    pthread_create(&stream_io->w_thread, NULL, stream_write, (void *)stream_ctx);
                    pthread_detach(stream_io->w_thread);

                    g_hash_table_insert(conn_io->streams, uint64_to_ptr(s), stream_io);
                    g_mutex_lock(&conn_io->queue_mutex);
                    g_queue_push_tail(conn_io->stream_io_queue, stream_io);
                    g_cond_signal(&conn_io->queue_cond);
                    g_mutex_unlock(&conn_io->queue_mutex);
                } else {
                    log_trace("[conn] [%p] writing to stream %p", conn_io, (void *)stream_io);
                    ssize_t res = write(stream_io->a_fd, buf, recv_len);
                    if (res < 0) {
                        log_error("failed to write to stream: %s", strerror(errno));
                        continue;
                    }
                }
            }
            quiche_stream_iter_free(readable);
        }
        pthread_mutex_unlock(&conn_io->mutex);

        flush_egress_thread(conn_io);
    }
}

void* client_recv_cb(void *arg) {
    struct conn_io *conn_io = (struct conn_io *)arg;
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
                continue;
            }
            log_error("failed to read: %s", strerror(errno));
            return NULL;
        }

        log_trace("recv %zd bytes", read);

        uint8_t type;
        uint32_t version;

        uint8_t scid[QUICHE_MAX_CONN_ID_LEN];
        size_t scid_len = sizeof(scid);

        uint8_t dcid[QUICHE_MAX_CONN_ID_LEN];
        size_t dcid_len = sizeof(dcid);

        uint8_t token[MAX_TOKEN_LEN];
        size_t token_len = sizeof(token);

        int rc = quiche_header_info(buf, read, LOCAL_CONN_ID_LEN, &version,
                                    &type, scid, &scid_len, dcid, &dcid_len,
                                    token, &token_len);
        if (rc < 0) {
            log_error("failed to parse header: %d", rc);
            continue;
        }

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
            return NULL;
        }
        pthread_mutex_lock(&conn_io->mutex);
        ssize_t done = quiche_conn_recv(conn_io->conn, buf, read, &recv_info);
        pthread_cond_signal(&conn_io->cond);
        if (done < 0) {
            log_error("failed to process packet");
            continue;
        }
        log_trace("connection %p: recv %zd bytes", conn_io, done);
        pthread_mutex_unlock(&conn_io->mutex);

        flush_egress_thread(conn_io);

        pthread_mutex_lock(&conn_io->mutex);
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

                struct stream_io *stream_io = g_hash_table_lookup(conn_io->streams, uint64_to_ptr(s));

                if (fin) {
                    if (stream_io == NULL) {
                        continue;
                    }
                    stream_io->stream_id = -1;
                    shutdown(stream_io->a_fd, SHUT_RDWR);
                    close(stream_io->c_fd);
                    close(stream_io->s_fd);
                    close(stream_io->a_fd);
                    log_trace("stream %" PRIu64 " closed", s);
                    continue;
                }
                
                if (stream_io == NULL) {
                    log_trace("stream not found");
                    if (strcmp((char *)buf, "stream opened") == 0) {
                        g_mutex_lock(&conn_io->queue_mutex);
                        stream_io = malloc(sizeof(struct stream_io));
                        g_queue_push_tail(conn_io->stream_io_queue, stream_io);
                        g_cond_signal(&conn_io->queue_cond);
                        g_mutex_unlock(&conn_io->queue_mutex);
                    }
                } else {
                    log_trace("stream %p found", (void *)stream_io);
                    ssize_t wrote = write(stream_io->a_fd, buf, recv_len);
                    if (wrote < 0) {
                        log_error("failed to write to stream: %s", strerror(errno));
                        continue;
                    }
                }
            }
            quiche_stream_iter_free(readable);
        }
        pthread_mutex_unlock(&conn_io->mutex);

        flush_egress_thread(conn_io);
    }
}

void* accept_unix_socket(void * args) {
    struct stream_io *stream_io = (struct stream_io *)args;

    if((stream_io->a_fd = accept(stream_io->s_fd, NULL, NULL)) < 0) {
        log_error("failed to accept unix socket");
        return NULL;
    }
    return (void *)&stream_io->a_fd;
}

void* connect_unix_socket(void * args) {
    struct stream_io *stream_io = (struct stream_io *)args;

    if (connect(stream_io->c_fd, (struct sockaddr *)&stream_io->addr, sizeof(struct sockaddr_un)) < 0) {
        log_error("failed to connect to unix socket");
        quic_error = QUIC_ERROR_STREAM_FAILED;
        return NULL;
    }

    return (void *)&stream_io->c_fd;
}

void * stream_write(void *arg) {
    struct stream_ctx *stream_ctx = (struct stream_ctx *)arg;
    struct conn_io *conn_io = stream_ctx->conn_io;
    struct stream_io *stream_io = stream_ctx->stream_io;

    char buffer[65536];
    while (1) {
        log_trace("strm_write: reading from unix socket %d", stream_io->a_fd);
        int to_read = 0;
        pthread_mutex_lock(&conn_io->mutex);
        log_trace("strm_write: conn lock", (void *)conn_io);
        while ((to_read = quiche_conn_stream_capacity(conn_io->conn, stream_io->stream_id)) <= 0) {
            log_trace("strm_write: conn %ld is blocked", stream_io->stream_id);
            pthread_cond_wait(&conn_io->cond, &conn_io->mutex); 
        }
        log_trace("strm_write: conn unlock", (void *)conn_io);
        pthread_mutex_unlock(&conn_io->mutex);
        log_trace("to_read: %d", to_read);
        ssize_t len = read(stream_io->a_fd, buffer, to_read);
        uint64_t error_code;
        if (len <= 0) {
            log_trace("strm_write: stream %ld closed", stream_io->stream_id);
            flush_egress(conn_io);
            pthread_mutex_lock(&conn_io->mutex);
            char* close_msg = "fin";
            if (stream_io->stream_id == -1) {
                log_trace("stream already closed");
                // g_hash_table_remove(conn_io->streams, uint64_to_ptr(stream_io->stream_id));
                pthread_mutex_unlock(&conn_io->mutex);
                break;
            }
            while (quiche_conn_stream_writable(conn_io->conn, stream_io->stream_id, strlen(close_msg)) <= 0) {
                pthread_cond_wait(&conn_io->cond, &conn_io->mutex);
            }
            if (quiche_conn_stream_send(conn_io->conn, stream_io->stream_id, (const uint8_t *)close_msg, strlen(close_msg), true, &error_code) < 0) {
                log_error("failed to finish the stream: %" PRIu64 " to_read: %d", error_code, to_read);
                quic_error = QUIC_ERROR_SEND_FAILED;
                pthread_mutex_unlock(&conn_io->mutex);
                break;
            }
            log_trace("fin sent");
            pthread_mutex_unlock(&conn_io->mutex);
            flush_egress(conn_io);
            // pthread_mutex_lock(&conn_io->mutex);
            // g_hash_table_remove(conn_io->streams, uint64_to_ptr(stream_io->stream_id));
            // stream_io = NULL;
            // pthread_mutex_unlock(&conn_io->mutex);

            break;
        }

        pthread_mutex_lock(&conn_io->mutex);
        if (!quiche_conn_is_closed(conn_io->conn)) {
            while (quiche_conn_stream_writable(conn_io->conn, stream_io->stream_id, len) <= 0) {
                pthread_cond_wait(&conn_io->cond, &conn_io->mutex);
            }
            if (quiche_conn_stream_send(conn_io->conn, stream_io->stream_id, (const uint8_t *)buffer, len, false, &error_code) < 0) {
                log_error("failed to send message: %" PRIu64 " to_read: %d", error_code, to_read);
                quic_error = QUIC_ERROR_SEND_FAILED;
                pthread_mutex_unlock(&conn_io->mutex);
                break;
            }
            log_trace("strm_write: sent %d bytes", len);
        } else {
            log_error("connection is closed");
            pthread_mutex_unlock(&conn_io->mutex);
            break;
        }
        pthread_mutex_unlock(&conn_io->mutex);
        flush_egress(conn_io);
    }
    free(stream_ctx);
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

        quiche_config_set_application_protos(ctx->config,
                                            (uint8_t *) "\x0ahq-interop\x05hq-29\x05hq-28\x05hq-27\x08http/0.9", 38);
        // quiche_config_set_application_protos(ctx->config,
        //                                     (uint8_t *)"\x05hq-29\x05hq-28\x05hq-27", 15);
        // quiche_config_set_max_idle_timeout(ctx->config, 10000000);
        quiche_config_set_max_recv_udp_payload_size(ctx->config, MAX_DATAGRAM_SIZE);
        quiche_config_set_max_send_udp_payload_size(ctx->config, MAX_DATAGRAM_SIZE);
        quiche_config_set_initial_max_data(ctx->config, 1000000000);
        quiche_config_set_initial_max_stream_data_bidi_local(ctx->config, 1000000000);
        quiche_config_set_initial_max_stream_data_bidi_remote(ctx->config, 1000000000);
        quiche_config_set_initial_max_streams_bidi(ctx->config, 10000);
        // quiche_config_set_initial_congestion_window_packets(ctx->config, 50);
        quiche_config_set_cc_algorithm(ctx->config, QUICHE_CC_CUBIC);

        ctx->conns = (struct connections *)malloc(sizeof(struct connections));
        if (ctx->conns == NULL)
        {
            log_error("failed to allocate connections");
            quic_error = QUIC_ERROR_ALLOCATION_FAILED;
            return NULL;
        }
        ctx->conns->config = ctx->config;
        ctx->conns->connections = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, free);

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
    memset(conn_io, 0, sizeof(struct conn_io));

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
    memcpy(&conn_io->peer_addr, peer->ai_addr, peer->ai_addrlen);
    conn_io->peer_addr_len = peer->ai_addrlen;
    conn_io->streams = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, free_stream_io);
    conn_io->stream_count = 0;
    conn_io->stream_io_queue = g_queue_new();
    g_mutex_init(&conn_io->queue_mutex);
    g_cond_init(&conn_io->queue_cond);
    conn_io->mutex = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
    conn_io->cond = (pthread_cond_t)PTHREAD_COND_INITIALIZER;

    
    pthread_create(&conn_io->conn_thread, NULL, client_recv_cb, (void*)conn_io);
    pthread_detach(conn_io->conn_thread);
    flush_egress_thread(conn_io);

    g_hash_table_insert(ctx->conns->connections, scid, conn_io);

    pthread_mutex_lock(&conn_io->mutex);
    while (!quiche_conn_is_established(conn_io->conn)) {
        pthread_cond_wait(&conn_io->cond, &conn_io->mutex);
    }
    pthread_mutex_unlock(&conn_io->mutex);
    flush_egress_thread(conn_io);

    // print all transport parameters
    quiche_transport_params params;
    quiche_conn_peer_transport_params(conn_io->conn, &params);
    log_trace("transport parameters:");
    log_trace("  peer_max_idle_timeout: %" PRIu64, params.peer_max_idle_timeout);
    log_trace("  peer_max_udp_payload_size: %" PRIu64, params.peer_max_udp_payload_size);
    log_trace("  peer_initial_max_data: %" PRIu64, params.peer_initial_max_data);
    log_trace("  peer_initial_max_stream_data_bidi_local: %" PRIu64, params.peer_initial_max_stream_data_bidi_local);
    log_trace("  peer_initial_max_stream_data_bidi_remote: %" PRIu64, params.peer_initial_max_stream_data_bidi_remote);
    log_trace("  peer_initial_max_stream_data_uni: %" PRIu64, params.peer_initial_max_stream_data_uni);
    log_trace("  peer_initial_max_streams_bidi: %" PRIu64, params.peer_initial_max_streams_bidi);
    log_trace("  peer_initial_max_streams_uni: %" PRIu64, params.peer_initial_max_streams_uni);
    log_trace("  peer_ack_delay_exponent: %" PRIu64, params.peer_ack_delay_exponent);
    log_trace("  peer_max_ack_delay: %" PRIu64, params.peer_max_ack_delay);
    log_trace("  peer_disable_active_migration: %s", params.peer_disable_active_migration ? "true" : "false");
    log_trace("  peer_active_conn_id_limit: %" PRIu64, params.peer_active_conn_id_limit);
    log_trace("  peer_max_datagram_frame_size: %zd", params.peer_max_datagram_frame_size);

    quiche_path_stats path_stats;
    quiche_conn_path_stats(conn_io->conn, 0, &path_stats);
    log_trace("cwnd size: %ld", path_stats.cwnd);
    
    log_debug("connection established");

    free(peer->ai_addr);
    free(peer);
    peer = NULL;

    return (connection_t) conn_io;
    #elif MSQUIC
    log_debug("opening connection");
    struct context *ctx = (struct context *)context;
    QUIC_STATUS status;

    connection_info_t *connection_info = (connection_info_t *)malloc(sizeof(connection_info_t));
    connection_info->h = NULL;
    connection_info->stream_queue = g_queue_new();
    g_mutex_init(&connection_info->queue_mutex);
    g_cond_init(&connection_info->queue_cond);

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

    // wait for connection to be established
    g_mutex_lock(&ctx->queue_mutex);
    if (g_queue_is_empty(ctx->conn_queue)) {
        g_cond_wait(&ctx->queue_cond, &ctx->queue_mutex);
        g_queue_pop_head(ctx->conn_queue);
    }
    g_mutex_unlock(&ctx->queue_mutex);

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

    if (conn_io == NULL) {
        log_error("connection is NULL");
        return -1;
    }

    const uint8_t *error_code = (const uint8_t *) "kthxbye";
    pthread_mutex_lock(&conn_io->mutex);
    quiche_conn_close(conn_io->conn, false, 0, error_code, 7);
    pthread_mutex_unlock(&conn_io->mutex);

    // Free streams
    if (conn_io->streams != NULL) {
        g_hash_table_destroy(conn_io->streams);
    }

    // Free stream_io_queue
    if (conn_io->stream_io_queue != NULL) {
        g_queue_free(conn_io->stream_io_queue);
    }

    // Free the connection
    pthread_mutex_lock(&conn_io->mutex);
    quiche_conn_free(conn_io->conn);
    pthread_cancel(conn_io->conn_thread);
    pthread_mutex_unlock(&conn_io->mutex);
    
    g_hash_table_remove(ctx->conns->connections, conn_io->cid);
    return 0;
    #elif MSQUIC
    struct context *ctx = (struct context *)context;
    connection_info_t *connection_info = connection;
    ctx->msquic->ConnectionShutdown(connection_info->connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
    return 0;
    #endif
}

int open_stream(context_t context, connection_t connection) {
    #ifdef QUICHE
    log_debug("open stream");
    struct context *ctx = (struct context *)context;
    struct conn_io *conn_io = (struct conn_io *)connection;
    struct stream_io *stream_io = NULL;

    uint8_t r[] = "open stream";
    uint64_t error_code;

    conn_io->stream_count = conn_io->stream_count + 4;
    
    stream_io = malloc(sizeof(struct stream_io));
    if (stream_io == NULL) {
        log_error("failed to allocate memory for stream_io");
        return -1;
    }
    stream_io->stream_id = conn_io->stream_count;

    g_hash_table_insert(conn_io->streams, uint64_to_ptr(stream_io->stream_id), stream_io);

    int s_fd, c_fd;
    if ((s_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        log_error("failed to create unix socket");
        quic_error = QUIC_ERROR_STREAM_FAILED;
        return -1;
    }

    log_trace("server socket created");

    if ((c_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        log_error("failed to create unix socket");
        quic_error = QUIC_ERROR_STREAM_FAILED;
        return -1;
    }

    struct sockaddr_un addr;

    addr.sun_family = AF_UNIX;
    char * path = "/tmp/quicsand-sockets/";
    char * sun_path = malloc(strlen(path) + 20);
    sprintf(sun_path, "%s%d", path, s_fd);
    strcpy(addr.sun_path, sun_path);
    sprintf(sun_path, "%s%d_%d", path, getpid(), s_fd); // Use process ID and socket FD to create unique path
    strcpy(addr.sun_path, sun_path);

    log_trace("server socket path: %s", addr.sun_path);

    // Create directory if it does not exist
    if (mkdir(path, 0777) && errno != EEXIST) {
        log_error("failed to create directory: %s", strerror(errno));
        quic_error = QUIC_ERROR_STREAM_FAILED;
        free(sun_path);
        close(c_fd);
        close(s_fd);
        return -1;
    }

    // Remove existing socket file if it exists
    unlink(addr.sun_path);

    if (bind(s_fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) < 0) {
        log_error("failed to bind unix socket");
        quic_error = QUIC_ERROR_STREAM_FAILED;
        return -1;
    }

    if (listen(s_fd, 1) < 0) {
        log_error("failed to listen on unix socket");
        quic_error = QUIC_ERROR_STREAM_FAILED;
        return -1;
    }

    stream_io->s_fd = s_fd;
    stream_io->c_fd = c_fd;
    stream_io->addr = addr;

    pthread_t accept_thread, connect_thread;
    pthread_create(&accept_thread, NULL, accept_unix_socket, (void *)stream_io);
    pthread_create(&connect_thread, NULL, connect_unix_socket, (void *)stream_io);

    pthread_join(accept_thread, NULL);
    pthread_join(connect_thread, NULL);

    struct stream_ctx *stream_ctx = malloc(sizeof(struct stream_ctx));
    stream_ctx->ctx = ctx;
    stream_ctx->conn_io = conn_io;
    stream_ctx->stream_io = stream_io;
    
    pthread_create(&stream_io->w_thread, NULL, stream_write, (void *)stream_ctx);
    pthread_detach(stream_io->w_thread);

    log_trace("sending open stream message to stream id: %d", conn_io->stream_count);
    pthread_mutex_lock(&conn_io->mutex);
    if (quiche_conn_stream_send(conn_io->conn, conn_io->stream_count, r, sizeof(r), false, &error_code) < 0) {
        log_error("failed to send message: %" PRIu64 "", error_code);
        quic_error = QUIC_ERROR_SEND_FAILED;
        return -1;
    }
    pthread_mutex_unlock(&conn_io->mutex);

    flush_egress(conn_io);

    free(sun_path);

    log_debug("stream opened: %p", (void *)stream_io);

    return stream_io->c_fd;
    #elif MSQUIC
        log_debug("opening stream");
        struct context *ctx = (struct context *)context;
        connection_info_t *connection_info = connection;
        
        stream_info_t *stream_info = (stream_info_t *)malloc(sizeof(stream_info_t));
        if (!stream_info) {
            log_error("failed to allocate memory for stream_info");
            return -1;
        }
        stream_info->a_fd = -1;
        stream_info->s_fd = -1;
        stream_info->c_fd = -1;
        stream_info->buffer_count = 0;

        stream_info->mutex = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
        stream_info->cond = (pthread_cond_t)PTHREAD_COND_INITIALIZER;
        stream_info->ready = 0;

        ctx_strm_t *ctx_strm = (ctx_strm_t *)malloc(sizeof(ctx_strm_t));
        if (!ctx_strm) {
            log_error("failed to allocate memory for ctx_strm");
            free(stream_info);
            return -1;
        }
        ctx_strm->ctx = ctx;
        ctx_strm->connection_info = connection_info;
        ctx_strm->stream_info = stream_info;

        pthread_mutex_lock(&stream_info->mutex);
        QUIC_STATUS status = QUIC_STATUS_SUCCESS;
        if (QUIC_FAILED(status = ctx->msquic->StreamOpen(connection_info->connection, QUIC_STREAM_OPEN_FLAG_NONE, stream_callback, ctx_strm, &stream_info->stream))) {
            log_error("failed to open stream, 0x%x!", status);
            quic_error = QUIC_ERROR_STREAM_FAILED;
            pthread_mutex_unlock(&stream_info->mutex);
            free(stream_info);
            free(ctx_strm);
            return -1;
        }
        log_debug("stream opened successfully");

        if (QUIC_FAILED(status = ctx->msquic->StreamStart(stream_info->stream, QUIC_STREAM_START_FLAG_IMMEDIATE))) {
            log_error("failed to start stream, 0x%x!", status);
            quic_error = QUIC_ERROR_STREAM_FAILED;
            ctx->msquic->StreamClose(stream_info->stream);
            pthread_mutex_unlock(&stream_info->mutex);
            free(stream_info);
            free(ctx_strm);
            return -1;
        }
        log_debug("stream started successfully");
        pthread_mutex_unlock(&stream_info->mutex);

        int s_fd, c_fd;
        if ((s_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
            log_error("failed to create server unix socket");
            quic_error = QUIC_ERROR_STREAM_FAILED;
            ctx->msquic->StreamClose(stream_info->stream);
            free(stream_info);
            free(ctx_strm);
            return -1;
        }
        log_debug("server socket created, fd: %d", s_fd);

        if ((c_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
            log_error("failed to create client unix socket");
            quic_error = QUIC_ERROR_STREAM_FAILED;
            close(s_fd);
            ctx->msquic->StreamClose(stream_info->stream);
            free(stream_info);
            free(ctx_strm);
            return -1;
        }
        log_debug("client socket created, fd: %d", c_fd);

        struct sockaddr_un addr;
        addr.sun_family = AF_UNIX;
        char *path = "/tmp/quicsand-sockets/";
        char *sun_path = malloc(strlen(path) + 20); // Increased size to accommodate unique identifier
        if (!sun_path) {
            log_error("failed to allocate memory for sun_path");
            close(c_fd);
            close(s_fd);
            ctx->msquic->StreamClose(stream_info->stream);
            free(stream_info);
            free(ctx_strm);
            return -1;
        }
        sprintf(sun_path, "%s%d_%d", path, getpid(), s_fd); // Use process ID and socket FD to create unique path
        strcpy(addr.sun_path, sun_path);

        if (mkdir(path, 0777) && errno != EEXIST) {
            log_error("failed to create directory: %s", strerror(errno));
            quic_error = QUIC_ERROR_STREAM_FAILED;
            free(sun_path);
            close(c_fd);
            close(s_fd);
            ctx->msquic->StreamClose(stream_info->stream);
            free(stream_info);
            free(ctx_strm);
            return -1;
        }
        log_debug("directory created or already exists: %s", path);

        if (bind(s_fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) < 0) {
            log_error("failed to bind server unix socket");
            quic_error = QUIC_ERROR_STREAM_FAILED;
            free(sun_path);
            close(c_fd);
            close(s_fd);
            ctx->msquic->StreamClose(stream_info->stream);
            free(stream_info);
            free(ctx_strm);
            return -1;
        }
        log_debug("server socket bound to path: %s", addr.sun_path);

        if (listen(s_fd, 1) < 0) {
            log_error("failed to listen on server unix socket");
            quic_error = QUIC_ERROR_STREAM_FAILED;
            free(sun_path);
            close(c_fd);
            close(s_fd);
            ctx->msquic->StreamClose(stream_info->stream);
            free(stream_info);
            free(ctx_strm);
            return -1;
        }
        log_debug("server socket listening");

        pthread_mutex_lock(&stream_info->mutex);
        stream_info->s_fd = s_fd;
        stream_info->c_fd = c_fd;
        stream_info->addr = addr;
        pthread_mutex_unlock(&stream_info->mutex);

        pthread_t accept_thread, connect_thread;
        pthread_create(&accept_thread, NULL, accept_unix_socket, (void *)stream_info);
        pthread_create(&connect_thread, NULL, connect_unix_socket, (void *)stream_info);

        pthread_join(accept_thread, NULL);
        pthread_join(connect_thread, NULL);

        if (stream_info->s_fd < 0 || stream_info->c_fd < 0) {
            log_error("failed to create unix socket");
            free(sun_path);
            close(c_fd);
            close(s_fd);
            ctx->msquic->StreamClose(stream_info->stream);
            free(stream_info);
            free(ctx_strm);
            return -1;
        }
        log_debug("unix socket connection established");

        pthread_mutex_lock(&stream_info->mutex);
        HASH_ADD(hh, connection_info->h, s_fd, sizeof(int), stream_info);
        pthread_mutex_unlock(&stream_info->mutex);
        log_debug("stream_info added to hash table");

        pthread_create(&stream_info->w_thread, NULL, stream_write, (void *)ctx_strm);
        pthread_detach(stream_info->w_thread);
        log_debug("write thread created and detached");

        free(sun_path);
        return stream_info->c_fd;
    #endif
}

int set_listen(context_t context) {
    #ifdef QUICHE
    pthread_t pthread;
    pthread_create(&pthread, NULL, read_socket_cb, (void*)context);
    pthread_detach(pthread);
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

connection_t accept_connection(context_t context) {
    #ifdef QUICHE
    struct context *ctx = (struct context *)context;
    log_debug("accepting connection");

    struct conn_io *conn_io = NULL;

    g_mutex_lock(&ctx->queue_mutex);
    if (g_queue_is_empty(ctx->conn_io_queue)) {
        log_debug("waiting for new connection");
        g_cond_wait(&ctx->queue_cond, &ctx->queue_mutex);
    }
    conn_io = g_queue_pop_head(ctx->conn_io_queue);
    g_mutex_unlock(&ctx->queue_mutex);
    conn_io->stream_count = 0;

    pthread_mutex_lock(&conn_io->mutex);
    while (!quiche_conn_is_established(conn_io->conn)) {
        pthread_cond_wait(&conn_io->cond, &conn_io->mutex);
    }
    pthread_mutex_unlock(&conn_io->mutex);
    flush_egress_thread(conn_io);

    // print all transport parameters
    quiche_transport_params params;
    quiche_conn_peer_transport_params(conn_io->conn, &params);
    log_trace("transport parameters:");
    log_trace("  peer_max_idle_timeout: %" PRIu64, params.peer_max_idle_timeout);
    log_trace("  peer_max_udp_payload_size: %" PRIu64, params.peer_max_udp_payload_size);
    log_trace("  peer_initial_max_data: %" PRIu64, params.peer_initial_max_data);
    log_trace("  peer_initial_max_stream_data_bidi_local: %" PRIu64, params.peer_initial_max_stream_data_bidi_local);
    log_trace("  peer_initial_max_stream_data_bidi_remote: %" PRIu64, params.peer_initial_max_stream_data_bidi_remote);
    log_trace("  peer_initial_max_stream_data_uni: %" PRIu64, params.peer_initial_max_stream_data_uni);
    log_trace("  peer_initial_max_streams_bidi: %" PRIu64, params.peer_initial_max_streams_bidi);
    log_trace("  peer_initial_max_streams_uni: %" PRIu64, params.peer_initial_max_streams_uni);
    log_trace("  peer_ack_delay_exponent: %" PRIu64, params.peer_ack_delay_exponent);
    log_trace("  peer_max_ack_delay: %" PRIu64, params.peer_max_ack_delay);
    log_trace("  peer_disable_active_migration: %s", params.peer_disable_active_migration ? "true" : "false");
    log_trace("  peer_active_conn_id_limit: %" PRIu64, params.peer_active_conn_id_limit);
    log_trace("  peer_max_datagram_frame_size: %zd", params.peer_max_datagram_frame_size);

    quiche_path_stats path_stats;
    quiche_conn_path_stats(conn_io->conn, 0, &path_stats);
    log_trace("cwnd size: %ld", path_stats.cwnd);

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

    HASH_ADD(hh, ctx->h, connection, sizeof(HQUIC), connection_info);

    log_debug("new connection accepted");
    return (connection_t)connection_info;
    #endif
}

int accept_stream(context_t context, connection_t connection) {
    #ifdef QUICHE

    struct context *ctx = (struct context *)context;
    struct conn_io *conn_io = (struct conn_io *)connection;
    struct stream_io *stream_io = NULL;

    log_trace("context: %p", ctx);
    log_debug("accepting stream");
    g_mutex_lock(&conn_io->queue_mutex);
    if (g_queue_is_empty(conn_io->stream_io_queue)) {
        log_debug("waiting for new stream");
        g_cond_wait(&conn_io->queue_cond, &conn_io->queue_mutex);
    }
    stream_io = g_queue_pop_head(conn_io->stream_io_queue);
    if (stream_io == NULL) {
        log_error("failed to accept stream");
        return -1;
    }
    g_mutex_unlock(&conn_io->queue_mutex);

    log_debug("new stream accepted");

    return stream_io->c_fd;
    #elif MSQUIC
    log_debug("accepting stream");
    struct context *ctx = (struct context *)context;
    connection_info_t *connection_info = connection;
    stream_info_t *stream_info = NULL;
    
    // Lock the mutex to wait for a connection
    g_mutex_lock(&connection_info->queue_mutex);
    if (g_queue_is_empty(connection_info->stream_queue)) {
        log_debug("waiting for new stream");
        g_cond_wait(&connection_info->queue_cond, &connection_info->queue_mutex);
    }
    stream_info = g_queue_pop_head(connection_info->stream_queue);
    if (stream_info == NULL) {
        log_error("failed to accept stream");
        return -1;
    }
    g_mutex_unlock(&connection_info->queue_mutex);

    HASH_ADD(hh, connection_info->h, s_fd, sizeof(int), stream_info);

    log_debug("new stream accepted");
    return stream_info->c_fd;
    #endif
}

void destroy_quic_context(context_t context) {
    #ifdef QUICHE
    struct context *ctx = (struct context *)context;

    if (ctx == NULL) {
        return;
    }

    // Free connections
    if (ctx->conns != NULL) {
        if (ctx->conns->connections != NULL) {
            g_hash_table_destroy(ctx->conns->connections);
        }
        free(ctx->conns);
    }

    // Free config
    if (ctx->config != NULL) {
        quiche_config_free(ctx->config);
    }

    g_queue_free(ctx->conn_io_queue);

    // Free the context
    free(ctx);
    #elif MSQUIC
    struct context *ctx = (struct context *)context;
    if (ctx->msquic != NULL) {
        ctx->msquic->RegistrationClose(ctx->registration);
        MsQuicClose(ctx->msquic);
    }
    free(ctx);
    #endif
}

int get_conneciton_statistics(context_t context, connection_t connection, statistics_t *stats) {
    #ifdef QUICHE
    struct context *ctx = (struct context *)context;
    struct conn_io *conn_io = (struct conn_io *)connection;
    quiche_stats statistics;
    quiche_path_stats path_stats;
    log_trace("context statistics: %p", ctx);
    pthread_mutex_lock(&conn_io->mutex);
    quiche_conn_stats(conn_io->conn, &statistics);
    quiche_conn_path_stats(conn_io->conn, 0, &path_stats);
    pthread_mutex_unlock(&conn_io->mutex);
    stats->avg_rtt = path_stats.rtt / 1e6; // convert nanoseconds to milliseconds
    stats->max_rtt = path_stats.rtt;
    stats->min_rtt = path_stats.rtt;
    stats->total_sent_packets = path_stats.sent;
    stats->total_received_packets = path_stats.recv;
    stats->total_lost_packets = path_stats.lost;
    stats->total_retransmitted_packets = path_stats.retrans;
    stats->total_sent_bytes = path_stats.sent_bytes;
    stats->total_received_bytes = path_stats.recv_bytes;

    

    return 0;
    #elif MSQUIC
    struct context *ctx = (struct context *)context;
    connection_info_t *connection_info = connection;
    QUIC_STATISTICS statistics;
    uint32_t statistics_length = sizeof(statistics);
    if (QUIC_FAILED(ctx->msquic->GetParam(connection_info->connection, QUIC_PARAM_CONN_STATISTICS, &statistics_length, &statistics))) {
        log_error("failed to get connection statistics");
        return -1;
    }
    stats->avg_rtt = statistics.Rtt / 1000;
    stats->max_rtt = statistics.MaxRtt / 1000;
    stats->min_rtt = statistics.MinRtt / 1000;
    stats->total_sent_packets = statistics.Send.TotalPackets;
    stats->total_received_packets = statistics.Recv.TotalPackets;
    stats->total_lost_packets = statistics.Send.SuspectedLostPackets - statistics.Send.SpuriousLostPackets;
    stats->total_retransmitted_packets = statistics.Send.RetransmittablePackets;
    stats->total_sent_bytes = statistics.Send.TotalBytes;
    stats->total_received_bytes = statistics.Recv.TotalBytes;

    return 0;
    #endif
}

char* quic_error_message(quic_error_code_t error_code) {
    switch (error_code) {
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