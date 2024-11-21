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
        QUIC_BUFFER *buffers;
        uint64_t total_buffer_length;
        uint32_t buffer_count;
        uint64_t absolute_offset;
        pthread_mutex_t lock;
        pthread_cond_t cond;
    } recv_buff;

    UT_hash_handle hh;
} stream_info_t;

typedef struct {
    HQUIC connection;
    stream_info_t *last_new_stream;
    stream_info_t *new_stream;
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

    connection_info_t *last_new_connection;
    connection_info_t *new_connection;
    pthread_mutex_t lock;
    pthread_cond_t cond;

    connection_info_t *h;
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
#include <fcntl.h>

#include <ev.h>
#include <lsquic.h>
#include <errno.h>
#include <assert.h>

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
    struct lsquic_engine_api    eapi;
    struct lsquic_engine_settings settings;
    union
    {
        struct client
        {
            struct lsquic_conn *conn;
            size_t              sz;         /* Size of bytes read is stored here */
            char                buf[0x100]; /* Read up to this many bytes */
        }   c;
    };   
    struct sockaddr_storage local_sas;
    union {
        struct sockaddr sa;
        struct sockaddr_in sin;
    } local_addr;
    union {
        struct sockaddr sa;
        struct sockaddr_in sin;
    } peer_addr;
    SSL_CTX *ssl_ctx;
};
#endif

#ifdef LSQUIC

static void process_conns (struct context *);

#define MAX(a, b) ((a) > (b) ? (a) : (b))

static int
log_buf (void *ctx, const char *buf, size_t len)
{
    FILE *out = ctx;
    fwrite(buf, 1, len, out);
    fflush(out);
    return 0;
}
static const struct lsquic_logger_if logger_if = { log_buf, };

static int load_cert(struct context *ctx, char * cert_path, const char * key_path) {

    int rv = -1;

    ctx->ssl_ctx = SSL_CTX_new(TLS_method());
    if (!ctx->ssl_ctx)
    {
        printf("SSL_CTX_new failed\n");
        goto end;
    }
    SSL_CTX_set_min_proto_version(ctx->ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx->ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_default_verify_paths(ctx->ssl_ctx);
    if (1 != SSL_CTX_use_certificate_chain_file(ctx->ssl_ctx, cert_path))
    {
        printf("SSL_CTX_use_certificate_chain_file failed\n");
        goto end;
    }
    if (1 != SSL_CTX_use_PrivateKey_file(ctx->ssl_ctx, key_path,
                                                            SSL_FILETYPE_PEM))
    {
        printf("SSL_CTX_use_PrivateKey_file failed\n");
        goto end;
    }
    rv = 0;

end:
    if (rv != 0)
    {
        if (ctx->ssl_ctx)
            SSL_CTX_free(ctx->ssl_ctx);
        ctx->ssl_ctx = NULL;
    }
    return rv;
}

static SSL_CTX *
get_ssl_ctx (void *peer_ctx, const struct sockaddr *local)
{
    struct context *ctx = (struct context *)peer_ctx;
    return ctx->ssl_ctx;
}

static int
set_nonblocking (int fd)
{
    int flags;

    flags = fcntl(fd, F_GETFL);
    if (-1 == flags)
        return -1;
    flags |= O_NONBLOCK;
    if (0 != fcntl(fd, F_SETFL, flags))
        return -1;

    return 0;
}


/* ToS is used to get ECN value */
static int
set_ecn (int fd, const struct sockaddr *addr)
{
    int on, s;

    on = 1;
    if (AF_INET == addr->sa_family)
        s = setsockopt(fd, IPPROTO_IP, IP_RECVTOS, &on, sizeof(on));
    if (s != 0)
        perror("setsockopt(ecn)");

    return s;
}


/* Set up the socket to return original destination address in ancillary data */
static int
set_origdst(int fd, const struct sockaddr *addr)
{
    int on, s;

    on = 1;
    s = setsockopt(fd, IPPROTO_IP, IP_RECVORIGDSTADDR, &on, sizeof(on));

    if (s != 0)
        perror("setsockopt");

    return s;
}

static lsquic_conn_ctx_t *
on_new_conn (void *stream_if_ctx, struct lsquic_conn *conn)
{
    printf("new connection\n");
    struct context *const ctx = stream_if_ctx;
    ctx->c.conn = conn;
    printf("created connection");
    return (void *) ctx;
}


static void
on_hsk_done (lsquic_conn_t *conn, enum lsquic_hsk_status status)
{
    printf("handshake done\n");
    struct context *const ctx = (void *) lsquic_conn_get_ctx(conn);

    switch (status)
    {
    case LSQ_HSK_OK:
        printf("handshake successful, start stdin watcher");
        break;
    case LSQ_HSK_RESUMED_OK:
        printf("handshake successful, start stdin watcher");
        break;
    default:
        printf("handshake failed");
        break;
    }
}


static void
on_conn_closed (struct lsquic_conn *conn)
{
    printf("client connection closed -- stop reading from socket");
    struct context *const ctx = (void *) lsquic_conn_get_ctx(conn);

    printf("client connection closed -- stop reading from socket");
}


static lsquic_stream_ctx_t *
on_new_stream (void *stream_if_ctx, struct lsquic_stream *stream)
{
    printf("created new stream, we want to write\n");
    struct context *ctx = stream_if_ctx;
    printf("created new stream, we want to write\n");
    lsquic_stream_wantwrite(stream, 1);
    /* return tut: we don't have any stream-specific context */
    return (void *) ctx;
}


/* Echo whatever comes back from server, no verification */
static void
on_read_v0 (struct lsquic_stream *stream, lsquic_stream_ctx_t *h)
{
    printf("read from stream\n");
    struct context *ctx = (struct context *) h;
    ssize_t nread;
    unsigned char buf[3];

    nread = lsquic_stream_read(stream, buf, sizeof(buf));
    if (nread > 0)
    {
        fwrite(buf, 1, nread, stdout);
        fflush(stdout);
    }
    else if (nread == 0)
    {
        printf("read to end-of-stream: close and read from stdin again\n");
        lsquic_stream_shutdown(stream, 0);
    }
    else
    {
        printf("error reading from stream (%s) -- exit loop\n");
    }
}


static size_t
readf_v1 (void *ctx, const unsigned char *data, size_t len, int fin)
{
    if (len)
    {
        fwrite(data, 1, len, stdout);
        fflush(stdout);
    }
    return len;
}


/* Same functionality as on_read_v0(), but use a readf callback */
static void
on_read_v1 (struct lsquic_stream *stream, lsquic_stream_ctx_t *h)
{
    struct context *ctx = (struct context *) h;
    ssize_t nread;

    nread = lsquic_stream_readf(stream, readf_v1, NULL);
    if (nread == 0)
    {
        printf("read to end-of-stream: close and read from stdin again\n");
        lsquic_stream_shutdown(stream, 0);
    }
    else if (nread < 0)
    {
        printf("error reading from stream (%s) -- exit loop\n");
    }
}


/* Alternatively, pass `stream' to lsquic_stream_readf() and call
 * lsquic_stream_get_ctx() to get struct tut *
 */
struct read_v2_ctx {
    struct context     *ctx;
    lsquic_stream_t *stream;
};


static size_t
readf_v2 (void *ctx, const unsigned char *data, size_t len, int fin)
{
    struct read_v2_ctx *v2ctx = ctx;
    if (len)
        fwrite(data, 1, len, stdout);
    if (fin)
    {
        fflush(stdout);
        printf("read to end-of-stream: close and read from stdin again");
        lsquic_stream_shutdown(v2ctx->stream, 0);
    }
    return len;
}


/* A bit different from v1: act on fin.  This version saves an extra on_read()
 * call at the cost of some complexity.
 */
static void
on_read_v2 (struct lsquic_stream *stream, lsquic_stream_ctx_t *h)
{
    struct context *ctx = (struct context *) h;
    ssize_t nread;

    // struct client_read_v2_ctx v2ctx = { ctx, stream, };
    // nread = lsquic_stream_readf(stream, readf_v2, &v2ctx);
    if (nread < 0)
    {
        printf("error reading from stream (%s) -- exit loop\n");
    }
}


/* Write out the whole line to stream, shutdown write end, and switch
 * to reading the response.
 */
static void
on_write (struct lsquic_stream *stream, lsquic_stream_ctx_t *h)
{
    lsquic_conn_t *conn;
    struct context *ctx;
    ssize_t nw;

    conn = lsquic_stream_conn(stream);
    ctx = (void *) lsquic_conn_get_ctx(conn);

    nw = lsquic_stream_write(stream, ctx->c.buf, ctx->c.sz);
    if (nw > 0)
    {
        ctx->c.sz -= (size_t) nw;
        if (ctx->c.sz == 0)
        {
            printf("wrote all %zd bytes to stream, switch to reading\n",
                                                            (size_t) nw);
            lsquic_stream_shutdown(stream, 1);  /* This flushes as well */
            lsquic_stream_wantread(stream, 1);
        }
        else
        {
            memmove(ctx->c.buf, ctx->c.buf + nw, ctx->c.sz);
            printf("wrote %zd bytes to stream, still have %zd bytes to write\n",
                                                (size_t) nw, ctx->c.sz);
        }
    }
    else
    {
        /* When `on_write()' is called, the library guarantees that at least
         * something can be written.  If not, that's an error whether 0 or -1
         * is returned.
         */
        printf("stream_write() returned %ld, abort connection\n", (long) nw);
        lsquic_conn_abort(lsquic_stream_conn(stream));
    }
}


static void
on_close (struct lsquic_stream *stream, lsquic_stream_ctx_t *h)
{
    printf("stream closed\n");
}

static int
packets_out_v0 (void *packets_out_ctx, const struct lsquic_out_spec *specs,
                                                                unsigned count)
{
    printf("packets out\n");
    unsigned n;
    int fd, s = 0;
    struct msghdr msg;

    if (0 == count)
        return 0;

    n = 0;
    msg.msg_flags      = 0;
    msg.msg_control    = NULL;
    msg.msg_controllen = 0;
    do
    {
        fd                 = (int) (uint64_t) specs[n].peer_ctx;
        msg.msg_name       = (void *) specs[n].dest_sa;
        msg.msg_namelen    = (AF_INET == specs[n].dest_sa->sa_family ?
                                            sizeof(struct sockaddr_in) :
                                            sizeof(struct sockaddr_in6)),
        msg.msg_iov        = specs[n].iov;
        msg.msg_iovlen     = specs[n].iovlen;
        s = sendmsg(fd, &msg, 0);
        if (s < 0)
        {
            printf("sendmsg failed: %s\n", strerror(errno));
            break;
        }
        ++n;
    }
    while (n < count);

    if (n < count)
        printf("could not send all of them\n");    /* TODO */

    if (n > 0)
        return n;
    else
    {
        assert(s < 0);
        return -1;
    }
}


static void (*const on_read[])
                        (lsquic_stream_t *, lsquic_stream_ctx_t *h) =
{
    on_read_v0,
    on_read_v1,
    on_read_v2,
};

static struct lsquic_stream_if callbacks =
{
    .on_new_conn        = on_new_conn,
    .on_hsk_done        = on_hsk_done,
    .on_conn_closed     = on_conn_closed,
    .on_new_stream      = on_new_stream,
    .on_read            = on_read_v0,
    .on_write           = on_write,
    .on_close           = on_close,
};

enum ctl_what
{
    CW_SENDADDR = 1 << 0,
    CW_ECN      = 1 << 1,
};


static void
setup_control_msg (struct msghdr *msg, enum ctl_what cw,
        const struct lsquic_out_spec *spec, unsigned char *buf, size_t bufsz)
{
    printf("setup control message\n");
    struct cmsghdr *cmsg;
    struct sockaddr_in *local_sa;
    struct sockaddr_in6 *local_sa6;
    struct in_pktinfo info;
    struct in6_pktinfo info6;
    size_t ctl_len;

    msg->msg_control    = buf;
    msg->msg_controllen = bufsz;

    /* Need to zero the buffer due to a bug(?) in CMSG_NXTHDR.  See
     * https://stackoverflow.com/questions/27601849/cmsg-nxthdr-returns-null-even-though-there-are-more-cmsghdr-objects
     */
    memset(buf, 0, bufsz);

    ctl_len = 0;
    for (cmsg = CMSG_FIRSTHDR(msg); cw && cmsg; cmsg = CMSG_NXTHDR(msg, cmsg))
    {
        if (cw & CW_SENDADDR)
        {
            if (AF_INET == spec->dest_sa->sa_family)
            {
                local_sa = (struct sockaddr_in *) spec->local_sa;
                memset(&info, 0, sizeof(info));
                info.ipi_spec_dst = local_sa->sin_addr;
                cmsg->cmsg_level    = IPPROTO_IP;
                cmsg->cmsg_type     = IP_PKTINFO;
                cmsg->cmsg_len      = CMSG_LEN(sizeof(info));
                ctl_len += CMSG_SPACE(sizeof(info));
                memcpy(CMSG_DATA(cmsg), &info, sizeof(info));
            }
            cw &= ~CW_SENDADDR;
        }
        else if (cw & CW_ECN)
        {
            if (AF_INET == spec->dest_sa->sa_family)
            {
                const int tos = spec->ecn;
                cmsg->cmsg_level = IPPROTO_IP;
                cmsg->cmsg_type  = IP_TOS;
                cmsg->cmsg_len   = CMSG_LEN(sizeof(tos));
                memcpy(CMSG_DATA(cmsg), &tos, sizeof(tos));
                ctl_len += CMSG_SPACE(sizeof(tos));
            }
            cw &= ~CW_ECN;
        }
        else
            assert(0);
    }

    msg->msg_controllen = ctl_len;
}

static void
timer_expired (EV_P_ ev_timer *timer, int revents)
{
    printf("timer expired\n");
    process_conns(timer->data);
}

static void
process_conns (struct context *ctx)
{
    printf("process connections\n");
    int diff;
    ev_tstamp timeout;

    ev_timer_stop(ctx->loop, &ctx->timer);
    lsquic_engine_process_conns(ctx->engine);

    if (lsquic_engine_earliest_adv_tick(ctx->engine, &diff))
    {
        if (diff >= LSQUIC_DF_CLOCK_GRANULARITY)
            /* Expected case: convert to seconds */
            timeout = (ev_tstamp) diff / 1000000;
        else if (diff <= 0)
            /* It should not happen often that the next tick is in the past
             * as we just processed connections.  Avoid a busy loop by
             * scheduling an event:
             */
            timeout = 0.0;
        else
            /* Round up to granularity */
            timeout = (ev_tstamp) LSQUIC_DF_CLOCK_GRANULARITY / 1000000;
        printf("converted diff %d usec to %.4lf seconds\n", diff, timeout);
        ev_timer_init(&ctx->timer, timer_expired, timeout, 0.);
        ev_timer_start(ctx->loop, &ctx->timer);
    }
}





static void
proc_ancillary (struct msghdr *msg, struct sockaddr_storage *storage, int *ecn)
{
    printf("process ancillary\n");
    struct cmsghdr *cmsg;
    for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg))
    {
        if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type  == IP_ORIGDSTADDR)
        {
            memcpy(storage, CMSG_DATA(cmsg), sizeof(struct sockaddr_in));
        }
    }
}

#define DST_MSG_SZ sizeof(struct sockaddr_in)

#define ECN_SZ CMSG_SPACE(sizeof(int))

/* Amount of space required for incoming ancillary data */
#define CTL_SZ (CMSG_SPACE(DST_MSG_SZ))

static void
read_socket (EV_P_ ev_io *w, int revents)
{
    printf("read socket\n");
    struct context *const ctx = w->data;
    ssize_t nread;
    int ecn;
    struct sockaddr_storage peer_sas, local_sas;
    unsigned char buf[0x1000];
    struct iovec vec[1] = {{ buf, sizeof(buf) }};
    unsigned char ctl_buf[CTL_SZ];

    struct msghdr msg = {
        .msg_name       = &peer_sas,
        .msg_namelen    = sizeof(peer_sas),
        .msg_iov        = vec,
        .msg_iovlen     = 1,
        .msg_control    = ctl_buf,
        .msg_controllen = sizeof(ctl_buf),
    };
    nread = recvmsg(w->fd, &msg, 0);
    if (-1 == nread) {
        if (!(EAGAIN == errno || EWOULDBLOCK == errno))
            printf("recvmsg: %s\n", strerror(errno));
        return;
    }

    local_sas = ctx->local_sas;
    ecn = 0;
    proc_ancillary(&msg, &local_sas, &ecn);

    (void) lsquic_engine_packet_in(ctx->engine, buf, nread,
        (struct sockaddr *) &local_sas,
        (struct sockaddr *) &peer_sas,
        (void *) (uintptr_t) w->fd, ecn);

    process_conns(ctx);
}

#elif MSQUIC

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

        log_trace("[strm][%p] start complete", (void *)stream);
        break;
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        //
        // A previous StreamSend call has completed, and the context is being
        // returned back to the app.
        //
        pthread_mutex_lock(&stream_info->lock);
        stream_info->can_send = TRUE;
        pthread_cond_signal(&stream_info->cond);
        pthread_mutex_unlock(&stream_info->lock);
        free(event->SEND_COMPLETE.ClientContext);
        log_trace("[strm][%p] data sent", (void *)stream);
        break;
    case QUIC_STREAM_EVENT_RECEIVE:
        //
        // Data was received from the peer on the stream.
        //
        log_trace("[strm][%p] data received", (void *)stream);
        // Reallocate memory for the recv_buff.buffers array to accommodate the new buffer
        stream_info->recv_buff.buffers = (QUIC_BUFFER *)realloc(
            stream_info->recv_buff.buffers,
            (stream_info->recv_buff.buffer_count + 1) * sizeof(QUIC_BUFFER)
        );
        if (stream_info->recv_buff.buffers == NULL) {
            // Handle memory allocation failure
            log_error("failed to reallocate memory for the recv_buff.buffers array");
            return QUIC_STATUS_OUT_OF_MEMORY;
        }

        // Allocate memory for the new buffer and copy the received data into it
        QUIC_BUFFER *new_buffer = &stream_info->recv_buff.buffers[stream_info->recv_buff.buffer_count];
        new_buffer->Buffer = (uint8_t *)malloc(event->RECEIVE.TotalBufferLength);
        if (new_buffer->Buffer == NULL) {
            // Handle memory allocation failure
            log_error("failed to allocate memory for the new buffer");
            return QUIC_STATUS_OUT_OF_MEMORY;
        }
        pthread_mutex_lock(&stream_info->lock);
        // Update the metadata fields
        memcpy(new_buffer->Buffer, event->RECEIVE.Buffers->Buffer, event->RECEIVE.TotalBufferLength);
        new_buffer->Length = event->RECEIVE.TotalBufferLength;
        stream_info->recv_buff.total_buffer_length += event->RECEIVE.TotalBufferLength;
        stream_info->recv_buff.buffer_count++;
        stream_info->recv_buff.absolute_offset = event->RECEIVE.AbsoluteOffset;
        pthread_cond_signal(&stream_info->cond);
        pthread_mutex_unlock(&stream_info->lock);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        //
        // The peer gracefully shut down its send direction of the stream.
        //
        log_trace("[strm][%p] peer shut down", (void *)stream);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        //
        // The peer aborted its send direction of the stream.
        //
        ctx->msquic->StreamShutdown(stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        log_trace("[strm][%p] peer aborted", (void *)stream);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        //
        // Both directions of the stream have been shut down and MsQuic is done
        // with the stream. It can now be safely cleaned up.
        //
        HASH_DELETE(hh, connection_info->h, stream_info);
        // ctx->msquic->StreamClose(stream);
        log_trace("[strm][%p] all done", (void *)stream);
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
        connection_info->connection = connection;
        ctx->new_connection = connection_info;
        pthread_cond_signal(&ctx->cond);
        pthread_mutex_unlock(&ctx->lock);
        log_trace("[conn][%p] connected", (void *)connection);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        //
        // The connection has been shut down by the transport. Generally, this
        // is the expected way for the connection to shut down with this
        // protocol, since we let idle timeout kill the connection.
        //
        if (event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status == QUIC_STATUS_CONNECTION_IDLE)
        {
            log_trace("[conn][%p] successfully shut down on idle.", (void *)connection);
        }
        else
        {
            log_trace("[conn][%p] shut down by transport, 0x%x", (void *)connection, event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
        }
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        //
        // The connection was explicitly shut down by the peer.
        //
        log_trace("[conn][%p] shut down by peer, 0x%llu", (void *)connection, (unsigned long long)event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        //
        // The connection has completed the shutdown process and is ready to be
        // safely cleaned up.
        //
        HASH_DELETE(hh, ctx->h, connection_info);
        log_trace("[conn][%p] all done", (void *)connection);
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
        log_trace("[conn][%p] resumption ticket received (%u bytes):", (void *)connection, event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength);
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
        stream_info_t *stream_info = (stream_info_t *)malloc(sizeof(stream_info_t));
        stream_info->stream = event->PEER_STREAM_STARTED.Stream;
        // Allocate memory for the data buffer
        stream_info->recv_buff.buffers = (QUIC_BUFFER *)malloc(sizeof(QUIC_BUFFER));
        if (stream_info->recv_buff.buffers == NULL) {
            // Handle memory allocation failure
            log_error("failed to allocate memory for the recv_buff.buffers array");
            return QUIC_STATUS_OUT_OF_MEMORY;
        }

        stream_info->lock = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
        stream_info->cond = (pthread_cond_t)PTHREAD_COND_INITIALIZER;
        stream_info->recv_buff.buffers->Buffer = NULL;
        stream_info->recv_buff.buffers->Length = 0;
        stream_info->recv_buff.total_buffer_length = 0;
        stream_info->recv_buff.buffer_count = 0;
        stream_info->recv_buff.absolute_offset = 0;
        stream_info->can_send = TRUE;
        ctx_strm_t *ctx_strm = (ctx_strm_t *)malloc(sizeof(ctx_strm_t));
        ctx_strm->connection_info = connection_info;
        ctx_strm->stream_info = stream_info;
        pthread_mutex_lock(&connection_info->lock);
        connection_info->new_stream = stream_info;
        pthread_cond_signal(&connection_info->cond);
        pthread_mutex_unlock(&connection_info->lock);
        ctx->msquic->SetCallbackHandler(event->PEER_STREAM_STARTED.Stream, (void *)stream_callback, ctx_strm);
        log_trace("[strm][%p] peer started", (void *)event->PEER_STREAM_STARTED.Stream);
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
static void server_recv_cb(EV_P_ ev_io *w, int revents);

static void debug_log(const char *line, void *argp) {
    fprintf(stderr, "%s\n", line);
}

static void flush_egress(struct ev_loop *loop, struct conn_io *conn_io) {
    static uint8_t out[MAX_DATAGRAM_SIZE];

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

    double t = quiche_conn_timeout_as_nanos(conn_io->conn) / 1e9f;
    conn_io->timer.repeat = t;
    ev_timer_again(loop, &conn_io->timer);
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
        return false;
    }

    token += addr_len;
    token_len -= addr_len;

    if (*odcid_len < token_len) {
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
        return NULL;
    }

    conn_io->sock = conns->sock;
    conn_io->conn = conn;

    memcpy(&conn_io->peer_addr, peer_addr, peer_addr_len);
    conn_io->peer_addr_len = peer_addr_len;

    ev_init(&conn_io->timer, server_timeout_cb);
    struct timeout_args *timeout_args = malloc(sizeof(struct timeout_args));
    timeout_args->ctx = ctx;
    timeout_args->conn_io = conn_io;
    conn_io->timer.data = timeout_args;

    HASH_ADD(hh, conns->h, cid, LOCAL_CONN_ID_LEN, conn_io);

    log_trace("created connection %p", (void *)conn_io);

    return conn_io;
}

static void server_recv_cb(EV_P_ ev_io *w, int revents) {
    struct conn_io *tmp, *conn_io = NULL;
    struct context *ctx = w->data;
    struct connections *conns = ctx->conns;
    struct conn_io *new_conn_io = conns->new_conn_io;

    static uint8_t buf[65535];
    static uint8_t out[MAX_DATAGRAM_SIZE];

    while (1) {
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

            log_error("failed to read, closing connection: %s", strerror(errno));
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

        int rc = quiche_header_info(buf, read, LOCAL_CONN_ID_LEN, &version,
                                    &type, scid, &scid_len, dcid, &dcid_len,
                                    token, &token_len);
        if (rc < 0) {
            log_error("failed to parse header: %d", rc);
            continue;
        }

        log_trace("Parsed header: version=%u, type=%u, scid_len=%zu, dcid_len=%zu, token_len=%zu",
               version, type, scid_len, dcid_len, token_len);

        HASH_FIND(hh, conns->h, dcid, dcid_len, conn_io);

        if (conn_io == NULL) {
            log_trace("connection not found, creating one");
            if (!quiche_version_is_supported(version)) {
                log_trace("version negotiation");

                ssize_t written = quiche_negotiate_version(scid, scid_len,
                                                           dcid, dcid_len,
                                                           out, sizeof(out));

                if (written < 0) {
                    log_error("failed to create version negotiation packet: %zd", written);
                    continue;
                }

                ssize_t sent = sendto(conns->sock, out, written, 0,
                                      (struct sockaddr *) &peer_addr,
                                      peer_addr_len);
                if (sent != written) {
                    log_error("failed to send");
                    continue;
                }

                log_trace("negotiation packet: sent %zd bytes", sent);
                continue;
            }

            if (token_len == 0) {
                log_trace("stateless retry");

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
                    log_trace("failed to create retry packet: %zd", written);
                    continue;
                }

                ssize_t sent = sendto(conns->sock, out, written, 0,
                                      (struct sockaddr *) &peer_addr,
                                      peer_addr_len);
                if (sent != written) {
                    log_error("failed to send");
                    continue;
                }

                log_trace("retry packet: sent %zd bytes", sent);
                continue;
            }

            if (!validate_token(token, token_len, &peer_addr, peer_addr_len,
                               odcid, &odcid_len)) {
                log_error("invalid address validation token");
                continue;
            }

            conn_io = create_conn(ctx, dcid, dcid_len, odcid, odcid_len,
                                  (struct sockaddr *)&conns->local_addr, conns->local_addr_len,
                                  &peer_addr, peer_addr_len);

            if (conn_io == NULL) {
                continue;
            }

            pthread_mutex_lock(&conns->lock);
            conns->new_conn_io = conn_io;
            pthread_cond_signal(&conns->cond);
            pthread_mutex_unlock(&conns->lock);
        }

        quiche_recv_info recv_info = {
            (struct sockaddr *)&peer_addr,
            peer_addr_len,

            (struct sockaddr *)&conns->local_addr,
            conns->local_addr_len,
        };

        ssize_t done = quiche_conn_recv(conn_io->conn, buf, read, &recv_info);

        if (done < 0) {
            log_error("failed to process packet: %zd", done);
            continue;
        }

        log_trace("connection %p: recv %zd bytes", conn_io, done);

        

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
                    log_trace("stream %p not found", (void *)stream_io);
                    if (strcmp((char *)buf, "open stream") == 0) {
                        stream_io = malloc(sizeof(struct stream_io));
                        if (stream_io == NULL) {
                            log_error("failed to allocate stream IO");
                            return;
                        }
                        stream_io->stream_id = s;
                        stream_io->recv_buf = malloc(sizeof(struct buffer));
                        stream_io->recv_buf->buf = NULL;
                        stream_io->recv_buf->len = 0;
                        stream_io->lock = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
                        stream_io->cond = (pthread_cond_t)PTHREAD_COND_INITIALIZER;
                        HASH_ADD(hh, conn_io->h, stream_id, sizeof(uint64_t), stream_io);
                        pthread_mutex_lock(&conn_io->lock);
                        conn_io->new_stream_io = stream_io;
                        pthread_cond_signal(&conn_io->cond);
                        pthread_mutex_unlock(&conn_io->lock);
                        quiche_conn_stream_send(conn_io->conn, s, (uint8_t *)"stream opened", sizeof("stream opened"), false, &error_code);
                        flush_egress(loop, conn_io);
                    }
                } else {
                    log_trace("stream %p found", (void *)stream_io);
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
    }

    HASH_ITER(hh, conns->h, conn_io, tmp) {
        flush_egress(loop, conn_io);

        if (quiche_conn_is_closed(conn_io->conn)) {
            quiche_stats stats;
            quiche_path_stats path_stats;

            quiche_conn_stats(conn_io->conn, &stats);
            quiche_conn_path_stats(conn_io->conn, 0, &path_stats);

            log_trace("connection %p: was closed, recv=%zu sent=%zu lost=%zu rtt=%" PRIu64 "ns cwnd=%zu delivery_rate=%zu",
                   (void *)conn_io, stats.recv, stats.sent, stats.lost, path_stats.rtt, path_stats.cwnd, path_stats.delivery_rate);

            HASH_DELETE(hh, conns->h, conn_io);

            ev_timer_stop(loop, &conn_io->timer);
            quiche_conn_free(conn_io->conn);
            free(conn_io);
        }
    }
    
}

static void client_recv_cb(EV_P_ ev_io *w, int revents) {
    struct conn_io *conn_io = w->data;

    static uint8_t buf[65535];
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

        quiche_recv_info recv_info = {
            (struct sockaddr *) &peer_addr,
            peer_addr_len,

            (struct sockaddr *) &conn_io->local_addr,
            conn_io->local_addr_len,
        };

        ssize_t done = quiche_conn_recv(conn_io->conn, buf, read, &recv_info);

        if (done < 0) {
            log_error("failed to process packet");
            continue;
        }

        pthread_mutex_lock(&conn_io->lock);
        conn_io->acked = true;
        pthread_cond_signal(&conn_io->cond);
        pthread_mutex_unlock(&conn_io->lock);

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

        log_trace("connection closed, recv=%zu sent=%zu lost=%zu rtt=%" PRIu64 "ns",
               stats.recv, stats.sent, stats.lost, path_stats.rtt);

        HASH_DELETE(hh, conns->h, conn_io);

        ev_timer_stop(loop, &conn_io->timer);
        quiche_conn_free(conn_io->conn);
        free(conn_io);

        return;
    }
}

static void client_timeout_cb(EV_P_ ev_timer *w, int revents) {
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

        log_trace("connection closed, recv=%zu sent=%zu lost=%zu rtt=%" PRIu64 "ns",
               stats.recv, stats.sent, stats.lost, path_stats.rtt);
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

        // quiche_enable_debug_logging(debug_log, NULL);

        quiche_config_set_application_protos(ctx->config,
                                            (uint8_t *)"\x0ahq-interop\x05hq-29\x05hq-28\x05hq-27\x08http/0.9", 38);
        quiche_config_set_max_idle_timeout(ctx->config, 5000);
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

        log_debug("context created: %p", (void *)ctx);
        return (context_t) ctx;
    #elif MSQUIC
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
    ctx->new_connection = NULL;
    ctx->last_new_connection = NULL;
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
    #elif LSQUIC
    printf("Using lsquic\n");
    struct context *ctx = malloc(sizeof(*ctx));
    memset(ctx, 0, sizeof(*ctx));
    const char *val;
    int opt, is_server, version_cleared = 0;
    int packets_out_version = 0;
    socklen_t socklen;
    const char *key_printf_dir = NULL;
    char errbuf[0x100];
    ctx->loop = EV_DEFAULT;

    lsquic_logger_init(&logger_if, stdout, LLTS_HHMMSSUS);
    lsquic_set_log_level("DEBUG");

    if (ctx == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    if (cert_path != NULL && key_path != NULL) {
        ctx->flags = LSENG_SERVER;
        load_cert(ctx, cert_path, key_path);
    }
    else if (cert_path == NULL && key_path == NULL) {
        ctx->flags = 0;
    }
    else {
        fprintf(stderr, "Both cert_path and key_path must be provided\n");
        exit(1);
        
    }

    if (0 != lsquic_global_init(ctx->flags & LSENG_SERVER ? LSQUIC_GLOBAL_SERVER : LSQUIC_GLOBAL_CLIENT))
    {
        exit(EXIT_FAILURE);
    }

    lsquic_engine_init_settings(&ctx->settings, ctx->flags);
    ctx->settings.es_versions = LSQUIC_DF_VERSIONS;
    ctx->settings.es_delay_onclose = 1;

    printf("cert_path: %s\n", cert_path);
    printf("key_path: %s\n", key_path);

    /* Check settings */
    if (0 != lsquic_engine_check_settings(&ctx->settings, ctx->flags, errbuf, sizeof(errbuf)))
    {
        printf("invalid settings: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    /* Initialize callbacks */
    memset(&ctx->eapi, 0, sizeof(ctx->eapi));
    ctx->eapi.ea_packets_out = packets_out_v0;
    ctx->eapi.ea_packets_out_ctx = ctx;
    ctx->eapi.ea_stream_if = &callbacks;
    ctx->eapi.ea_stream_if_ctx = ctx;
    ctx->eapi.ea_get_ssl_ctx = get_ssl_ctx;
    ctx->eapi.ea_settings = &ctx->settings;

    ctx->engine = lsquic_engine_new(ctx->flags, &ctx->eapi);
    if (!ctx->engine)
    {
        printf("cannot create engine\n");
        exit(EXIT_FAILURE);
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

    #elif LSQUIC
    struct context *ctx = (struct context *)context;

    /* Parse IP address and port number */
    if (inet_pton(AF_INET, ip, &ctx->local_addr.sin.sin_addr))
    {
        ctx->local_addr.sin.sin_family = AF_INET;
        ctx->local_addr.sin.sin_port   = htons(port);
    } else {
        perror("inet_pton");
        exit(EXIT_FAILURE);
    }
    
    /* Initialize event loop */
    ctx->sock_fd = socket(ctx->local_addr.sa.sa_family, SOCK_DGRAM, 0);

    /* Set up socket */
    if (ctx->sock_fd < 0)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    if (0 != set_nonblocking(ctx->sock_fd))
    {
        perror("fcntl");
        exit(EXIT_FAILURE);
    }
    if (0 != set_ecn(ctx->sock_fd, &ctx->local_addr.sa))
        exit(EXIT_FAILURE);
    if (ctx->flags & LSENG_SERVER)
        if (0 != set_origdst(ctx->sock_fd, &ctx->local_addr.sa))
            exit(EXIT_FAILURE);

    if (ctx->flags & LSENG_SERVER)
    {
        ssize_t socklen = sizeof(ctx->local_addr);
        if (0 != bind(ctx->sock_fd, &ctx->local_addr.sa, socklen))
        {
            perror("bind");
            exit(EXIT_FAILURE);
        }
        memcpy(&ctx->local_sas, &ctx->local_addr, sizeof(ctx->local_addr));
    }
    printf("Socket created\n");

    ev_io_init(&ctx->sock_w, read_socket, ctx->sock_fd, EV_READ);
    ev_io_start(ctx->loop, &ctx->sock_w);

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

    printf("after\n");
    conn_io->sock = sock;
    conn_io->conn = conn;
    conn_io->lock = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
    conn_io->cond = (pthread_cond_t)PTHREAD_COND_INITIALIZER;
    memcpy(&conn_io->peer_addr, peer->ai_addr, peer->ai_addrlen);
    conn_io->peer_addr_len = peer->ai_addrlen;
    conn_io->h = NULL;
    conn_io->new_stream_io = NULL;
    conn_io->last_stream_io = NULL;

    ctx->loop = ev_default_loop(0);

    ev_io_init(&ctx->watcher, client_recv_cb, sock, EV_READ);
    ev_io_start(ctx->loop, &ctx->watcher);
    ctx->watcher.data = conn_io;

    ev_init(&conn_io->timer, client_timeout_cb);
    struct timeout_args *args = malloc(sizeof(struct timeout_args));
    args->ctx = ctx;
    args->conn_io = conn_io;
    conn_io->timer.data = args;

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
    connection_info->last_new_stream = NULL;
    connection_info->new_stream = NULL;
    connection_info->h = NULL;
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
    if (ctx->last_new_connection == ctx->new_connection)
    {
        log_debug("waiting for connection to be established");
        pthread_cond_wait(&ctx->cond, &ctx->lock);
    }
    ctx->last_new_connection = ctx->new_connection;
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
    #elif LSQUIC
    struct context *ctx = (struct context *)context;
    printf("Opening connection\n");

    ctx->local_addr.sin.sin_family = AF_INET;
    ctx->local_addr.sin.sin_addr.s_addr = htonl(INADDR_ANY);
    ctx->local_addr.sin.sin_port = htons(0);

    ctx->sock_fd = socket(ctx->local_addr.sa.sa_family, SOCK_DGRAM, 0);
    if (ctx->sock_fd < 0)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    if (0 != set_nonblocking(ctx->sock_fd))
    {
        perror("fcntl");
        exit(EXIT_FAILURE);
    }
    if (0 != set_ecn(ctx->sock_fd, &ctx->local_addr.sa))
        exit(EXIT_FAILURE);

    ctx->local_sas.ss_family = ctx->local_addr.sa.sa_family;
    size_t socklen = sizeof(ctx->local_sas);
    if (0 != bind(ctx->sock_fd, (struct sockaddr *) &ctx->local_sas, socklen))
    {
        perror("bind");
        exit(EXIT_FAILURE);
    }
    ev_init(&ctx->timer, timer_expired);

    ev_io_init(&ctx->sock_w, read_socket, ctx->sock_fd, EV_READ);
    ev_io_start(ctx->loop, &ctx->sock_w);

    ctx->timer.data = &ctx;
    ctx->sock_w.data = &ctx;
    /* Parse IP address and port number */
    if (inet_pton(AF_INET, ip, &ctx->peer_addr.sin.sin_addr))
    {
        ctx->peer_addr.sin.sin_family = AF_INET;
        ctx->peer_addr.sin.sin_port   = htons(port);
    }

    printf("Connecting to %s:%d\n", ip, port);

    ctx->c.conn = lsquic_engine_connect(
            ctx->engine, N_LSQVER,
            (struct sockaddr *) &ctx->local_sas, &ctx->peer_addr.sa,
            (void *) ctx,  /* Peer ctx */
            NULL, NULL, 0, NULL, 0, NULL, 0);
    printf("Connection: %p\n", (void *)ctx->c.conn);
    if (!ctx->c.conn)
    {
        printf("cannot create connection\n");
        exit(EXIT_FAILURE);
    }
    printf("Connection created\n");
    process_conns(ctx);
    ev_run(ctx->loop, 0);

    // ctx->engine = lsquic_engine_new(ctx->flags & LSENG_SERVER
    //                                         ? LSENG_SERVER : 0, &eapi);
    // if (!ctx->engine)
    // {
    //     printf("cannot create engine\n");LOG
    //     exit(EXIT_FAILURE);
    // }
    return (connection_t) &ctx->c.conn;
    #endif
}

int close_connection(context_t context, connection_t connection) {
    #ifdef QUICHE
    struct context *ctx = (struct context *)context;
    return 0;
    #elif MSQUIC
    struct context *ctx = (struct context *)context;
    connection_info_t *connection_info = connection;
    ctx->msquic->ConnectionShutdown(connection_info->connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
    #elif LSQUIC
    struct context *ctx = (struct context *)context;
    #endif
}

stream_t open_stream(context_t context, connection_t connection) {
    #ifdef QUICHE
    log_debug("open stream");
    struct context *ctx = (struct context *)context;
    struct conn_io *conn_io = (struct conn_io *)connection;
    struct connections *conns = ctx->conns;
    struct stream_io *stream_io = NULL;

    if (quiche_conn_is_established(conn_io->conn)) {
        const static uint8_t r[] = "open stream";
        uint64_t error_code;

        if (quiche_conn_stream_send(conn_io->conn, 4, r, sizeof(r), false, &error_code) < 0) {
            log_error("failed to send message: %" PRIu64 "", error_code);
            quic_error = QUIC_ERROR_SEND_FAILED;
            return NULL;
        }
        log_debug("open stream message sent");
        flush_egress(ctx->loop, conn_io);

        stream_io = malloc(sizeof(struct stream_io));
        if (stream_io == NULL) {
            log_error("failed to allocate stream IO");
            quic_error = QUIC_ERROR_ALLOCATION_FAILED;
            return NULL;
        }
        stream_io->stream_id = 4;
        stream_io->recv_buf = malloc(sizeof(struct buffer));
        stream_io->recv_buf->buf = NULL;
        stream_io->recv_buf->len = 0;
        stream_io->lock = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
        stream_io->cond = (pthread_cond_t)PTHREAD_COND_INITIALIZER;
        
        log_debug("waiting for new stream");
        pthread_mutex_lock(&conn_io->lock);
        pthread_cond_wait(&conn_io->cond, &conn_io->lock);
        pthread_mutex_unlock(&conn_io->lock);

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
    stream_info->recv_buff.buffers = (QUIC_BUFFER *)malloc(sizeof(QUIC_BUFFER));
    if (stream_info->recv_buff.buffers == NULL) {
        // Handle memory allocation failure
        log_error("failed to allocate memory for stream buffer");
        quic_error = QUIC_ERROR_ALLOCATION_FAILED;
        return NULL;
    }
    stream_info->lock = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
    stream_info->cond = (pthread_cond_t)PTHREAD_COND_INITIALIZER;
    stream_info->recv_buff.buffers->Buffer = NULL;
    stream_info->recv_buff.buffers->Length = 0;
    stream_info->recv_buff.total_buffer_length = 0;
    stream_info->recv_buff.buffer_count = 0;
    stream_info->recv_buff.absolute_offset = 0;
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
    connection_info->last_new_stream = stream_info;
    HASH_ADD(hh, connection_info->h, stream, sizeof(HQUIC), stream_info);
    return (stream_t) stream_info;
    #elif LSQUIC
    struct context *ctx = (struct context *)context;
    printf("Opening stream\n");
    #endif
}

int close_stream(context_t context, connection_t connection, stream_t stream) {
    #ifdef QUICHE
    struct context *ctx = (struct context *)context;
    return 0;
    #elif MSQUIC
    struct context *ctx = (struct context *)context;
    stream_info_t *stream_info = stream;
    connection_info_t *connection_info = connection;
    ctx->msquic->StreamShutdown(stream_info->stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
    #elif LSQUIC
    struct context *ctx = (struct context *)context;
    #endif
}

int send_data(context_t context, connection_t connection, stream_t stream, void* data, int len) {
    #ifdef QUICHE
    log_debug("sending data");
    struct context *ctx = (struct context *)context;
    struct conn_io *conn_io = (struct conn_io *)connection;
    struct stream_io *stream_io = (struct stream_io *)stream;

    if (quiche_conn_is_established(conn_io->conn)) {
        uint64_t error_code;
        pthread_mutex_lock(&conn_io->lock);
        if (quiche_conn_stream_send(conn_io->conn, stream_io->stream_id, data, len, false, &error_code) < 0) {
            log_error("failed to send message: %" PRIu64 "", error_code);
            quic_error = QUIC_ERROR_SEND_FAILED;
            return -1;
        }
        conn_io->acked = false;
        pthread_mutex_unlock(&conn_io->lock);
        flush_egress(ctx->loop, conn_io);
    }

    pthread_mutex_lock(&conn_io->lock);
    if (!conn_io->acked) {
        log_debug("waiting for ack");
        pthread_cond_wait(&conn_io->cond, &conn_io->lock);
    }
    pthread_mutex_unlock(&conn_io->lock);

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
    log_trace("sent %d bytes", len);

    pthread_mutex_lock(&stream_info->lock);
    if (stream_info->can_send == FALSE) {
        log_debug("waiting for data to be sent");
        pthread_cond_wait(&stream_info->cond, &stream_info->lock);
    }
    pthread_mutex_unlock(&stream_info->lock);
    log_debug("sending data done");

    #elif LSQUIC
    struct context *ctx = (struct context *)context;
    #endif
    
}

ssize_t recv_data(context_t context, connection_t connection, stream_t stream, void* buf, ssize_t n_bytes, time_t timeout) {
    #ifdef QUICHE
    struct context *ctx = (struct context *)context;
    struct conn_io *conn_io = (struct conn_io *)connection;
    struct stream_io *stream_io = (struct stream_io *)stream;
    ssize_t to_read = 0;

    log_debug("receiving data");

    if (quiche_conn_is_established(conn_io->conn)) {
        struct stream_io *stream_io_check;
        HASH_FIND(hh, conn_io->h, &stream_io->stream_id, sizeof(stream_io->stream_id), stream_io_check);
        if (stream_io_check == NULL) {
            log_error("stream not found");
            return -1;
        }
        pthread_mutex_lock(&stream_io->lock);
        if (stream_io->recv_buf->len == 0) {
            if (timeout == 0) {    
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
                pthread_mutex_unlock(&stream_info->recv_buff.lock);
                return -1; // Indicate timeout
            }
        }
    }

    // Calculate the amount of data to read
    ssize_t to_read = stream_info->recv_buff.total_buffer_length;
    if (to_read > n_bytes) {
        to_read = n_bytes;
    } else if (to_read == 0) {
        log_debug("no data available");
        pthread_mutex_unlock(&stream_info->recv_buff.lock);
        return 0; // No data available
    }

    // Copy data to the buffer
    size_t copied = 0;
    while (copied < to_read) {
        if (stream_info->recv_buff.buffer_count == 0) {
            log_debug("no data available");
            break;
        }

        QUIC_BUFFER *current_buffer = &stream_info->recv_buff.buffers[0];
        size_t copy_size = current_buffer->Length < (to_read - copied) ? current_buffer->Length : (to_read - copied);
        memcpy((uint8_t *)buf + copied, current_buffer->Buffer, copy_size);
        copied += copy_size;

        // Update the buffer state
        if (copy_size < current_buffer->Length) {
            // There is still data left in the current buffer
            memmove(current_buffer->Buffer, current_buffer->Buffer + copy_size, current_buffer->Length - copy_size);
            current_buffer->Length -= copy_size;
        } else {
            // Remove the current buffer
            free(current_buffer->Buffer);
            memmove(stream_info->recv_buff.buffers, stream_info->recv_buff.buffers + 1, (stream_info->recv_buff.buffer_count - 1) * sizeof(QUIC_BUFFER));
            stream_info->recv_buff.buffer_count--;
        }
    }

    stream_info->recv_buff.total_buffer_length -= to_read;
    pthread_mutex_unlock(&stream_info->lock);
    return to_read;
    #elif LSQUIC
    struct context *ctx = (struct context *)context;
    #endif
}

int set_listen(context_t context) {
    #ifdef QUICHE
    struct context *ctx = (struct context *)context;

    ctx->loop = ev_default_loop(0);

    ev_io_init(&ctx->watcher, server_recv_cb, ctx->conns->sock, EV_READ);
    ev_io_start(ctx->loop, &ctx->watcher);
    ctx->watcher.data = ctx;

    // Create a new thread for the event loop
    pthread_t thread_id;
    if (pthread_create(&thread_id, NULL, event_loop_thread, ctx) != 0) {
        log_error("failed to create event loop thread");
        return -1;
    }

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
    #elif LSQUIC
    struct context *ctx = (struct context *)context;
    #endif
}

connection_t accept_connection(context_t context, time_t timeout) {
    #ifdef QUICHE
    struct context *ctx = (struct context *)context;
    log_debug("accepting connection");

    struct conn_io *conn_io = NULL;

    pthread_mutex_lock(&ctx->conns->lock);
    if (ctx->conns->last_conn_io == ctx->conns->new_conn_io)
    {
        pthread_cond_wait(&ctx->conns->cond, &ctx->conns->lock);
        ctx->conns->last_conn_io = ctx->conns->new_conn_io;
        conn_io = ctx->conns->new_conn_io;    
    }
    pthread_mutex_unlock(&ctx->conns->lock);

    log_debug("new connnetion: %p", (void *)conn_io);

    while (!quiche_conn_is_established(conn_io->conn))
    {
        if (quiche_conn_is_closed(conn_io->conn))
        {
            log_error("connection closed");
            return NULL;
        }
    }

    log_debug("new connection accepted");

    return (connection_t) conn_io;

    #elif MSQUIC
    log_debug("accepting connection");
    struct context *ctx = (struct context *)context;
    connection_info_t *connection_info; 

    // Lock the mutex to wait for a connection
    pthread_mutex_lock(&ctx->lock);
    if (ctx->new_connection == ctx->last_new_connection)
    {
        if (timeout == 0)
        {
            // Wait indefinitely
            pthread_cond_wait(&ctx->cond, &ctx->lock);
        }
        else
        {
            // Wait with a timeout (convert time_t to timespec)
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += timeout;
            pthread_cond_timedwait(&ctx->cond, &ctx->lock, &ts);
        }
    }
    connection_info = ctx->new_connection;
    // Unlock the mutex
    pthread_mutex_unlock(&ctx->lock);

    ctx->last_new_connection = connection_info;

    HASH_ADD(hh, ctx->h, connection, sizeof(HQUIC), connection_info);

    log_debug("new connection accepted");
    return (connection_t)connection_info;
    #elif LSQUIC
    printf("accept_connection\n");
    struct context *ctx = (struct context *)context;
    process_conns(ctx);
    ev_run(ctx->loop, 0);
    return (connection_t) &ctx->c.conn;
    #endif
}

stream_t accept_stream(context_t context, connection_t connection, time_t timeout) {
    #ifdef QUICHE
    struct context *ctx = (struct context *)context;
    struct conn_io *conn_io = (struct conn_io *)connection;
    struct stream_io *stream_io = NULL;

    log_debug("accepting stream");
    pthread_mutex_lock(&conn_io->lock);
    if (conn_io->last_stream_io == conn_io->new_stream_io)
    {
        log_debug("waiting for new stream");
        pthread_cond_wait(&conn_io->cond, &conn_io->lock);
    }
    conn_io->last_stream_io = conn_io->new_stream_io;
    stream_io = conn_io->new_stream_io;
    pthread_mutex_unlock(&conn_io->lock);

    log_debug("new stream accepted");

    return (stream_t) stream_io;
    #elif MSQUIC
    log_debug("accepting stream");
    struct context *ctx = (struct context *)context;
    connection_info_t *connection_info = connection;
    stream_info_t *stream_info;
    
    // Lock the mutex to wait for a connection
    pthread_mutex_lock(&connection_info->lock);
    if (connection_info->new_stream == connection_info->last_new_stream)
    {
        if (timeout == 0)
        {
            // Wait indefinitely
            pthread_cond_wait(&connection_info->cond, &connection_info->lock);
        }
        else
        {
            // Wait with a timeout (convert time_t to timespec)
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += timeout;
            pthread_cond_timedwait(&connection_info->cond, &connection_info->lock, &ts);
        }
    }
    stream_info = connection_info->new_stream;
    // Unlock the mutex
    pthread_mutex_unlock(&connection_info->lock);
    connection_info->last_new_stream = stream_info;
    char* data = "STREAM HSK";
    send_data(context, (connection_t)connection, (stream_t)stream_info, data, 11);
    HASH_ADD(hh, connection_info->h, stream, sizeof(HQUIC), stream_info);
    log_debug("new stream accepted");
    return (stream_t)connection_info->new_stream;
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