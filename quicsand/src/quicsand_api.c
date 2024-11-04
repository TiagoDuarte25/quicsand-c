#include "quicsand_api.h"
#include <errno.h>

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
};

struct context
{
    struct connections *conns;
    struct ev_loop *loop;
    struct ev_io watcher;
    char *hostname;
    quiche_config *config;
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
    struct Buffer
    {
        QUIC_BUFFER *buffers;
        uint64_t total_buffer_length;
        uint32_t buffer_count;
        uint64_t absolute_offset;
        pthread_mutex_t lock;
        pthread_cond_t cond;
    } recv_buff;
} stream_info_t;

typedef struct stream_node{
    stream_info_t *stream_info;
    struct stream_node *prev;
    struct stream_node *next;
} stream_node_t;

typedef struct {
    HQUIC connection;
    stream_node_t *streams;
    stream_node_t *last_new_stream;
    stream_node_t *new_stream;
    size_t stream_count;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int connected;
    int last_receive_count;
    int receive_count;
} connection_info_t;

typedef struct connection_node { 
    connection_info_t *connection_info;
    struct connection_node *prev;
    struct connection_node *next;
} connection_node_t;

typedef struct {
    struct context *ctx;
    connection_node_t *connection_node;
} ctx_conn_t;

typedef struct {
    struct context *ctx;
    connection_node_t *connection_node;
    stream_node_t *stream_node;
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

    connection_node_t *connections;
    size_t connection_count;
    connection_node_t * last_new_connection;
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

/*
    auxillary functions
*/
#elif MSQUIC

//print every connections and streams in the context
int print_context(context_t context) {
    // struct context *ctx = (struct context *)context;
    // connection_node_t *current_conn = ctx->connections;
    // while (current_conn->next != NULL) {
    //     connection_info_t *connection_info = current_conn->connection_info;
    //     printf("Connection: %p\n", (void *)connection_info->connection);
    //     stream_node_t *current_strm = connection_info->streams;
    //     while (current_strm->next != NULL) {
    //         stream_info_t *stream_info = current_strm->stream_info;
    //         printf("Stream: %p\n", (void *)stream_info->stream);
    //         current_strm = current_strm->next;
    //     }
    //     current_conn = current_conn->next;
    // }
    if (context == NULL) {
        errno = EINVAL;
        return -1;
    } else {
        errno = 0;
        return 0;
    }
}

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

void remove_connection(connection_node_t *head, connection_node_t *node) {
    connection_node_t *current = head;
    while (current->next != node) {
        current = current->next;
    }
    current->next = node->next;
    free(node);
}

void remove_stream(stream_node_t *head, stream_node_t *node) {
    stream_node_t *current = head;
    while (current->next != node) {
        current = current->next;
    }
    current->next = node->next;
    free(node);
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
    connection_node_t *connection_node = ctx_strm->connection_node;
    connection_info_t *connection_info = connection_node->connection_info;
    stream_node_t *stream_node = ctx_strm->stream_node;
    stream_info_t *stream_info = stream_node->stream_info;
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
        printf("[strm][%p] Data received\n", (void *)stream);
        pthread_mutex_lock(&stream_info->recv_buff.lock);
        // Reallocate memory for the recv_buff.buffers array to accommodate the new buffer
        stream_info->recv_buff.buffers = (QUIC_BUFFER *)realloc(
            stream_info->recv_buff.buffers,
            (stream_info->recv_buff.buffer_count + 1) * sizeof(QUIC_BUFFER)
        );
        if (stream_info->recv_buff.buffers == NULL) {
            // Handle memory allocation failure
            pthread_mutex_unlock(&stream_info->recv_buff.lock);
            exit(1);
        }

        // Allocate memory for the new buffer and copy the received data into it
        QUIC_BUFFER *new_buffer = &stream_info->recv_buff.buffers[stream_info->recv_buff.buffer_count];
        new_buffer->Buffer = (uint8_t *)malloc(event->RECEIVE.TotalBufferLength);
        if (new_buffer->Buffer == NULL) {
            // Handle memory allocation failure
            pthread_mutex_unlock(&stream_info->recv_buff.lock);
            exit(1);
        }
        memcpy(new_buffer->Buffer, event->RECEIVE.Buffers->Buffer, event->RECEIVE.TotalBufferLength);
        new_buffer->Length = event->RECEIVE.TotalBufferLength;
        // Update the metadata fields
        stream_info->recv_buff.total_buffer_length += event->RECEIVE.TotalBufferLength;
        stream_info->recv_buff.buffer_count++;
        stream_info->recv_buff.absolute_offset = event->RECEIVE.AbsoluteOffset;
        connection_info->receive_count++;

        pthread_cond_signal(&stream_info->recv_buff.cond);
        pthread_mutex_unlock(&stream_info->recv_buff.lock);
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
        remove_stream(connection_info->streams, stream_node);
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
    connection_node_t *connection_node = ctx_conn->connection_node;
    connection_info_t *connection_info = connection_node->connection_info;
    switch (event->Type)
    {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        //
        // The handshake has completed for the connection.
        //
        pthread_mutex_lock(&ctx->lock);
        connection_info->connection = connection;
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
        remove_connection(ctx->connections, connection_node);
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
        // Allocate memory for the data buffer
        stream_info->recv_buff.buffers = (QUIC_BUFFER *)malloc(sizeof(QUIC_BUFFER));
        if (stream_info->recv_buff.buffers == NULL) {
            // Handle memory allocation failure
            fprintf(stderr, "Memory allocation failed\n");
            exit(1);
        }

        stream_info->recv_buff.lock = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
        stream_info->recv_buff.cond = (pthread_cond_t)PTHREAD_COND_INITIALIZER;
        stream_info->recv_buff.buffers->Buffer = NULL;
        stream_info->recv_buff.buffers->Length = 0;
        stream_info->recv_buff.total_buffer_length = 0;
        stream_info->recv_buff.buffer_count = 0;
        stream_info->recv_buff.absolute_offset = 0;
        stream_node_t *stream_node = push_stream(connection_info->streams, stream_info);
        connection_info->new_stream = stream_node;
        ctx_strm_t *ctx_strm = (ctx_strm_t *)malloc(sizeof(ctx_strm_t));
        ctx_strm->ctx = ctx;
        ctx_strm->connection_node = connection_node;
        ctx_strm->stream_node = stream_node;
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

        // pointers allocation
        ctx_conn_t *ctx_conn = (ctx_conn_t *)malloc(sizeof(ctx_conn_t));
        connection_info_t *connection_info = (connection_info_t *)malloc(sizeof(connection_info_t));
        connection_info->streams = (stream_node_t *)malloc(sizeof(stream_node_t));
        connection_info->streams->prev = NULL;
        connection_info->streams->next = NULL;
        connection_info->stream_count = 0;
        connection_info->lock = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
        connection_info->cond = (pthread_cond_t)PTHREAD_COND_INITIALIZER;

        // set the callback handler
        connection_node_t *connection_node = push_connection(ctx->connections, connection_info);
        ctx_conn->connection_node = connection_node;
        ctx_conn->ctx = ctx;
        ctx->msquic->SetCallbackHandler(event->NEW_CONNECTION.Connection, (void *)connection_callback, ctx_conn);
        status = ctx->msquic->ConnectionSetConfiguration(event->NEW_CONNECTION.Connection, ctx->configuration);

        printf("[list][%p] New Connection\n", (void *)listener);
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
        ssize_t written = quiche_conn_send(conn_io->conn, out, sizeof(out),
                                           &send_info);

        if (written == QUICHE_ERR_DONE) {
            fprintf(stderr, "done writing\n");
            break;
        }

        if (written < 0) {
            fprintf(stderr, "failed to create packet: %zd\n", written);
            return;
        }

        ssize_t sent = sendto(conn_io->sock, out, written, 0,
                              (struct sockaddr *) &send_info.to,
                              send_info.to_len);

        if (sent != written) {
            perror("failed to send");
            return;
        }

        fprintf(stderr, "sent %zd bytes\n", sent);
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
        perror("failed to open /dev/urandom");
        return NULL;
    }

    ssize_t rand_len = read(rng, cid, cid_len);
    if (rand_len < 0) {
        perror("failed to create connection ID");
        return NULL;
    }

    return cid;
}

static struct conn_io *create_conn(struct connections *conns, uint8_t *scid, size_t scid_len,
                                   uint8_t *odcid, size_t odcid_len,
                                   struct sockaddr *local_addr,
                                   socklen_t local_addr_len,
                                   struct sockaddr_storage *peer_addr,
                                   socklen_t peer_addr_len)
{
    struct conn_io *conn_io = malloc(sizeof(struct conn_io));
    if (conn_io == NULL) {
        fprintf(stderr, "failed to allocate connection IO\n");
        return NULL;
    }

    if (scid_len != LOCAL_CONN_ID_LEN) {
        fprintf(stderr, "failed, scid length too short\n");
    }

    memcpy(conn_io->cid, scid, LOCAL_CONN_ID_LEN);

    printf("local_addr_len: %zu\n", local_addr_len);
    printf("peer_addr_len: %zu\n", peer_addr_len);

    quiche_conn *conn = quiche_accept(conn_io->cid, LOCAL_CONN_ID_LEN,
                                      odcid, odcid_len,
                                      local_addr,
                                      local_addr_len,
                                      (struct sockaddr *) peer_addr,
                                      peer_addr_len,
                                      conns->config);

    printf("conn: %p\n", (void *)conn);

    if (conn == NULL) {
        fprintf(stderr, "failed to create connection\n");
        return NULL;
    }

    printf("created connection\n");

    conn_io->sock = conns->sock;
    printf("sock: %d\n", conn_io->sock);
    conn_io->conn = conn;
    printf("conn: %p\n", (void *)conn);

    memcpy(&conn_io->peer_addr, peer_addr, peer_addr_len);
    conn_io->peer_addr_len = peer_addr_len;
    printf("peer_addr_len: %zu\n", conn_io->peer_addr_len);

    ev_init(&conn_io->timer, server_timeout_cb);
    conn_io->timer.data = conn_io;
    printf("timer data: %p\n", (void *)conn_io);

    HASH_ADD(hh, conns->h, cid, LOCAL_CONN_ID_LEN, conn_io);

    printf("added connection to hash\n");

    fprintf(stderr, "new connection\n");

    return conn_io;
}

static void server_recv_cb(EV_P_ ev_io *w, int revents) {
    printf("server recv\n");
    struct conn_io *tmp, *conn_io = NULL;
    struct connections *conns = w->data;

    static uint8_t buf[65535];
    static uint8_t out[MAX_DATAGRAM_SIZE];

    while (1) {
        struct sockaddr_storage peer_addr;
        socklen_t peer_addr_len = sizeof(peer_addr);
        memset(&peer_addr, 0, peer_addr_len);

        printf("Waiting to receive data...\n");
        ssize_t read = recvfrom(conns->sock, buf, sizeof(buf), 0,
                                (struct sockaddr *) &peer_addr,
                                &peer_addr_len);

        if (read < 0) {
            if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
                fprintf(stderr, "recv would block\n");
                break;
            }

            perror("failed to read");
            return;
        }

        printf("Received %zd bytes\n", read);

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
            fprintf(stderr, "failed to parse header: %d\n", rc);
            continue;
        }

        printf("Parsed header: version=%u, type=%u, scid_len=%zu, dcid_len=%zu, token_len=%zu\n",
               version, type, scid_len, dcid_len, token_len);

        HASH_FIND(hh, conns->h, dcid, dcid_len, conn_io);

        if (conn_io == NULL) {
            printf("Connection not found, creating new connection\n");

            if (!quiche_version_is_supported(version)) {
                fprintf(stderr, "version negotiation\n");

                ssize_t written = quiche_negotiate_version(scid, scid_len,
                                                           dcid, dcid_len,
                                                           out, sizeof(out));

                if (written < 0) {
                    fprintf(stderr, "failed to create vneg packet: %zd\n",
                            written);
                    continue;
                }

                ssize_t sent = sendto(conns->sock, out, written, 0,
                                      (struct sockaddr *) &peer_addr,
                                      peer_addr_len);
                if (sent != written) {
                    perror("failed to send");
                    continue;
                }

                fprintf(stderr, "sent %zd bytes\n", sent);
                continue;
            }

            if (token_len == 0) {
                fprintf(stderr, "stateless retry\n");

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
                    fprintf(stderr, "failed to create retry packet: %zd\n",
                            written);
                    continue;
                }

                ssize_t sent = sendto(conns->sock, out, written, 0,
                                      (struct sockaddr *) &peer_addr,
                                      peer_addr_len);
                if (sent != written) {
                    perror("failed to send");
                    continue;
                }

                fprintf(stderr, "sent %zd bytes\n", sent);
                continue;
            }

            if (!validate_token(token, token_len, &peer_addr, peer_addr_len,
                               odcid, &odcid_len)) {
                fprintf(stderr, "invalid address validation token\n");
                continue;
            }

            conn_io = create_conn(conns, dcid, dcid_len, odcid, odcid_len,
                                  (struct sockaddr *)&conns->local_addr, conns->local_addr_len,
                                  &peer_addr, peer_addr_len);

            if (conn_io == NULL) {
                continue;
            }
        }

        printf("Processing received data\n");

        quiche_recv_info recv_info = {
            (struct sockaddr *)&peer_addr,
            peer_addr_len,

            (struct sockaddr *)&conns->local_addr,
            conns->local_addr_len,
        };

        ssize_t done = quiche_conn_recv(conn_io->conn, buf, read, &recv_info);

        if (done < 0) {
            fprintf(stderr, "failed to process packet: %zd\n", done);
            continue;
        }

        fprintf(stderr, "recv %zd bytes\n", done);

        if (quiche_conn_is_established(conn_io->conn)) {
            uint64_t s = 0;

            quiche_stream_iter *readable = quiche_conn_readable(conn_io->conn);

            while (quiche_stream_iter_next(readable, &s)) {
                fprintf(stderr, "stream %" PRIu64 " is readable\n", s);

                bool fin = false;
                uint64_t error_code;
                ssize_t recv_len = quiche_conn_stream_recv(conn_io->conn, s,
                                                           buf, sizeof(buf),
                                                           &fin, &error_code);
                if (recv_len < 0) {
                    break;
                }

                if (fin) {
                    static const char *resp = "byez\n";
                    uint64_t error_code;
                    quiche_conn_stream_send(conn_io->conn, s, (uint8_t *) resp,
                                            5, true, &error_code);
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

            fprintf(stderr, "connection closed, recv=%zu sent=%zu lost=%zu rtt=%" PRIu64 "ns cwnd=%zu\n",
                    stats.recv, stats.sent, stats.lost, path_stats.rtt, path_stats.cwnd);

            HASH_DELETE(hh, conns->h, conn_io);

            ev_timer_stop(loop, &conn_io->timer);
            quiche_conn_free(conn_io->conn);
            free(conn_io);
        }
    }
}

static void client_recv_cb(EV_P_ ev_io *w, int revents) {
    static bool req_sent = false;

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
                fprintf(stderr, "recv would block\n");
                break;
            }

            perror("failed to read");
            return;
        }

        fprintf(stderr, "received %zd bytes\n", read);

        quiche_recv_info recv_info = {
            (struct sockaddr *) &peer_addr,
            peer_addr_len,

            (struct sockaddr *) &conn_io->local_addr,
            conn_io->local_addr_len,
        };

        ssize_t done = quiche_conn_recv(conn_io->conn, buf, read, &recv_info);

        if (done < 0) {
            fprintf(stderr, "failed to process packet\n");
            continue;
        }

        fprintf(stderr, "recv %zd bytes\n", done);
    }

    fprintf(stderr, "done reading\n");

    if (quiche_conn_is_closed(conn_io->conn)) {
        fprintf(stderr, "connection closed\n");

        ev_break(EV_A_ EVBREAK_ONE);
        return;
    }

    if (quiche_conn_is_established(conn_io->conn) && !req_sent) {
        const uint8_t *app_proto;
        size_t app_proto_len;

        quiche_conn_application_proto(conn_io->conn, &app_proto, &app_proto_len);

        fprintf(stderr, "connection established: %.*s\n",
                (int) app_proto_len, app_proto);

        const static uint8_t r[] = "GET /index.html\r\n";
        uint64_t error_code;
        if (quiche_conn_stream_send(conn_io->conn, 4, r, sizeof(r), true, &error_code) < 0) {
            fprintf(stderr, "failed to send HTTP request: %" PRIu64 "\n", error_code);
            return;
        }

        fprintf(stderr, "sent HTTP request\n");

        req_sent = true;
    }

    if (quiche_conn_is_established(conn_io->conn)) {
        uint64_t s = 0;

        quiche_stream_iter *readable = quiche_conn_readable(conn_io->conn);

        while (quiche_stream_iter_next(readable, &s)) {
            fprintf(stderr, "stream %" PRIu64 " is readable\n", s);

            bool fin = false;
            uint64_t error_code;
            ssize_t recv_len = quiche_conn_stream_recv(conn_io->conn, s,
                                                       buf, sizeof(buf),
                                                       &fin, &error_code);
            if (recv_len < 0) {
                break;
            }

            printf("%.*s", (int) recv_len, buf);

            if (fin) {
                if (quiche_conn_close(conn_io->conn, true, 0, NULL, 0) < 0) {
                    fprintf(stderr, "failed to close connection\n");
                }
            }
        }

        quiche_stream_iter_free(readable);
    }

    flush_egress(loop, conn_io);
}

static void server_timeout_cb(EV_P_ ev_timer *w, int revents) {
    struct conn_io *conn_io = w->data;
    quiche_conn_on_timeout(conn_io->conn);

    fprintf(stderr, "timeout\n");

    flush_egress(loop, conn_io);

    if (quiche_conn_is_closed(conn_io->conn)) {
        quiche_stats stats;
        quiche_path_stats path_stats;

        quiche_conn_stats(conn_io->conn, &stats);
        quiche_conn_path_stats(conn_io->conn, 0, &path_stats);

        fprintf(stderr, "connection closed, recv=%zu sent=%zu lost=%zu rtt=%" PRIu64 "ns cwnd=%zu\n",
                stats.recv, stats.sent, stats.lost, path_stats.rtt, path_stats.cwnd);

        //HASH_DELETE(hh, conns->h, conn_io);

        ev_timer_stop(loop, &conn_io->timer);
        quiche_conn_free(conn_io->conn);
        free(conn_io);

        return;
    }
}

static void client_timeout_cb(EV_P_ ev_timer *w, int revents) {
    struct conn_io *conn_io = w->data;
    quiche_conn_on_timeout(conn_io->conn);

    fprintf(stderr, "timeout\n");

    flush_egress(loop, conn_io);

    if (quiche_conn_is_closed(conn_io->conn)) {
        quiche_stats stats;
        quiche_path_stats path_stats;

        quiche_conn_stats(conn_io->conn, &stats);
        quiche_conn_path_stats(conn_io->conn, 0, &path_stats);

        fprintf(stderr, "connection closed, recv=%zu sent=%zu lost=%zu rtt=%" PRIu64 "ns\n",
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

        printf("Using quiche\n");

        struct context *ctx = (struct context *)malloc(sizeof(struct context));

        ctx->config = quiche_config_new(QUICHE_PROTOCOL_VERSION);
        if (ctx->config == NULL)
        {
            fprintf(stderr, "failed to create config\n");
            exit(EXIT_FAILURE);
        }

        if(cert_path && key_path) {
            quiche_config_load_cert_chain_from_pem_file(ctx->config, cert_path);
            quiche_config_load_priv_key_from_pem_file(ctx->config, key_path);
        } else {
            quiche_config_verify_peer(ctx->config, false);
        }

        quiche_enable_debug_logging(debug_log, NULL);

        quiche_config_set_application_protos(ctx->config,
                                            (uint8_t *)"\x0ahq-interop\x05hq-29\x05hq-28\x05hq-27\x08http/0.9", 38);
        // quiche_config_set_application_protos(ctx->config, (uint8_t *)("example-proto"), 12);
        quiche_config_set_max_idle_timeout(ctx->config, 5000);
        quiche_config_set_max_recv_udp_payload_size(ctx->config, MAX_DATAGRAM_SIZE);
        quiche_config_set_max_send_udp_payload_size(ctx->config, MAX_DATAGRAM_SIZE);
        quiche_config_set_initial_max_data(ctx->config, 10000000);
        quiche_config_set_initial_max_stream_data_bidi_local(ctx->config, 1000000);
        quiche_config_set_initial_max_stream_data_uni(ctx->config, 1000000);
        quiche_config_set_initial_max_streams_bidi(ctx->config, 100);
        quiche_config_set_initial_max_streams_uni(ctx->config, 100);
        quiche_config_set_disable_active_migration(ctx->config, true);

        ctx->conns = (struct connections *)malloc(sizeof(struct connections));
        if (ctx->conns == NULL)
        {
            fprintf(stderr, "failed to allocate connections\n");
            exit(EXIT_FAILURE);
        }
        ctx->conns->config = ctx->config;
        
        return (context_t) ctx;

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

    //
    // Configures the idle timeout.
    //
    QUIC_SETTINGS settings = {0};
    settings.IdleTimeoutMs = ctx->idle_timeout_ms;
    settings.IsSet.IdleTimeoutMs = TRUE;

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
        fprintf(stderr, "cert_path: %s\n", cert_path);
        fprintf(stderr, "key_path: %s\n", key_path);
        cred_config.CertificateFile = &CertFile;
    }

    ctx->connections = (connection_node_t *)malloc(sizeof(connection_node_t));
    ctx->connections->connection_info = NULL;
    ctx->connections->prev = NULL;
    ctx->connections->next = NULL;
    ctx->connection_count = 0;
    ctx->new_connection = NULL;
    ctx->last_new_connection = NULL;
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

void bind_addr(context_t context, char* ip, int port) {
    fprintf(stderr, "Binding to %s:%d\n", ip, port);
    #ifdef QUICHE

    struct context *ctx = (struct context *)context;


    // struct sockaddr_in local_addr;
    // if (inet_pton(AF_INET, ip, &local_addr.sin_addr))
    // {
    //     local_addr.sin_family = AF_INET;
    //     local_addr.sin_port   = htons(port);
    // }

    // memcpy(&ctx->conns->local_addr, &local_addr, sizeof(local_addr));
    // ctx->conns->local_addr_len = sizeof(local_addr);
    // ctx->hostname = "quicsandserver";
    // ctx->conns->local_addr->sa_family = PF_UNSPEC;
    const struct addrinfo hints = {
        .ai_family = PF_UNSPEC,
        .ai_socktype = SOCK_DGRAM,
        .ai_protocol = IPPROTO_UDP
    };

    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%d", port);
    struct addrinfo *local;
    if (getaddrinfo(ip, port_str, &hints, &local) != 0) {
        perror("failed to resolve host");
        exit(EXIT_FAILURE);
    }

    if ((ctx->conns->sock = socket(local->ai_family, SOCK_DGRAM, 0)) < 0)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    if (fcntl(ctx->conns->sock, F_SETFL, O_NONBLOCK) != 0)
    {
        perror("fcntl");
        exit(EXIT_FAILURE);
    }

    if (bind(ctx->conns->sock, local->ai_addr, local->ai_addrlen) < 0)
    {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    memcpy(&ctx->conns->local_addr, local->ai_addr, local->ai_addrlen);
    ctx->conns->local_addr_len = local->ai_addrlen;

    //print binded address
    char host[NI_MAXHOST];
    char service[NI_MAXSERV];
    if (getnameinfo(local->ai_addr, local->ai_addrlen, host, NI_MAXHOST, service, NI_MAXSERV, 0) == 0)
    {
        fprintf(stderr, "bound to %s:%s\n", host, service);
    }
    else
    {
        perror("getnameinfo");
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

    printf("Opening connection\n");

    char *host = "quicsand-api-server"; 

    struct addrinfo *peer = NULL;
    struct sockaddr_in addr4;

    printf("bind ip address\n");
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
    printf("bounded\n");

    int sock = socket(peer->ai_family, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("failed to create socket");
        return NULL;
    }

    if (fcntl(sock, F_SETFL, O_NONBLOCK) != 0) {
        perror("failed to make socket non-blocking");
        return NULL;
    }
    printf("socket created\n");

    ctx->conns->h = (struct conn_io *)malloc(sizeof(struct conn_io));
    if (ctx->conns->h == NULL)
    {
        fprintf(stderr, "failed to allocate connection IO\n");
        exit(EXIT_FAILURE);
    }

    printf("scid\n");

    uint8_t scid[LOCAL_CONN_ID_LEN];
    int rng = open("/dev/urandom", O_RDONLY);
    if (rng < 0) {
        perror("failed to open /dev/urandom");
        return NULL;
    }

    ssize_t rand_len = read(rng, &scid, sizeof(scid));
    if (rand_len < 0) {
        perror("failed to create connection ID");
        return NULL;
    }

    printf("created\n");

    ctx->conns->local_addr_len = sizeof(ctx->conns->local_addr);
    if (getsockname(sock, (struct sockaddr *)&ctx->conns->local_addr,
                    &ctx->conns->local_addr_len) != 0)
    {
        perror("failed to get local address of socket");
        return NULL;
    };

    memcpy(&ctx->conns->h->local_addr, &ctx->conns->local_addr, ctx->conns->local_addr_len);
    ctx->conns->h->local_addr_len = ctx->conns->local_addr_len;

    quiche_conn *conn = quiche_connect(host, (const uint8_t *) scid, sizeof(scid),
                                       (struct sockaddr *) &ctx->conns->local_addr,
                                       ctx->conns->local_addr_len,
                                       peer->ai_addr, peer->ai_addrlen, ctx->config);

    if (conn == NULL) {
        fprintf(stderr, "failed to create connection\n");
        return NULL;
    }

    printf("after\n");
    ctx->conns->h->sock = sock;
    ctx->conns->h->conn = conn;

    ctx->loop = ev_default_loop(0);

    ev_io_init(&ctx->watcher, client_recv_cb, sock, EV_READ);
    ev_io_start(ctx->loop, &ctx->watcher);
    ctx->watcher.data = ctx->conns->h;

    ev_init(&ctx->conns->h->timer, client_timeout_cb);
    ctx->conns->h->timer.data = ctx->conns->h;

    flush_egress(ctx->loop, ctx->conns->h);

    // Create a new thread for the event loop
    pthread_t thread_id;
    if (pthread_create(&thread_id, NULL, event_loop_thread, ctx) != 0) {
        perror("failed to create thread");
        return NULL;
    }

    return (connection_t) ctx->conns->h;
    #elif MSQUIC
    struct context *ctx = (struct context *)context;
    QUIC_STATUS status;

    connection_info_t *connection_info = (connection_info_t *)malloc(sizeof(connection_info_t));
    connection_info->connected = 0;
    connection_info->streams = (stream_node_t *)malloc(sizeof(stream_node_t));
    connection_info->streams->stream_info = NULL;
    connection_info->streams->prev = NULL;
    connection_info->streams->next = NULL;
    connection_info->stream_count = 0;
    connection_info->last_new_stream = NULL;
    connection_info->new_stream = NULL;
    connection_info->last_receive_count = 0;
    connection_info->receive_count = 0;
    connection_info->lock = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
    connection_info->cond = (pthread_cond_t)PTHREAD_COND_INITIALIZER;

    connection_node_t *connection_node = push_connection(ctx->connections, connection_info);
    ctx_conn_t *ctx_conn = (ctx_conn_t *)malloc(sizeof(ctx_conn_t));
    ctx_conn->ctx = ctx;
    ctx_conn->connection_node = connection_node;
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
    if (ctx->last_new_connection == ctx->new_connection)
    {
        printf("Waiting for connection: %p\n", (void *)ctx);
        pthread_cond_wait(&ctx->cond, &ctx->lock);
    }

    ctx->last_new_connection = ctx->new_connection;
    pthread_mutex_unlock(&ctx->lock);
    return (connection_t) ctx->new_connection;
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

void close_connection(context_t context, connection_t connection) {
    #ifdef QUICHE
    struct context *ctx = (struct context *)context;
    #elif MSQUIC
    struct context *ctx = (struct context *)context;
    connection_node_t *connection_node = (connection_node_t *)connection;
    connection_info_t *connection_info = connection_node->connection_info;
    ctx->msquic->ConnectionShutdown(connection_info->connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
    #elif LSQUIC
    struct context *ctx = (struct context *)context;
    #endif
}

stream_t open_stream(context_t context, connection_t connection) {
    #ifdef QUICHE
    struct context *ctx = (struct context *)context;
    getchar();
    #elif MSQUIC
    printf("Opening stream\n");
    struct context *ctx = (struct context *)context;
    HQUIC stream;
    connection_node_t *connection_node = (connection_node_t *)connection;
    connection_info_t *connection_info = connection_node->connection_info;
    stream_info_t *stream_info = (stream_info_t *)malloc(sizeof(stream_info_t));
    stream_info->established = 0;

    // Allocate memory for the data buffer
    stream_info->recv_buff.buffers = (QUIC_BUFFER *)malloc(sizeof(QUIC_BUFFER));
    if (stream_info->recv_buff.buffers == NULL) {
        // Handle memory allocation failure
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    stream_info->recv_buff.lock = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
    stream_info->recv_buff.cond = (pthread_cond_t)PTHREAD_COND_INITIALIZER;
    stream_info->recv_buff.buffers->Buffer = NULL;
    stream_info->recv_buff.buffers->Length = 0;
    stream_info->recv_buff.total_buffer_length = 0;
    stream_info->recv_buff.buffer_count = 0;
    stream_info->recv_buff.absolute_offset = 0;

    stream_node_t *stream_node = push_stream(connection_info->streams, stream_info);
    connection_info->new_stream = stream_node;
    ctx_strm_t *ctx_strm = (ctx_strm_t *)malloc(sizeof(ctx_strm_t));
    ctx_strm->ctx = ctx;
    ctx_strm->connection_node = connection_node;
    ctx_strm->stream_node = stream_node;
    printf("[strm][%p] Creating...\n", (void *)stream);
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
    if (QUIC_FAILED(status = ctx->msquic->StreamStart(stream, QUIC_STREAM_START_FLAG_IMMEDIATE)))
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
    char data[256];
    ssize_t len = recv_data(context, connection, (stream_t) connection_info->new_stream, data, 256, 0);
    if (strcmp(data, "STREAM HSK") == 0) {
        printf("stream started on server side\n");
    }
    connection_info->last_new_stream = stream_node;
    return (stream_t) stream_node;
    #elif LSQUIC
    struct context *ctx = (struct context *)context;
    printf("Opening stream\n");
    #endif
}

void close_stream(context_t context, connection_t connection, stream_t stream) {
    #ifdef QUICHE
    struct context *ctx = (struct context *)context;
    #elif MSQUIC
    struct context *ctx = (struct context *)context;
    stream_node_t *stream_node = (stream_node_t *)stream;
    stream_info_t *stream_info = stream_node->stream_info;
    connection_node_t *connection_node = (connection_node_t *)connection;
    connection_info_t *connection_info = connection_node->connection_info;
    ctx->msquic->StreamShutdown(stream_info->stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
    #elif LSQUIC
    struct context *ctx = (struct context *)context;
    #endif
}

void send_data(context_t context, connection_t connection, stream_t stream, void* data, int len) {
    #ifdef QUICHE
    struct context *ctx = (struct context *)context;
    #elif MSQUIC
    struct context *ctx = (struct context *)context;
    QUIC_STATUS status = QUIC_STATUS_SUCCESS;
    connection_node_t *connection_node = (connection_node_t *)connection;
    connection_info_t *connection_info = connection_node->connection_info;
    stream_node_t *stream_node = (stream_node_t *)stream;
    stream_info_t *stream_info = stream_node->stream_info;

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
    send_buffer->Length = (uint32_t)len;
    
    //
    // Sends the buffer over the stream. Note the FIN flag is passed along with
    // the buffer. This indicates this is the last buffer on the stream and the
    // the stream is shut down (in the send direction) immediately after.
    //
    if (QUIC_FAILED(status = ctx->msquic->StreamSend(stream_info->stream, send_buffer, 1, QUIC_SEND_FLAG_START, send_buffer)))
    {
        printf("StreamSend failed, 0x%x!\n", status);
        free(send_buffer_raw);
        exit(EXIT_FAILURE);
    }
    #elif LSQUIC
    struct context *ctx = (struct context *)context;
    #endif
    
}

ssize_t recv_data(context_t context, connection_t connection, stream_t stream, void* buf, ssize_t n_bytes, time_t timeout) {
    #ifdef QUICHE
    struct context *ctx = (struct context *)context;
    #elif MSQUIC
    struct context *ctx = (struct context *)context;
    connection_node_t *connection_node = (connection_node_t *)connection;
    connection_info_t *connection_info = connection_node->connection_info;
    stream_node_t *stream_node = (stream_node_t *)stream;
    stream_info_t *stream_info = stream_node->stream_info;

    pthread_mutex_lock(&stream_info->recv_buff.lock);

    if (stream_info->recv_buff.total_buffer_length == 0) {
        // Wait for data to be available
        if (timeout == 0) {
            pthread_cond_wait(&stream_info->recv_buff.cond, &stream_info->recv_buff.lock);
        } else {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += timeout;
            int ret = pthread_cond_timedwait(&stream_info->recv_buff.cond, &stream_info->recv_buff.lock, &ts);
            if (ret == ETIMEDOUT) {
                printf("Timed out\n");
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
        printf("No data available\n");
        pthread_mutex_unlock(&stream_info->recv_buff.lock);
        return 0; // No data available
    }

    // Copy data to the buffer
    size_t copied = 0;
    while (copied < to_read) {
        if (stream_info->recv_buff.buffer_count == 0) {
            printf("No more buffers available\n");
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
    pthread_mutex_unlock(&stream_info->recv_buff.lock);

    return to_read;
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
    struct context *ctx = (struct context *)context;
    printf("Accepting connection\n");

    ctx->loop = ev_default_loop(0);

    printf("sockfd: %d\n", ctx->conns->sock);

    ev_io_init(&ctx->watcher, server_recv_cb, ctx->conns->sock, EV_READ);
    ev_io_start(ctx->loop, &ctx->watcher);
    ctx->watcher.data = ctx->conns;

    ev_loop(ctx->loop, 0);

    // quiche_conn *conn = quiche_accept((const uint8_t *)ctx->scid, sizeof(ctx->scid), NULL, 0,
    //                                     &ctx->local_addr, ctx->local_addr_len, &ctx->conn_io->peer_addr, 
    //                                     ctx->conn_io->peer_addr_len, ctx->config);
    // if (conn == NULL)
    // {
    //     fprintf(stderr, "failed to create connection\n");
    //     exit(EXIT_FAILURE);
    // }
    return (connection_t) (void*)0;

    #elif MSQUIC
    struct context *ctx = (struct context *)context;

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
    printf("New connection accepted\n");
    ctx->last_new_connection = ctx->new_connection;
    // Unlock the mutex
    pthread_mutex_unlock(&ctx->lock);
    return (connection_t)ctx->new_connection;
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
    #elif MSQUIC
    struct context *ctx = (struct context *)context;
    connection_node_t *connection_node = (connection_node_t *)connection;
    connection_info_t *connection_info = connection_node->connection_info;
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
    char* data = "STREAM HSK";
    send_data(context, (connection_t)connection, (stream_t)connection_info->new_stream, data, 11);
    printf("New stream accepted\n");
    connection_info->last_new_stream = connection_info->new_stream;
    // Unlock the mutex
    pthread_mutex_unlock(&connection_info->lock);
    return (stream_t)connection_info->new_stream;
    #endif
}