#include "lsquic.h"
#include "quicsand_server_adapter.h"
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ev.h>
#include <fcntl.h>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>

static lsquic_conn_ctx_t *on_new_conn_cb(void *ea_stream_if_ctx, lsquic_conn_t *conn);

static void on_conn_closed_cb(lsquic_conn_t *conn);

static lsquic_stream_ctx_t *on_new_stream_cb(void *ea_stream_if_ctx, lsquic_stream_t *stream);

static void on_read_cb(lsquic_stream_t *stream, lsquic_stream_ctx_t *h);

static void on_write_cb(lsquic_stream_t *stream, lsquic_stream_ctx_t *h);

static void on_close_cb(struct lsquic_stream *stream, lsquic_stream_ctx_t *h);

#define MAX(a, b) ((a) > (b) ? (a) : (b))

typedef struct server_ctx
{
    struct ev_loop *loop;
    ev_io sock_w; /* socket watcher */
    ev_timer timer;

    // lsquic
    int sockfd;
    struct sockaddr_storage local_sas;
    lsquic_engine_t *engine;

    // SSL
    SSL_CTX *ssl_ctx;

    size_t sz;
    char buf[0x100];

} server_ctx_t;

void process_conns(server_ctx_t *server_ctx);

const struct lsquic_stream_if stream_if = {
    .on_new_conn = on_new_conn_cb,
    .on_conn_closed = on_conn_closed_cb,
    .on_new_stream = on_new_stream_cb,
    .on_read = on_read_cb,
    .on_write = on_write_cb,
    .on_close = on_close_cb,
};

SSL_CTX *ssl_ctx;

SSL_CTX *get_ssl_ctx(void *peer_ctx, const struct sockaddr *sa)
{
    fprintf(stdout, "GET ssl_ctx\n");
    fflush(stdout);
    return ssl_ctx;
}

void create_ssl_ctx(server_ctx_t *server_ctx)
{
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_method());
    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_default_verify_paths(ssl_ctx);
    if (ssl_ctx == NULL)
    {
        fprintf(stderr, "Error: Failed to create SSL context\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

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
    printf("cert_path: %s\n", cert_path);
    printf("key_path: %s\n", key_path);

    if (SSL_CTX_use_certificate_chain_file(ssl_ctx, cert_path) != 1)
    {
        printf("Cannot load server certificate\n");
        fflush(stdout);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, key_path, SSL_FILETYPE_PEM) != 1)
    {
        printf("Cannot load key\n");
        fflush(stdout);
        exit(EXIT_FAILURE);
    }

    server_ctx->ssl_ctx = ssl_ctx;
}

static int
set_nonblocking(int fd)
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
set_ecn(int fd, const struct sockaddr *sa)
{
    int on, s;

    on = 1;
    if (AF_INET == sa->sa_family)
        s = setsockopt(fd, IPPROTO_IP, IP_RECVTOS, &on, sizeof(on));
    else
        s = setsockopt(fd, IPPROTO_IPV6, IPV6_RECVTCLASS, &on, sizeof(on));
    if (s != 0)
        perror("setsockopt(ecn)");

    return s;
}

/* Set up the socket to return original destination address in ancillary data */
static int
set_origdst(int fd, const struct sockaddr *sa)
{
    int on, s;

    on = 1;
    if (AF_INET == sa->sa_family)
        s = setsockopt(fd, IPPROTO_IP,
#if defined(IP_RECVORIGDSTADDR)
                       IP_RECVORIGDSTADDR,
#else
                       IP_PKTINFO,
#endif
                       &on, sizeof(on));
    else
        s = setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on));

    if (s != 0)
        perror("setsockopt");

    return s;
}

struct sockaddr_in new_addr(char *ip, unsigned int port)
{
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);
    return addr;
}

int create_sock(char *ip, unsigned int port, struct sockaddr_storage *local_sas)
{
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1)
    {
        printf("Error creating socket\n");
        fflush(stdout);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in local_addr = new_addr(ip, port);
    if (bind(sockfd, (struct sockaddr *)&local_addr, sizeof(local_addr)) != 0)
    {
        printf("Cannot bind");
        fflush(stdout);
        exit(EXIT_FAILURE);
    }

    if (!memcpy(local_sas, &local_addr, sizeof(local_addr)))
    {
        printf("memcpy local_sas error\n");
        fflush(stdout);
        exit(EXIT_FAILURE);
    }
    return sockfd;
}

enum ctl_what
{
    CW_SENDADDR = 1 << 0,
    CW_ECN = 1 << 1,
};

static void
setup_control_msg(struct msghdr *msg, enum ctl_what cw,
                  const struct lsquic_out_spec *spec, unsigned char *buf, size_t bufsz)
{
    struct cmsghdr *cmsg;
    struct sockaddr_in *local_sa;
    struct sockaddr_in6 *local_sa6;
    struct in_pktinfo info;
    struct in6_pktinfo info6;
    size_t ctl_len;

    msg->msg_control = buf;
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
                local_sa = (struct sockaddr_in *)spec->local_sa;
                memset(&info, 0, sizeof(info));
                info.ipi_spec_dst = local_sa->sin_addr;
                cmsg->cmsg_level = IPPROTO_IP;
                cmsg->cmsg_type = IP_PKTINFO;
                cmsg->cmsg_len = CMSG_LEN(sizeof(info));
                ctl_len += CMSG_SPACE(sizeof(info));
                memcpy(CMSG_DATA(cmsg), &info, sizeof(info));
            }
            else
            {
                local_sa6 = (struct sockaddr_in6 *)spec->local_sa;
                memset(&info6, 0, sizeof(info6));
                info6.ipi6_addr = local_sa6->sin6_addr;
                cmsg->cmsg_level = IPPROTO_IPV6;
                cmsg->cmsg_type = IPV6_PKTINFO;
                cmsg->cmsg_len = CMSG_LEN(sizeof(info6));
                memcpy(CMSG_DATA(cmsg), &info6, sizeof(info6));
                ctl_len += CMSG_SPACE(sizeof(info6));
            }
            cw &= ~CW_SENDADDR;
        }
        else if (cw & CW_ECN)
        {
            if (AF_INET == spec->dest_sa->sa_family)
            {
                const int tos = spec->ecn;
                cmsg->cmsg_level = IPPROTO_IP;
                cmsg->cmsg_type = IP_TOS;
                cmsg->cmsg_len = CMSG_LEN(sizeof(tos));
                memcpy(CMSG_DATA(cmsg), &tos, sizeof(tos));
                ctl_len += CMSG_SPACE(sizeof(tos));
            }
            else
            {
                const int tos = spec->ecn;
                cmsg->cmsg_level = IPPROTO_IPV6;
                cmsg->cmsg_type = IPV6_TCLASS;
                cmsg->cmsg_len = CMSG_LEN(sizeof(tos));
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

/* A simple version of ea_packets_out -- does not use ancillary messages */
static int
packets_out_v0(void *packets_out_ctx, const struct lsquic_out_spec *specs,
               unsigned count)
{
    unsigned n;
    int fd, s = 0;
    struct msghdr msg;

    if (0 == count)
        return 0;

    n = 0;
    msg.msg_flags = 0;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    do
    {
        fd = (int)(uint64_t)specs[n].peer_ctx;
        msg.msg_name = (void *)specs[n].dest_sa;
        msg.msg_namelen = (AF_INET == specs[n].dest_sa->sa_family ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)),
        msg.msg_iov = specs[n].iov;
        msg.msg_iovlen = specs[n].iovlen;
        s = sendmsg(fd, &msg, 0);
        if (s < 0)
        {
            printf("sendmsg failed: %s", strerror(errno));
            break;
        }
        ++n;
    } while (n < count);

    if (n < count)
        printf("could not send all of them"); /* TODO */

    if (n > 0)
        return n;
    else
    {
        assert(s < 0);
        return -1;
    }
}

/* A more complicated version of ea_packets_out -- this one sets source IP
 * address and ECN.
 */
static int
packets_out_v1(void *packets_out_ctx, const struct lsquic_out_spec *specs,
               unsigned count)
{
    server_ctx_t *const server_ctx = packets_out_ctx;
    unsigned n;
    int fd, s = 0;
    struct msghdr msg;
    enum ctl_what cw;
    union
    {
        /* cmsg(3) recommends union for proper alignment */
        unsigned char buf[CMSG_SPACE(MAX(sizeof(struct in_pktinfo),
                                         sizeof(struct in6_pktinfo))) +
                          CMSG_SPACE(sizeof(int))];
        struct cmsghdr cmsg;
    } ancil;

    if (0 == count)
        return 0;

    n = 0;
    msg.msg_flags = 0;
    do
    {
        fd = (int)(uint64_t)specs[n].peer_ctx;
        msg.msg_name = (void *)specs[n].dest_sa;
        msg.msg_namelen = (AF_INET == specs[n].dest_sa->sa_family ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)),
        msg.msg_iov = specs[n].iov;
        msg.msg_iovlen = specs[n].iovlen;

        /* Set up ancillary message */
        cw = CW_SENDADDR;
        if (specs[n].ecn)
            cw |= CW_ECN;
        if (cw)
            setup_control_msg(&msg, cw, &specs[n], ancil.buf,
                              sizeof(ancil.buf));
        else
        {
            msg.msg_control = NULL;
            msg.msg_controllen = 0;
        }

        s = sendmsg(fd, &msg, 0);
        if (s < 0)
        {
            printf("sendmsg failed: %s", strerror(errno));
            break;
        }
        ++n;
    } while (n < count);

    if (n < count)
        printf("could not send all of them"); /* TODO */

    if (n > 0)
        return n;
    else
    {
        assert(s < 0);
        return -1;
    }
}

static int (*const packets_out[])(void *packets_out_ctx,
                                  const struct lsquic_out_spec *specs, unsigned count) =
    {
        packets_out_v0,
        packets_out_v1,
};

static lsquic_conn_ctx_t *on_new_conn_cb(void *ea_stream_if_ctx, lsquic_conn_t *conn)
{
    server_ctx_t *const server_ctx = ea_stream_if_ctx;

    printf("created new connection\n");
    return (void *)server_ctx;
}

static void on_conn_closed_cb(lsquic_conn_t *conn)
{
    printf("closed connection\n");
}

struct stream_ctx
{
    size_t sc_sz;                /* Number of bytes in sc_buf */
    off_t sc_off;                /* Number of bytes written to stream */
    unsigned char sc_buf[0x100]; /* Bytes read in from client */
};

static lsquic_stream_ctx_t *on_new_stream_cb(void *ea_stream_if_ctx, lsquic_stream_t *stream)
{
    struct stream_ctx *sc;

    /* Allocate a new buffer per stream.  There is no reason why the echo
     * server could not process several echo streams at the same time.
     */
    sc = malloc(sizeof(*sc));
    if (!sc)
    {
        printf("cannot allocate server stream context\n");
        lsquic_conn_abort(lsquic_stream_conn(stream));
        return NULL;
    }

    sc->sc_sz = 0;
    sc->sc_off = 0;
    lsquic_stream_wantread(stream, 1);
    printf("created new echo stream -- want to read\n");
    return (void *)sc;
}

static void on_read_cb(lsquic_stream_t *stream, lsquic_stream_ctx_t *h)
{
    struct stream_ctx *const sc = (void *)h;
    ssize_t nread;
    unsigned char buf[1];

    nread = lsquic_stream_read(stream, buf, sizeof(buf));
    if (nread > 0)
    {
        sc->sc_buf[sc->sc_sz] = buf[0];
        ++sc->sc_sz;
        if (buf[0] == (unsigned char)'\n' || sc->sc_sz == sizeof(sc->sc_buf))
        {
            printf("read newline or filled buffer, switch to writing\n");
            lsquic_stream_wantread(stream, 0);
            lsquic_stream_wantwrite(stream, 1);
        }
    }
    else if (nread == 0)
    {
        printf("read EOF\n");
        lsquic_stream_shutdown(stream, 0);
        if (sc->sc_sz)
            lsquic_stream_wantwrite(stream, 1);
    }
    else
    {
        /* This should not happen */
        printf("error reading from stream (errno: %d) -- abort connection\n", errno);
        lsquic_conn_abort(lsquic_stream_conn(stream));
    }
}

static size_t
sc_read(void *ctx, void *buf, size_t count)
{
    struct stream_ctx *sc = ctx;

    if (count > sc->sc_sz - sc->sc_off)
        count = sc->sc_sz - sc->sc_off;
    memcpy(buf, sc->sc_buf + sc->sc_off, count);
    sc->sc_off += count;
    return count;
}

static size_t
sc_size(void *ctx)
{
    struct stream_ctx *sc = ctx;
    return sc->sc_sz - sc->sc_off;
}

static void on_write_cb(lsquic_stream_t *stream, lsquic_stream_ctx_t *h)
{
    struct stream_ctx *const sc = (void *)h;
    ssize_t nw;

    assert(sc->sc_sz > 0);
    nw = lsquic_stream_write(stream, sc->sc_buf + sc->sc_off,
                             sc->sc_sz - sc->sc_off);
    if (nw > 0)
    {
        sc->sc_off += nw;
        if (sc->sc_off == sc->sc_sz)
        {
            printf("wrote all %zd bytes to stream, close stream\n",
                   (size_t)nw);
            lsquic_stream_close(stream);
        }
        else
            printf("wrote %zd bytes to stream, still have %zd bytes to write\n",
                   (size_t)nw, sc->sc_sz - sc->sc_off);
    }
    else
    {
        /* When `on_write()' is called, the library guarantees that at least
         * something can be written.  If not, that's an error whether 0 or -1
         * is returned.
         */
        printf("stream_write() returned %ld, abort connection\n", (long)nw);
        lsquic_conn_abort(lsquic_stream_conn(stream));
    }
}

static void
on_close_cb(struct lsquic_stream *stream, lsquic_stream_ctx_t *h)
{
    struct stream_ctx *const sc = (void *)h;
    free(sc);
    printf("stream closed\n");
}

static void
proc_ancillary(struct msghdr *msg, struct sockaddr_storage *storage,
               int *ecn)
{
    const struct in6_pktinfo *in6_pkt;
    struct cmsghdr *cmsg;

    for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg))
    {
        if (cmsg->cmsg_level == IPPROTO_IP &&
            cmsg->cmsg_type ==
#if defined(IP_RECVORIGDSTADDR)
                IP_ORIGDSTADDR
#else
                IP_PKTINFO
#endif
        )
        {
#if defined(IP_RECVORIGDSTADDR)
            memcpy(storage, CMSG_DATA(cmsg), sizeof(struct sockaddr_in));
#else
            const struct in_pktinfo *in_pkt;
            in_pkt = (void *)CMSG_DATA(cmsg);
            ((struct sockaddr_in *)storage)->sin_addr = in_pkt->ipi_addr;
#endif
        }
        else if (cmsg->cmsg_level == IPPROTO_IPV6 &&
                 cmsg->cmsg_type == IPV6_PKTINFO)
        {
            in6_pkt = (void *)CMSG_DATA(cmsg);
            ((struct sockaddr_in6 *)storage)->sin6_addr =
                in6_pkt->ipi6_addr;
        }
        else if ((cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TOS) || (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_TCLASS))
        {
            memcpy(ecn, CMSG_DATA(cmsg), sizeof(*ecn));
            *ecn &= IPTOS_ECN_MASK;
        }
    }
}

#if defined(IP_RECVORIGDSTADDR)
#define DST_MSG_SZ sizeof(struct sockaddr_in)
#else
#define DST_MSG_SZ sizeof(struct in_pktinfo)
#endif

#define ECN_SZ CMSG_SPACE(sizeof(int))

/* Amount of space required for incoming ancillary data */
#define CTL_SZ (CMSG_SPACE(MAX(DST_MSG_SZ,                    \
                               sizeof(struct in6_pktinfo))) + \
                ECN_SZ)

static void read_sock(EV_P_ ev_io *w, int revents)
{
    fprintf(stdout, "Reading socket...\n");
    server_ctx_t *server_ctx = w->data;
    ssize_t nread;
    struct sockaddr_storage peer_sas, local_sas;
    unsigned char buf[0x1000];
    struct iovec vec[1] = {{buf, sizeof(buf)}};

    struct msghdr msg = {
        .msg_name = &peer_sas,
        .msg_namelen = sizeof(peer_sas),
        .msg_iov = vec,
        .msg_iovlen = 1,
    };
    nread = recvmsg(server_ctx->sockfd, &msg, 0);
    if (-1 == nread)
    {
        return;
    }

    local_sas = server_ctx->local_sas;
    int ecn = 0;
    proc_ancillary(&msg, &local_sas, &ecn);

    (void)lsquic_engine_packet_in(server_ctx->engine, buf, nread,
                                  (struct sockaddr *)&server_ctx->local_sas,
                                  (struct sockaddr *)&peer_sas,
                                  (void *)(uintptr_t)server_ctx->sockfd, ecn);

    process_conns(server_ctx);
}

static void process_conns_cb(EV_P_ ev_timer *timer, int revents)
{
    fprintf(stdout, "Processing connections...\n");
    process_conns(timer->data);
}

void process_conns(server_ctx_t *server_ctx)
{
    int diff;
    ev_tstamp timeout;

    ev_timer_stop(server_ctx->loop, &server_ctx->timer);
    lsquic_engine_process_conns(server_ctx->engine);
    if (lsquic_engine_earliest_adv_tick(server_ctx->engine, &diff))
    {
        if (diff > 0)
        {
            timeout = (ev_tstamp)diff / 1000000;
        }
        else
        {
            timeout = 0;
        }
    }
    else
    {
        timeout = 2;
    }
    ev_timer_init(&server_ctx->timer, process_conns_cb, timeout, 0.);
    ev_timer_start(server_ctx->loop, &server_ctx->timer);
}

void server_init()
{
    printf("Server initialization...\n");
    char err_buf[100];
    struct timeval timeout;
    struct lsquic_engine_settings settings;

    // Loading server configuration
    Config *conf = read_config("config.yaml");
    printf("Server configuration loaded\n");

    server_ctx_t server_ctx;
    // Initialization of the server context structure
    memset(&server_ctx, 0, sizeof(server_ctx));

    // Create SSL Context
    create_ssl_ctx(&server_ctx);
    ssl_ctx = server_ctx.ssl_ctx;

    server_ctx.sockfd = create_sock(conf->target, atoi(conf->port), &server_ctx.local_sas);

    if (0 != set_nonblocking(server_ctx.sockfd))
    {
        perror("set_nonblocking");
        exit(EXIT_FAILURE);
    }

    if (0 != set_ecn(server_ctx.sockfd, (struct sockaddr *)&server_ctx.local_sas))
    {
        perror("set_ecn");
        exit(EXIT_FAILURE);
    }

    if (0 != set_origdst(server_ctx.sockfd, (struct sockaddr *)&server_ctx.local_sas))
    {
        perror("set_origdst");
        exit(EXIT_FAILURE);
    }

    server_ctx.loop = EV_DEFAULT;
    ev_io_init(&server_ctx.sock_w, read_sock, server_ctx.sockfd, EV_READ);
    ev_io_start(server_ctx.loop, &server_ctx.sock_w);

    if (0 != lsquic_global_init(LSQUIC_GLOBAL_SERVER | LSQUIC_GLOBAL_CLIENT))
    {
        exit(EXIT_FAILURE);
    }

    lsquic_engine_init_settings(&settings, LSENG_SERVER);

    if (0 != lsquic_engine_check_settings(&settings, LSENG_SERVER,
                                          err_buf, sizeof(err_buf)))
    {
        fprintf(stderr, "invalid settings: %s", err_buf);
        exit(EXIT_FAILURE);
    }

    // Initialization of lsquic logger
    lsquic_log_to_fstream(stdout, LLTS_HHMMSSMS);
    lsquic_set_log_level("debug");

    struct lsquic_engine_api engine_api;
    memset(&engine_api, 0, sizeof(engine_api));
    engine_api.ea_packets_out = packets_out[0];
    engine_api.ea_packets_out_ctx = (void *)&server_ctx.sockfd;
    engine_api.ea_stream_if = &stream_if;
    engine_api.ea_stream_if_ctx = (void *)&server_ctx;
    engine_api.ea_get_ssl_ctx = get_ssl_ctx;
    engine_api.ea_settings = &settings;

    server_ctx.engine = lsquic_engine_new(LSENG_SERVER, &engine_api);

    if (!server_ctx.engine)
    {
        fprintf(stderr, "cannot create engine\n");
        exit(EXIT_FAILURE);
    }

    server_ctx.timer.data = &server_ctx;
    server_ctx.sock_w.data = &server_ctx;

    ev_run(server_ctx.loop, 0);
}

void server_shutdown()
{
    printf("Server shutdown\n");
    lsquic_global_cleanup();
    exit(EXIT_SUCCESS);
}