#include "lsquic.h"
#include "quicsand_client_adapter.h"
#include <errno.h>
#include <ev.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>

// #include <openssl/pem.h>
// #include <openssl/x509.h>
// #include <openssl/ssl.h>
#include "../../../implementations/boringssl/include/openssl/pem.h"
#include "../../../implementations/boringssl/include/openssl/x509.h"
#include "../../../implementations/boringssl/include/openssl/ssl.h"
#include <assert.h>

#define MAX(a, b) ((a) > (b) ? (a) : (b))

static lsquic_conn_ctx_t *on_new_conn_cb(void *ea_stream_if_ctx, lsquic_conn_t *conn);
static void on_conn_closed_cb(lsquic_conn_t *conn);
static lsquic_stream_ctx_t *on_new_stream_cb(void *ea_stream_if_ctx, lsquic_stream_t *stream);
static void on_read_cb(lsquic_stream_t *stream, lsquic_stream_ctx_t *h);
static void on_write_cb(lsquic_stream_t *stream, lsquic_stream_ctx_t *h);
static void on_hsk_done(lsquic_conn_t *c, enum lsquic_hsk_status s);
static void on_close_cb(struct lsquic_stream *stream, lsquic_stream_ctx_t *h);

typedef struct client_ctx
{
    struct ev_loop *loop;
    ev_io sock_w; /* socket watcher */
    ev_timer timer;

    // lsquic
    int sockfd;
    struct sockaddr_storage local_sas;
    lsquic_engine_t *engine;
    lsquic_conn_t *conn;
    lsquic_stream_t *stream;

    // SSL
    SSL_CTX *ssl_ctx;

    // Connection
    char *buf;
    int size;
} client_ctx_t;

static void process_conns(client_ctx_t *client_ctx);

const struct lsquic_stream_if stream_if = {
    .on_new_conn = on_new_conn_cb,
    .on_conn_closed = on_conn_closed_cb,
    .on_new_stream = on_new_stream_cb,
    .on_read = on_read_cb,
    .on_write = on_write_cb,
    .on_hsk_done = on_hsk_done,
    .on_close = on_close_cb,
};

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

struct sockaddr_in new_addr(char *ip, unsigned int port)
{

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = (port == 0) ? port : htons(port);
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
    client_ctx_t *const client_ctx = packets_out_ctx;
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

static void read_sock(EV_P_ ev_io *w, int revents)
{
    client_ctx_t *client_ctx = w->data;
    ssize_t nread;
    struct sockaddr_storage peer_sas;
    unsigned char buf[0x1000];
    struct iovec vec[1] = {{buf, sizeof(buf)}};

    struct msghdr msg = {
        .msg_name = &peer_sas,
        .msg_namelen = sizeof(peer_sas),
        .msg_iov = vec,
        .msg_iovlen = 1,
    };
    nread = recvmsg(client_ctx->sockfd, &msg, 0);
    if (-1 == nread)
    {
        return;
    }

    // TODO handle ECN properly
    int ecn = 0;

    (void)lsquic_engine_packet_in(client_ctx->engine, buf, nread,
                                  (struct sockaddr *)&client_ctx->local_sas,
                                  (struct sockaddr *)&peer_sas,
                                  (void *)(uintptr_t)client_ctx->sockfd, ecn);

    process_conns(client_ctx);
}

static void process_conns_cb(EV_P_ ev_timer *timer, int revents)
{
    process_conns(timer->data);
}

void process_conns(client_ctx_t *client_ctx)
{
    int diff;
    ev_tstamp timeout;

    ev_timer_stop(client_ctx->loop, &client_ctx->timer);
    lsquic_engine_process_conns(client_ctx->engine);
    if (lsquic_engine_earliest_adv_tick(client_ctx->engine, &diff))
    {
        if (diff > 0)
        {
            timeout = (ev_tstamp)diff / 1000000;
        }
        else
        {
            timeout = 0;
        }
        ev_timer_init(&client_ctx->timer, process_conns_cb, timeout, 0.);
        ev_timer_start(client_ctx->loop, &client_ctx->timer);
    }
}

static lsquic_conn_ctx_t *on_new_conn_cb(void *ea_stream_if_ctx, lsquic_conn_t *conn)
{
    printf("On new connection\n");
    fflush(stdout);
    client_ctx_t *const client_ctx = ea_stream_if_ctx;
    client_ctx->conn = conn;
    printf("created connection\n");
    return (void *)client_ctx;
}

static void on_conn_closed_cb(lsquic_conn_t *conn)
{
    printf("On connection close\n");

    client_ctx_t *const client_ctx = (void *)lsquic_conn_get_ctx(conn);

    printf("client connection closed -- stop reading from socket\n");
    ev_io_stop(client_ctx->loop, &client_ctx->sock_w);
}

static void on_hsk_done(lsquic_conn_t *conn, enum lsquic_hsk_status status)
{
    client_ctx_t *const client_ctx = (void *)lsquic_conn_get_ctx(conn);

    switch (status)
    {
    case LSQ_HSK_OK:
    case LSQ_HSK_RESUMED_OK:
        printf("handshake successful, start stdin watcher\n");
        break;
    default:
        printf("handshake failed\n");
        break;
    }
}

static lsquic_stream_ctx_t *on_new_stream_cb(void *ea_stream_if_ctx, lsquic_stream_t *stream)
{
    client_ctx_t *client_ctx = ea_stream_if_ctx;
    printf("created new stream, we want to write\n");
    lsquic_stream_wantwrite(stream, 1);
    return (void *)client_ctx;
}

static void on_read_cb(lsquic_stream_t *stream, lsquic_stream_ctx_t *h)
{
    client_ctx_t *client_ctx = (client_ctx_t *)h;
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
        printf("error reading from stream (%s) -- exit loop\n", strerror(errno));
        ev_break(client_ctx->loop, EVBREAK_ONE);
    }
}

static void on_write_cb(lsquic_stream_t *stream, lsquic_stream_ctx_t *h)
{
    lsquic_conn_t *conn;
    client_ctx_t *client_ctx;
    ssize_t nw;

    conn = lsquic_stream_conn(stream);
    client_ctx = (void *)lsquic_conn_get_ctx(conn);

    nw = lsquic_stream_write(stream, client_ctx->buf, client_ctx->size);
    if (nw > 0)
    {
        client_ctx->size -= (size_t)nw;
        if (client_ctx->size == 0)
        {
            printf("wrote all %zd bytes to stream, switch to reading\n", (size_t)nw);
            lsquic_stream_shutdown(stream, 1); /* This flushes as well */
            lsquic_stream_wantread(stream, 1);
        }
        else
        {
            memmove(client_ctx->buf, client_ctx->buf + nw, client_ctx->size);
            printf("wrote %zd bytes to stream, still have %zd bytes to write\n", (size_t)nw, client_ctx->size);
        }
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
    printf("stream closed");
}

void get_docker_ip(const char *container_name, char *ip_address, size_t size)
{
    char command[100];
    FILE *fp;

    // Construct the command to get the IP address of the Docker container
    snprintf(command, sizeof(command),
             "getent hosts %s | awk '{print $1}'",
             container_name);

    // Open the command for reading
    fp = popen(command, "r");
    if (fp == NULL)
    {
        perror("popen failed");
        exit(EXIT_FAILURE);
    }

    // Read the output a line at a time and copy it to the ip_address
    if (fgets(ip_address, size, fp) == NULL)
    {
        perror("fgets failed");
        exit(EXIT_FAILURE);
    }

    // Close the file pointer
    if (pclose(fp) == -1)
    {
        perror("pclose failed");
        exit(EXIT_FAILURE);
    }

    // Remove the trailing newline character, if any
    size_t len = strlen(ip_address);
    if (len > 0 && ip_address[len - 1] == '\n')
    {
        ip_address[len - 1] = '\0';
    }
}

void client_init(Config *conf, Client_CTX *ctx, char *target_ip)
{
    printf("Starting client...\n");

    *ctx = malloc(sizeof(client_ctx_t));
    client_ctx_t *client_ctx = (client_ctx_t *)*ctx;
    if (client_ctx == NULL)
    {
        fprintf(stderr, "Error allocating memory for client context\n");
        exit(EXIT_FAILURE);
    }

    const char *container_name = "client";
    char ip_address[17];

    get_docker_ip(container_name, ip_address, sizeof(ip_address));

    printf("Client socket '%s': %s\n", container_name, ip_address);
    client_ctx->sockfd = create_sock(ip_address, 5000, &client_ctx->local_sas);
    struct sockaddr_in peer_addr = new_addr(target_ip, atoi(conf->port));

    if (set_nonblocking(client_ctx->sockfd) != 0)
    {
        fprintf(stderr, "Error setting non-blocking socket\n");
        close(client_ctx->sockfd);
        exit(EXIT_FAILURE);
    }

    if (set_ecn(client_ctx->sockfd, (struct sockaddr *)&client_ctx->local_sas) != 0)
    {
        fprintf(stderr, "Error setting ECN\n");
        close(client_ctx->sockfd);
        exit(EXIT_FAILURE);
    }

    // Event initialiazation
    client_ctx->loop = EV_DEFAULT;
    ev_io_init(&client_ctx->sock_w, read_sock, client_ctx->sockfd, EV_READ);
    ev_io_start(client_ctx->loop, &client_ctx->sock_w);
    ev_init(&client_ctx->timer, process_conns_cb);

    if (0 != lsquic_global_init(LSQUIC_GLOBAL_CLIENT))
    {
        exit(EXIT_FAILURE);
    }

    // Initialization of lsquic logger
    lsquic_log_to_fstream(stderr, LLTS_HHMMSSMS);
    lsquic_set_log_level("debug");

    struct lsquic_engine_api engine_api = {
        .ea_packets_out = packets_out[0],
        .ea_packets_out_ctx = (void *)&client_ctx->sockfd,
        .ea_stream_if = &stream_if,
        .ea_stream_if_ctx = (void *)&client_ctx,
    };

    client_ctx->engine = lsquic_engine_new(0, &engine_api);
    if (!client_ctx->engine)
    {
        printf("Cannot create engine\n");
        fflush(stdout);
        exit(EXIT_FAILURE);
    }

    client_ctx->timer.data = &client_ctx;
    client_ctx->sock_w.data = &client_ctx;

    client_ctx->conn = lsquic_engine_connect(client_ctx->engine, N_LSQVER,
                                             (struct sockaddr *)&client_ctx->local_sas,
                                             (struct sockaddr *)&peer_addr, (void *)&client_ctx->sockfd, NULL,
                                             NULL, 0, NULL, 0, NULL, 0);

    if (!client_ctx->conn)
    {
        printf("Cannot create connection\n");
        fflush(stdout);
        exit(EXIT_FAILURE);
    }

    printf("Connection created\n");

    process_conns(client_ctx);

    printf("Client initialized\n");

    ev_run(client_ctx->loop, 0);
}

void open_connection(Client_CTX ctx)
{
    // printf("Openning connection...\n");

    // if (0 != connect(client_ctx->sport->sockfd, (const struct sockaddr *)&client_ctx->sport->sas, sizeof(struct sockaddr_in)))
    // {
    //     fprintf(stderr, "Error connecting sockets: %s\n", strerror(errno));
    //     close(client_ctx->sport->sockfd);
    //     exit(EXIT_FAILURE);
    // }

    // struct lsquic_conn_t *conn = lsquic_engine_connect(client_ctx->engine, N_LSQVER,
    //                                                    (struct sockaddr *)&client_ctx->sport->sp_local_addr,
    //                                                    (struct sockaddr *)&client_ctx->sport->sas, (void *)&client_ctx->sport->sockfd, NULL,
    //                                                    NULL, 0, NULL, 0, NULL, 0);
    // if (!conn)
    // {
    //     fprintf(stderr, "Connection failed: %s\n", strerror(errno));
    //     exit(EXIT_FAILURE);
    // }

    // lsquic_engine_process_conns(client_ctx->engine);
}

void close_connection(Client_CTX ctx)
{
    // lsquic_conn_close((lsquic_conn_t *)conn);
}

void open_stream(Client_CTX ctx)
{
    // lsquic_conn_make_stream((lsquic_conn_t *)conn);

    // return (Stream)stream;
}

void close_stream(Client_CTX ctx)
{
    // lsquic_stream_close((lsquic_stream_t *)stream);
}

void send_data(Client_CTX ctx, int *reqsize)
{
    // lsquic_stream_write((lsquic_stream_t *)stream, data, strlen(data));
    // lsquic_stream_flush((lsquic_stream_t *)stream);
}

void receive_data(Client_CTX ctx)
{
}

void client_shutdown(Client_CTX ctx)
{
    // lsquic_engine_destroy(engine);
    // printf("Client shutdown\n");
    // lsquic_global_cleanup();
    // exit(EXIT_SUCCESS);
}
