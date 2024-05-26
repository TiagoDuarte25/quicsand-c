#include "lsquic.h"
#include "quicsand_client_adapter.h"
#include <errno.h>
#include <event2/event.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>

static lsquic_conn_ctx_t *on_new_conn_cb(void *ea_stream_if_ctx, lsquic_conn_t *conn);
static void on_conn_closed_cb(lsquic_conn_t *conn);
static lsquic_stream_ctx_t *on_new_stream_cb(void *ea_stream_if_ctx, lsquic_stream_t *stream);
static void on_read_cb(lsquic_stream_t *stream, lsquic_stream_ctx_t *h);
static void on_write_cb(lsquic_stream_t *stream, lsquic_stream_ctx_t *h);
static void on_hsk_done(lsquic_conn_t *c, enum lsquic_hsk_status s);

typedef struct client_ctx
{
    // event loop
    struct event_base *loop;
    struct event *sock_ev, *conn_ev, *strm_ev;

    // lsquic
    int sockfd;
    struct sockaddr_storage local_sas;
    lsquic_engine_t *engine;
    lsquic_conn_t *conn;
    lsquic_stream_t *stream;

    // SSL
    SSL_CTX *ssl_ctx;

    // msg to send
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
    .on_hsk_done = on_hsk_done};

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

static int send_packets_out(void *ctx, const struct lsquic_out_spec *specs, unsigned n_specs)
{
    fprintf(stdout, "Sending out packets\n");
    unsigned n;
    int fd, s = 0;
    struct msghdr msg;

    if (0 == n_specs)
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
            printf("sendmsg failed: %s\n", strerror(errno));
            break;
        }
        ++n;
    } while (n < n_specs);

    if (n < n_specs)
        printf("could not send all of them\n"); /* TODO */
    if (n > 0)
        return n;
    else
    {
        assert(s < 0);
        return -1;
    }
}

static void read_sock(evutil_socket_t fd, short what, void *arg)
{
    client_ctx_t *client_ctx = arg;
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
    nread = recvmsg(fd, &msg, 0);
    if (-1 == nread)
    {
        return;
    }

    // TODO handle ECN properly
    int ecn = 0;

    (void)lsquic_engine_packet_in(client_ctx->engine, buf, nread,
                                  (struct sockaddr *)&client_ctx->local_sas,
                                  (struct sockaddr *)&peer_sas,
                                  (void *)(uintptr_t)fd, ecn);

    process_conns(client_ctx);
}

static void process_conns_cb(evutil_socket_t fd, short what, void *arg)
{
    process_conns(arg);
}

void process_conns(client_ctx_t *client_ctx)
{
    int diff;
    struct timeval timeout;

    event_del(client_ctx->conn_ev);
    lsquic_engine_process_conns(client_ctx->engine);
    if (lsquic_engine_earliest_adv_tick(client_ctx->engine, &diff))
    {
        if (diff > 0)
        {
            timeout.tv_sec = (time_t)diff / 1000000;
        }
        else
        {
            timeout.tv_sec = 0;
        }
        event_add(client_ctx->conn_ev, &timeout);
    }
}

static lsquic_conn_ctx_t *on_new_conn_cb(void *ea_stream_if_ctx, lsquic_conn_t *conn)
{
    printf("On new connection\n");
    client_ctx_t *client_ctx = ea_stream_if_ctx;
    fflush(stdout);
    return (void *)client_ctx;
}

static void on_conn_closed_cb(lsquic_conn_t *conn)
{
    printf("On connection close\n");
    char errbuf[2048];
    enum LSQUIC_CONN_STATUS status = lsquic_conn_status(conn, errbuf, 2048);
    printf("errbuf: %s\n", errbuf);
    // printf("conn status: %s\n", get_conn_status_str(status));
    fflush(stdout);
}

static void on_hsk_done(lsquic_conn_t *conn, enum lsquic_hsk_status status)
{
    client_ctx_t *client_ctx = (void *)lsquic_conn_get_ctx(conn);

    switch (status)
    {
    case LSQ_HSK_OK:
        printf("OK: handshake successful, start stdin watcher\n");
        fflush(stdout);
        break;
    case LSQ_HSK_RESUMED_OK:
        printf("RESUME OK: handshake successful, start stdin watcher\n");
        fflush(stdout);
        lsquic_conn_make_stream(client_ctx->conn);
        break;
    default:
        printf("handshake failed\n");
        fflush(stdout);
        break;
    }
}

static lsquic_stream_ctx_t *on_new_stream_cb(void *ea_stream_if_ctx, lsquic_stream_t *stream)
{
    printf("On new stream\n");
    fflush(stdout);
    client_ctx_t *client_ctx = ea_stream_if_ctx;
    client_ctx->stream = stream;
    event_active(client_ctx->strm_ev, 0, 0);
    return (void *)client_ctx;
}

static void on_read_cb(lsquic_stream_t *stream, lsquic_stream_ctx_t *h)
{
    lsquic_conn_t *conn = lsquic_stream_conn(stream);
    client_ctx_t *client_ctx = (void *)lsquic_conn_get_ctx(conn);

    unsigned char buf[256] = {0};

    ssize_t nr = lsquic_stream_read(stream, buf, sizeof(buf));

    buf[nr] = '\0';
    printf("recv %zd bytes: %s\n", nr, buf);

    // lsquic_stream_wantread(stream, 0);
    // event_add(client_ctx->strm_ev, NULL);
}

static void on_write_cb(lsquic_stream_t *stream, lsquic_stream_ctx_t *h)
{
    lsquic_conn_t *conn = lsquic_stream_conn(stream);
    client_ctx_t *client_ctx = (void *)lsquic_conn_get_ctx(conn);

    lsquic_stream_write(stream, client_ctx->buf, client_ctx->size);
    lsquic_stream_wantwrite(stream, 0);
    lsquic_stream_flush(stream);
    lsquic_stream_wantread(stream, 1);
}

void read_stdin(evutil_socket_t fd, short what, void *ctx)
{
    char *req = "Client request\n";
    client_ctx_t *client_ctx = ctx;
    client_ctx->buf = req;
    client_ctx->size = sizeof(req);
    event_del(client_ctx->strm_ev);
    lsquic_stream_wantwrite(client_ctx->stream, 1);
    process_conns(client_ctx);
}

Config *
client_init()
{
    printf("Starting client...\n");

    client_ctx_t client_ctx;
    memset(&client_ctx, 0, sizeof(client_ctx));

    Config *conf = read_config("config.yaml");
    if (!conf)
    {
        fprintf(stderr, "Error: Failed to read configuration file\n");
        exit(EXIT_FAILURE);
    }

    client_ctx.sockfd = create_sock("127.0.0.1", 5000, &client_ctx.local_sas);
    struct sockaddr_in peer_addr = new_addr(conf->target, atoi(conf->port));

    // Event initialiazation
    client_ctx.loop = event_base_new();
    client_ctx.sock_ev = event_new(client_ctx.loop, client_ctx.sockfd, EV_READ | EV_PERSIST, read_sock, &client_ctx);
    client_ctx.conn_ev = event_new(client_ctx.loop, -1, EV_TIMEOUT, process_conns_cb, &client_ctx);
    client_ctx.strm_ev = event_new(client_ctx.loop, -1, 0, read_stdin, &client_ctx);

    if (0 != lsquic_global_init(LSQUIC_GLOBAL_CLIENT))
    {
        exit(EXIT_FAILURE);
    }

    // Initialization of lsquic logger
    lsquic_log_to_fstream(stderr, LLTS_HHMMSSMS);
    lsquic_set_log_level("debug");

    struct lsquic_engine_api engine_api = {
        .ea_packets_out = send_packets_out,
        .ea_packets_out_ctx = (void *)&client_ctx.sockfd,
        .ea_stream_if = &stream_if,
        .ea_stream_if_ctx = (void *)&client_ctx,
    };
    client_ctx.engine = lsquic_engine_new(0, &engine_api);
    printf("Engine created with success!\n");
    client_ctx.conn = lsquic_engine_connect(client_ctx.engine, N_LSQVER,
                                            (struct sockaddr *)&client_ctx.local_sas,
                                            (struct sockaddr *)&peer_addr, (void *)&client_ctx.sockfd, NULL,
                                            NULL, 0, NULL, 0, NULL, 0);

    if (!client_ctx.conn)
    {
        printf("Cannot create connection\n");
        fflush(stdout);
        exit(EXIT_FAILURE);
    }

    printf("Cheguei aqui!\n");
    lsquic_engine_process_conns(client_ctx.engine);

    event_base_dispatch(client_ctx.loop);

    lsquic_global_cleanup();
    return conf;
}

Connection open_connection(Config *conf)
{
    // printf("Openning connection...\n");

    // if (0 != connect(client_ctx.sport->sockfd, (const struct sockaddr *)&client_ctx.sport->sas, sizeof(struct sockaddr_in)))
    // {
    //     fprintf(stderr, "Error connecting sockets: %s\n", strerror(errno));
    //     close(client_ctx.sport->sockfd);
    //     exit(EXIT_FAILURE);
    // }

    // struct lsquic_conn_t *conn = lsquic_engine_connect(client_ctx.engine, N_LSQVER,
    //                                                    (struct sockaddr *)&client_ctx.sport->sp_local_addr,
    //                                                    (struct sockaddr *)&client_ctx.sport->sas, (void *)&client_ctx.sport->sockfd, NULL,
    //                                                    NULL, 0, NULL, 0, NULL, 0);
    // if (!conn)
    // {
    //     fprintf(stderr, "Connection failed: %s\n", strerror(errno));
    //     exit(EXIT_FAILURE);
    // }

    // lsquic_engine_process_conns(client_ctx.engine);

    // return (Connection)conn;
    return (void *)0;
}

void close_connection(Connection conn)
{
    lsquic_conn_close((lsquic_conn_t *)conn);
    printf("conn[%x] Connection closed\n", lsquic_conn_id(conn)->buf);
}

Stream open_stream(Connection conn)
{
    // lsquic_conn_make_stream((lsquic_conn_t *)conn);

    // return (Stream)stream;
}

void close_stream(Stream stream)
{
    // lsquic_stream_close((lsquic_stream_t *)stream);
}

void send_data(Connection connnection, Stream stream, int *reqsize)
{
    // lsquic_stream_write((lsquic_stream_t *)stream, data, strlen(data));
    // lsquic_stream_flush((lsquic_stream_t *)stream);
}

void receive_data()
{
}

void client_shutdown()
{
    // lsquic_engine_destroy(engine);
    printf("Client shutdown\n");
    lsquic_global_cleanup();
    exit(EXIT_SUCCESS);
}
