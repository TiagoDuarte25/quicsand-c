#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
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

#include "quicsand_client_adapter.h"

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

struct client_ctx
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

static void debug_log(const char *line, void *argp)
{
    fprintf(stderr, "%s\n", line);
}

static void flush_egress(struct ev_loop *loop, struct conn_io *conn_io)
{
    static uint8_t out[MAX_DATAGRAM_SIZE];

    for (int i = 0; i < MAX_DATAGRAM_SIZE; i++)
    {
        printf("%02x ", out[i]);
    }
    printf("\n");

    quiche_send_info send_info;

    while (1)
    {
        ssize_t written = quiche_conn_send(conn_io->conn, out, sizeof(out),
                                           &send_info);

        if (written == QUICHE_ERR_DONE)
        {
            fprintf(stderr, "done writing\n");
            break;
        }

        if (written < 0)
        {
            fprintf(stderr, "failed to create packet: %zd\n", written);
            return;
        }

        ssize_t sent = sendto(conn_io->sock, out, written, 0,
                              (struct sockaddr *)&send_info.to,
                              send_info.to_len);

        if (sent != written)
        {
            perror("failed to send");
            return;
        }

        fprintf(stderr, "sent %zd bytes\n", sent);
    }

    double t = quiche_conn_timeout_as_nanos(conn_io->conn) / 1e9f;
    conn_io->timer.repeat = t;
    ev_timer_again(loop, &conn_io->timer);
}

static void recv_cb(EV_P_ ev_io *w, int revents)
{
    static bool req_sent = false;

    struct conn_io *conn_io = w->data;

    static uint8_t buf[65535];

    while (1)
    {
        struct sockaddr_storage peer_addr;
        socklen_t peer_addr_len = sizeof(peer_addr);
        memset(&peer_addr, 0, peer_addr_len);

        ssize_t read = recvfrom(conn_io->sock, buf, sizeof(buf), 0,
                                (struct sockaddr *)&peer_addr,
                                &peer_addr_len);

        if (read < 0)
        {
            if ((errno == EWOULDBLOCK) || (errno == EAGAIN))
            {
                fprintf(stderr, "recv would block\n");
                break;
            }

            perror("failed to read");
            return;
        }

        quiche_recv_info recv_info = {
            (struct sockaddr *)&peer_addr,
            peer_addr_len,

            (struct sockaddr *)&conn_io->local_addr,
            conn_io->local_addr_len,
        };

        ssize_t done = quiche_conn_recv(conn_io->conn, buf, read, &recv_info);

        if (done < 0)
        {
            fprintf(stderr, "failed to process packet\n");
            continue;
        }

        fprintf(stderr, "recv %zd bytes\n", done);
    }

    fprintf(stderr, "done reading\n");

    if (quiche_conn_is_closed(conn_io->conn))
    {
        fprintf(stderr, "connection closed\n");

        ev_break(EV_A_ EVBREAK_ONE);
        return;
    }

    if (quiche_conn_is_established(conn_io->conn) && !req_sent)
    {
        const uint8_t *app_proto;
        size_t app_proto_len;

        quiche_conn_application_proto(conn_io->conn, &app_proto, &app_proto_len);

        fprintf(stderr, "connection established: %.*s\n",
                (int)app_proto_len, app_proto);

        const static uint8_t r[] = "GET /index.html\r\n";
        uint64_t error_code;
        if (quiche_conn_stream_send(conn_io->conn, 4, r, sizeof(r), true, &error_code) < 0)
        {
            fprintf(stderr, "failed to send HTTP request: %" PRIu64 "\n", error_code);
            return;
        }

        fprintf(stderr, "sent HTTP request\n");

        req_sent = true;
    }

    if (quiche_conn_is_established(conn_io->conn))
    {
        uint64_t s = 0;

        quiche_stream_iter *readable = quiche_conn_readable(conn_io->conn);

        while (quiche_stream_iter_next(readable, &s))
        {
            fprintf(stderr, "stream %" PRIu64 " is readable\n", s);

            bool fin = false;
            uint64_t error_code;
            ssize_t recv_len = quiche_conn_stream_recv(conn_io->conn, s,
                                                       buf, sizeof(buf),
                                                       &fin, &error_code);
            if (recv_len < 0)
            {
                break;
            }

            printf("%.*s", (int)recv_len, buf);

            if (fin)
            {
                if (quiche_conn_close(conn_io->conn, true, 0, NULL, 0) < 0)
                {
                    fprintf(stderr, "failed to close connection\n");
                }
            }
        }

        quiche_stream_iter_free(readable);
    }
}

static void timeout_cb(EV_P_ ev_timer *w, int revents)
{
    struct conn_io *conn_io = w->data;
    quiche_conn_on_timeout(conn_io->conn);

    fprintf(stderr, "timeout\n");

    if (quiche_conn_is_closed(conn_io->conn))
    {
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

void client_init(Config *conf, Client_CTX *client_ctx, char *target_ip)
{
    *client_ctx = malloc(sizeof(struct client_ctx));
    if (*client_ctx == NULL)
    {
        fprintf(stderr, "failed to allocate connection IO\n");
        exit(EXIT_FAILURE);
    }

    struct client_ctx *ctx = (struct client_ctx *)*client_ctx;
    ctx->host = target_ip;
    ctx->port = conf->port;

    const struct addrinfo hints = {
        .ai_family = PF_UNSPEC,
        .ai_socktype = SOCK_DGRAM,
        .ai_protocol = IPPROTO_UDP};

    quiche_enable_debug_logging(debug_log, NULL);

    printf("connecting to %s:%s\n", ctx->host, ctx->port);
    if (getaddrinfo(ctx->host, ctx->port, &hints, &ctx->peer) != 0)
    {
        perror("failed to resolve host");
        exit(EXIT_FAILURE);
    }

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
}

void open_connection(Client_CTX client_ctx)
{
    struct client_ctx *ctx = (struct client_ctx *)client_ctx;

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

    ctx->loop = ev_default_loop(0);

    ev_io_init(&ctx->watcher, recv_cb, ctx->conn_io->sock, EV_READ);
    ev_io_start(ctx->loop, &ctx->watcher);
    ctx->watcher.data = ctx->conn_io;

    ev_init(&ctx->conn_io->timer, timeout_cb);
    ctx->conn_io->timer.data = ctx->conn_io;

    // flush_egress(ctx->loop, ctx->conn_io);

    // ev_loop(ctx->loop, 0);
}

void close_connection(Client_CTX client_ctx)
{
    struct client_ctx *ctx = (struct client_ctx *)client_ctx;

    close(ctx->conn_io->sock);

    freeaddrinfo(ctx->peer);

    quiche_conn_free(ctx->conn_io->conn);

    free(ctx->conn_io);

    printf("Connection closed\n");
}

void open_stream(Client_CTX ctx)
{
}

void close_stream(Client_CTX ctx)
{
}

void send_data(Client_CTX client_ctx, int *reqsize)
{
    struct client_ctx *ctx = (struct client_ctx *)client_ctx;
    struct conn_io *conn_io = ctx->conn_io;

    static uint8_t out[MAX_DATAGRAM_SIZE];

    for (int i = 0; i < MAX_DATAGRAM_SIZE; i++)
    {
        printf("%02x ", out[i]);
    }
    printf("\n");

    quiche_send_info send_info;

    while (1)
    {
        ssize_t written = quiche_conn_send(conn_io->conn, out, sizeof(out),
                                           &send_info);

        if (written == QUICHE_ERR_DONE)
        {
            fprintf(stderr, "done writing\n");
            break;
        }

        if (written < 0)
        {
            fprintf(stderr, "failed to create packet: %zd\n", written);
            return;
        }

        ssize_t sent = sendto(conn_io->sock, out, written, 0,
                              (struct sockaddr *)&send_info.to,
                              send_info.to_len);

        if (sent != written)
        {
            perror("failed to send");
            return;
        }

        fprintf(stderr, "sent %zd bytes\n", sent);
    }
}

void receive_data(Client_CTX ctx)
{
}

void client_shutdown(Client_CTX client_ctx)
{
    struct client_ctx *ctx = (struct client_ctx *)client_ctx;
    quiche_config_free(ctx->config);
}