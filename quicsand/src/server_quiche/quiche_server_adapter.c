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
#include <uthash.h>

#include <quiche.h>

#include "quicsand_server_adapter.h"

#define LOCAL_CONN_ID_LEN 16

#define MAX_DATAGRAM_SIZE 1350

#define MAX_TOKEN_LEN                     \
    sizeof("quiche") - 1 +                \
        sizeof(struct sockaddr_storage) + \
        QUICHE_MAX_CONN_ID_LEN

struct connections
{
    int sock;

    struct sockaddr *local_addr;
    socklen_t local_addr_len;

    struct conn_io *h;
};

struct conn_io
{
    ev_timer timer;

    int sock;

    uint8_t cid[LOCAL_CONN_ID_LEN];

    quiche_conn *conn;

    struct sockaddr_storage peer_addr;
    socklen_t peer_addr_len;

    UT_hash_handle hh;
};

struct server_ctx
{
    struct connections *conns;
    struct quiche_config *config;

    struct ev_loop *loop;
    ev_io watcher;
};

static void timeout_cb(EV_P_ ev_timer *w, int revents);

static void debug_log(const char *line, void *argp)
{
    fprintf(stderr, "%s\n", line);
}

static void flush_egress(struct ev_loop *loop, struct conn_io *conn_io)
{
    static uint8_t out[MAX_DATAGRAM_SIZE];

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

static void mint_token(const uint8_t *dcid, size_t dcid_len,
                       struct sockaddr_storage *addr, socklen_t addr_len,
                       uint8_t *token, size_t *token_len)
{
    memcpy(token, "quiche", sizeof("quiche") - 1);
    memcpy(token + sizeof("quiche") - 1, addr, addr_len);
    memcpy(token + sizeof("quiche") - 1 + addr_len, dcid, dcid_len);

    *token_len = sizeof("quiche") - 1 + addr_len + dcid_len;
}

static bool validate_token(const uint8_t *token, size_t token_len,
                           struct sockaddr_storage *addr, socklen_t addr_len,
                           uint8_t *odcid, size_t *odcid_len)
{
    if ((token_len < sizeof("quiche") - 1) ||
        memcmp(token, "quiche", sizeof("quiche") - 1))
    {
        return false;
    }

    token += sizeof("quiche") - 1;
    token_len -= sizeof("quiche") - 1;

    if ((token_len < addr_len) || memcmp(token, addr, addr_len))
    {
        return false;
    }

    token += addr_len;
    token_len -= addr_len;

    if (*odcid_len < token_len)
    {
        return false;
    }

    memcpy(odcid, token, token_len);
    *odcid_len = token_len;

    return true;
}

static uint8_t *gen_cid(uint8_t *cid, size_t cid_len)
{
    int rng = open("/dev/urandom", O_RDONLY);
    if (rng < 0)
    {
        perror("failed to open /dev/urandom");
        return NULL;
    }

    ssize_t rand_len = read(rng, cid, cid_len);
    if (rand_len < 0)
    {
        perror("failed to create connection ID");
        return NULL;
    }

    return cid;
}

struct timer_data
{
    struct server_ctx *ctx;
    struct conn_io *conn_io;
};

static struct conn_io *create_conn(uint8_t *scid, size_t scid_len,
                                   uint8_t *odcid, size_t odcid_len,
                                   struct sockaddr *local_addr,
                                   socklen_t local_addr_len,
                                   struct sockaddr_storage *peer_addr,
                                   socklen_t peer_addr_len, struct server_ctx *ctx)
{
    struct conn_io *conn_io = calloc(1, sizeof(*conn_io));
    if (conn_io == NULL)
    {
        fprintf(stderr, "failed to allocate connection IO\n");
        return NULL;
    }

    if (scid_len != LOCAL_CONN_ID_LEN)
    {
        fprintf(stderr, "failed, scid length too short\n");
    }

    memcpy(conn_io->cid, scid, LOCAL_CONN_ID_LEN);

    quiche_conn *conn = quiche_accept(conn_io->cid, LOCAL_CONN_ID_LEN,
                                      odcid, odcid_len,
                                      local_addr,
                                      local_addr_len,
                                      (struct sockaddr *)peer_addr,
                                      peer_addr_len,
                                      ctx->config);

    if (conn == NULL)
    {
        fprintf(stderr, "failed to create connection\n");
        return NULL;
    }

    conn_io->sock = ctx->conns->sock;
    conn_io->conn = conn;

    memcpy(&conn_io->peer_addr, peer_addr, peer_addr_len);
    conn_io->peer_addr_len = peer_addr_len;

    ev_init(&conn_io->timer, timeout_cb);
    struct timer_data *td = malloc(sizeof(struct timer_data));
    if (td == NULL)
    {
        fprintf(stderr, "failed to allocate timer data\n");
        return NULL;
    }
    td->ctx = ctx;
    td->conn_io = conn_io;
    conn_io->timer.data = td;

    HASH_ADD(hh, ctx->conns->h, cid, LOCAL_CONN_ID_LEN, conn_io);

    fprintf(stderr, "new connection\n");

    return conn_io;
}

static void recv_cb(EV_P_ ev_io *w, int revents)
{
    struct conn_io *tmp, *conn_io = NULL;

    static uint8_t buf[65535];
    static uint8_t out[MAX_DATAGRAM_SIZE];

    struct server_ctx *ctx = w->data;

    while (1)
    {
        struct sockaddr_storage peer_addr;
        socklen_t peer_addr_len = sizeof(peer_addr);
        memset(&peer_addr, 0, peer_addr_len);

        struct server_ctx *ctx = w->data;
        ssize_t read = recvfrom(ctx->conns->sock, buf, sizeof(buf), 0,
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

        if (rc < 0)
        {
            fprintf(stderr, "failed to parse header: %d\n", rc);
            continue;
        }

        HASH_FIND(hh, ctx->conns->h, dcid, dcid_len, conn_io);

        if (conn_io == NULL)
        {
            if (!quiche_version_is_supported(version))
            {
                fprintf(stderr, "version negotiation\n");

                ssize_t written = quiche_negotiate_version(scid, scid_len,
                                                           dcid, dcid_len,
                                                           out, sizeof(out));

                if (written < 0)
                {
                    fprintf(stderr, "failed to create vneg packet: %zd\n",
                            written);
                    continue;
                }

                ssize_t sent = sendto(ctx->conns->sock, out, written, 0,
                                      (struct sockaddr *)&peer_addr,
                                      peer_addr_len);
                if (sent != written)
                {
                    perror("failed to send");
                    continue;
                }

                fprintf(stderr, "sent %zd bytes\n", sent);
                continue;
            }

            if (token_len == 0)
            {
                fprintf(stderr, "stateless retry\n");

                mint_token(dcid, dcid_len, &peer_addr, peer_addr_len,
                           token, &token_len);

                uint8_t new_cid[LOCAL_CONN_ID_LEN];

                if (gen_cid(new_cid, LOCAL_CONN_ID_LEN) == NULL)
                {
                    continue;
                }

                ssize_t written = quiche_retry(scid, scid_len,
                                               dcid, dcid_len,
                                               new_cid, LOCAL_CONN_ID_LEN,
                                               token, token_len,
                                               version, out, sizeof(out));

                if (written < 0)
                {
                    fprintf(stderr, "failed to create retry packet: %zd\n",
                            written);
                    continue;
                }

                ssize_t sent = sendto(ctx->conns->sock, out, written, 0,
                                      (struct sockaddr *)&peer_addr,
                                      peer_addr_len);
                if (sent != written)
                {
                    perror("failed to send");
                    continue;
                }

                fprintf(stderr, "sent %zd bytes\n", sent);
                continue;
            }

            if (!validate_token(token, token_len, &peer_addr, peer_addr_len,
                                odcid, &odcid_len))
            {
                fprintf(stderr, "invalid address validation token\n");
                continue;
            }

            conn_io = create_conn(dcid, dcid_len, odcid, odcid_len,
                                  ctx->conns->local_addr, ctx->conns->local_addr_len,
                                  &peer_addr, peer_addr_len, ctx);

            if (conn_io == NULL)
            {
                continue;
            }
        }

        quiche_recv_info recv_info = {
            (struct sockaddr *)&peer_addr,
            peer_addr_len,

            ctx->conns->local_addr,
            ctx->conns->local_addr_len,
        };

        ssize_t done = quiche_conn_recv(conn_io->conn, buf, read, &recv_info);

        if (done < 0)
        {
            fprintf(stderr, "failed to process packet: %zd\n", done);
            continue;
        }

        fprintf(stderr, "recv %zd bytes\n", done);

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

                if (fin)
                {
                    static const char *resp = "byez\n";
                    uint64_t error_code;
                    quiche_conn_stream_send(conn_io->conn, s, (uint8_t *)resp,
                                            5, true, &error_code);
                }
            }

            quiche_stream_iter_free(readable);
        }
    }

    HASH_ITER(hh, ctx->conns->h, conn_io, tmp)
    {
        flush_egress(loop, conn_io);

        if (quiche_conn_is_closed(conn_io->conn))
        {
            quiche_stats stats;
            quiche_path_stats path_stats;

            quiche_conn_stats(conn_io->conn, &stats);
            quiche_conn_path_stats(conn_io->conn, 0, &path_stats);

            fprintf(stderr, "connection closed, recv=%zu sent=%zu lost=%zu rtt=%" PRIu64 "ns cwnd=%zu\n",
                    stats.recv, stats.sent, stats.lost, path_stats.rtt, path_stats.cwnd);

            HASH_DELETE(hh, ctx->conns->h, conn_io);

            ev_timer_stop(loop, &conn_io->timer);
            quiche_conn_free(conn_io->conn);
            free(conn_io);
        }
    }
}

static void timeout_cb(EV_P_ ev_timer *w, int revents)
{
    struct timer_data *timer_data = w->data;
    struct conn_io *conn_io = timer_data->conn_io;
    struct connections *conns = timer_data->ctx->conns;

    if (conn_io == NULL)
    {
        fprintf(stderr, "failed to get connection from timer\n");
        return;
    }
    printf("Timer data: %p\n", timer_data);
    printf("Connection data: %p\n", conn_io);

    quiche_conn_on_timeout(conn_io->conn);

    fprintf(stderr, "timeout\n");

    flush_egress(loop, conn_io);

    if (quiche_conn_is_closed(conn_io->conn))
    {
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

        return;
    }
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

void server_init(Config *conf, Server_CTX *ctx)
{
    *ctx = malloc(sizeof(struct server_ctx));
    if (*ctx == NULL)
    {
        perror("failed to allocate server context");
        exit(EXIT_FAILURE);
    }

    struct server_ctx *server_ctx = (struct server_ctx *)*ctx;

    const char *container_name = "localhost";
    char ip_address[17];

    get_docker_ip(container_name, ip_address, sizeof(ip_address));

    printf("IP Address of container '%s': %s\n", container_name, ip_address);
    const char *port = conf->port;

    const struct addrinfo hints = {
        .ai_family = PF_UNSPEC,
        .ai_socktype = SOCK_DGRAM,
        .ai_protocol = IPPROTO_UDP};

    quiche_enable_debug_logging(debug_log, NULL);

    struct addrinfo *local;
    if (getaddrinfo(ip_address, port, &hints, &local) != 0)
    {
        perror("failed to resolve host");
        exit(EXIT_FAILURE);
    }

    printf("Openning socket on %s:%s\n", ip_address, port);
    int sock = socket(local->ai_family, SOCK_DGRAM, 0);
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

    if (bind(sock, local->ai_addr, local->ai_addrlen) < 0)
    {
        perror("failed to connect socket");
        exit(EXIT_FAILURE);
    }

    printf("Starting quiche server\n");
    server_ctx->config = quiche_config_new(QUICHE_PROTOCOL_VERSION);
    if (server_ctx->config == NULL)
    {
        fprintf(stderr, "failed to create config\n");
        exit(EXIT_FAILURE);
    }

    quiche_config_load_cert_chain_from_pem_file(server_ctx->config, "./certs/quicsand-server.pem");
    quiche_config_load_priv_key_from_pem_file(server_ctx->config, "./certs/key.pem");

    quiche_config_set_application_protos(server_ctx->config,
                                         (uint8_t *)"\x0ahq-interop\x05hq-29\x05hq-28\x05hq-27\x08http/0.9", 38);

    quiche_config_set_max_idle_timeout(server_ctx->config, 5000);
    quiche_config_set_max_recv_udp_payload_size(server_ctx->config, MAX_DATAGRAM_SIZE);
    quiche_config_set_max_send_udp_payload_size(server_ctx->config, MAX_DATAGRAM_SIZE);
    quiche_config_set_initial_max_data(server_ctx->config, 10000000);
    quiche_config_set_initial_max_stream_data_bidi_local(server_ctx->config, 1000000);
    quiche_config_set_initial_max_stream_data_bidi_remote(server_ctx->config, 1000000);
    quiche_config_set_initial_max_streams_bidi(server_ctx->config, 100);
    quiche_config_set_cc_algorithm(server_ctx->config, QUICHE_CC_RENO);

    server_ctx->conns = malloc(sizeof(struct connections));
    if (server_ctx->conns == NULL)
    {
        perror("failed to allocate connections");
        exit(EXIT_FAILURE);
    }
    struct connections *c = server_ctx->conns;
    c->sock = sock;
    c->local_addr = local->ai_addr;
    c->local_addr_len = local->ai_addrlen;

    server_ctx->loop = ev_default_loop(0);

    ev_io_init(&server_ctx->watcher, recv_cb, sock, EV_READ);
    ev_io_start(server_ctx->loop, &server_ctx->watcher);
    server_ctx->watcher.data = server_ctx;

    ev_loop(server_ctx->loop, 0);

    freeaddrinfo(local);

    quiche_config_free(server_ctx->config);
}

void server_shutdown(Server_CTX ctx)
{
    struct server_ctx *server_ctx = (struct server_ctx *)ctx;
    close(server_ctx->conns->sock);
    printf("Shutting down server\n");
}
