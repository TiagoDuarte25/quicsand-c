#include "lsquic.h"
#include "quicsand_server_adapter.h"
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <event2/event.h>
#include <fcntl.h>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>

static lsquic_conn_ctx_t *on_new_conn_cb(void *ea_stream_if_ctx, lsquic_conn_t *conn);

static void on_conn_closed_cb(lsquic_conn_t *conn);

static lsquic_stream_ctx_t *on_new_stream_cb(void *ea_stream_if_ctx, lsquic_stream_t *stream);

static void on_read_cb(lsquic_stream_t *stream, lsquic_stream_ctx_t *h);

static void on_write_cb(lsquic_stream_t *stream, lsquic_stream_ctx_t *h);

typedef struct server_ctx
{
    // event loop
    struct event_base *loop;
    struct event *read, *timer;

    // lsquic
    int sockfd;
    struct sockaddr_storage local_sas;
    lsquic_engine_t *engine;

    // SSL
    SSL_CTX *ssl_ctx;

    // response
    char *response;
    int size;
} server_ctx_t;

void process_conns(server_ctx_t *server_ctx);

const struct lsquic_stream_if stream_if = {
    .on_new_conn = on_new_conn_cb,
    .on_conn_closed = on_conn_closed_cb,
    .on_new_stream = on_new_stream_cb,
    .on_read = on_read_cb,
    .on_write = on_write_cb,
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

    int flags;
    flags = fcntl(sockfd, F_GETFL);
    if (-1 == flags)
        return -1;
    flags |= O_NONBLOCK;
    if (0 != fcntl(sockfd, F_SETFL, flags))
        return -1;
    int on, s;
    on = 1;
    s = setsockopt(sockfd, IPPROTO_IP, IP_RECVORIGDSTADDR, &on, sizeof(on));
    if (s != 0)
        perror("setsockopt");

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
    struct msghdr msg;
    int *sockfd;
    unsigned n;

    memset(&msg, 0, sizeof(msg));
    sockfd = (int *)ctx;

    for (n = 0; n < n_specs; ++n)
    {
        msg.msg_name = (void *)specs[n].dest_sa;
        msg.msg_namelen = sizeof(struct sockaddr_in);
        msg.msg_iov = specs[n].iov;
        msg.msg_iovlen = specs[n].iovlen;
        if (sendmsg(*sockfd, &msg, 0) < 0)
        {
            perror("sendmsg");
            break;
        }
    }

    return (int)n;
}

static lsquic_conn_ctx_t *on_new_conn_cb(void *ea_stream_if_ctx, lsquic_conn_t *conn)
{
    printf("On new connection\n");
    fflush(stdout);
    server_ctx_t *server_ctx = ea_stream_if_ctx;
    return (void *)server_ctx;
}

static void on_conn_closed_cb(lsquic_conn_t *conn)
{
    printf("On connection close\n");
    fflush(stdout);
}

static lsquic_stream_ctx_t *on_new_stream_cb(void *ea_stream_if_ctx, lsquic_stream_t *stream)
{
    printf("On new stream\n");
    fflush(stdout);
    lsquic_stream_wantread(stream, 1);
    return NULL;
}

static void on_read_cb(lsquic_stream_t *stream, lsquic_stream_ctx_t *h)
{
    lsquic_conn_t *conn = lsquic_stream_conn(stream);
    server_ctx_t *server_ctx = (void *)lsquic_conn_get_ctx(conn);

    unsigned char buf[256] = {0};
    ssize_t nr = lsquic_stream_read(stream, buf, sizeof(buf));
    buf[nr] = '\0';
    printf("recv %zd bytes: %s\n", nr, buf);
    fflush(stdout);

    char *response = (char *)malloc(sizeof(char) * nr + 2);
    char *server_prefix = "s:";

    int response_size = snprintf(response, nr + strlen(server_prefix), "%s%s", server_prefix, buf);
    server_ctx->response = response;
    server_ctx->size = response_size;

    lsquic_stream_wantread(stream, 0);
    lsquic_stream_wantwrite(stream, 1);
}

static void on_write_cb(lsquic_stream_t *stream, lsquic_stream_ctx_t *h)
{
    lsquic_conn_t *conn = lsquic_stream_conn(stream);
    server_ctx_t *server_ctx = (void *)lsquic_conn_get_ctx(conn);

    lsquic_stream_write(stream, server_ctx->response, server_ctx->size);
    lsquic_stream_wantwrite(stream, 0);
    lsquic_stream_wantread(stream, 1);
    lsquic_stream_flush(stream);
}

static void read_sock(evutil_socket_t fd, short what, void *arg)
{
    fprintf(stdout, "Reading socket...\n");
    server_ctx_t *server_ctx = arg;
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
    nread = recvmsg((int)fd, &msg, 0);
    if (-1 == nread)
    {
        return;
    }

    // TODO handle ECN properly
    int ecn = 0;

    (void)lsquic_engine_packet_in(server_ctx->engine, buf, nread,
                                  (struct sockaddr *)&server_ctx->local_sas,
                                  (struct sockaddr *)&peer_sas,
                                  (void *)(uintptr_t)fd, ecn);

    process_conns(server_ctx);
}

static void process_conns_cb(evutil_socket_t fd, short what, void *arg)
{
    fprintf(stdout, "Processing connections...\n");
    process_conns(arg);
}

void process_conns(server_ctx_t *server_ctx)
{
    int diff;
    struct timeval timeout;

    event_del(server_ctx->timer);
    lsquic_engine_process_conns(server_ctx->engine);
    if (lsquic_engine_earliest_adv_tick(server_ctx->engine, &diff))
    {
        if (diff > 0)
        {
            timeout.tv_sec = (time_t)diff / 1000000;
            timeout.tv_usec = diff % 1000000;
        }
        else
        {
            timeout.tv_sec = 0;
        }
    }
    else
    {
        timeout.tv_sec = 2;
        timeout.tv_usec = 200000;
    }
    server_ctx->timer = event_new(server_ctx->loop, -1, EV_TIMEOUT, process_conns_cb, server_ctx);
    event_add(server_ctx->timer, &timeout);
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

    if (0 != lsquic_global_init(LSQUIC_GLOBAL_CLIENT | LSQUIC_GLOBAL_SERVER))
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
    lsquic_log_to_fstream(stderr, LLTS_HHMMSSMS);
    lsquic_set_log_level("debug");

    struct lsquic_engine_api engine_api;
    memset(&engine_api, 0, sizeof(engine_api));
    engine_api.ea_packets_out = send_packets_out;
    engine_api.ea_packets_out_ctx = (void *)&server_ctx.sockfd;
    engine_api.ea_stream_if = &stream_if;
    engine_api.ea_stream_if_ctx = (void *)&server_ctx;
    engine_api.ea_get_ssl_ctx = get_ssl_ctx;
    engine_api.ea_settings = &settings;

    server_ctx.engine = lsquic_engine_new(LSENG_SERVER, &engine_api);

    server_ctx.loop = event_base_new();
    server_ctx.read = event_new(server_ctx.loop, server_ctx.sockfd, EV_READ | EV_PERSIST, read_sock, &server_ctx);
    event_add(server_ctx.read, NULL);
    server_ctx.timer = event_new(server_ctx.loop, -1, EV_TIMEOUT, process_conns_cb, &server_ctx);
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;
    event_add(server_ctx.timer, &timeout);
    event_base_dispatch(server_ctx.loop);
}

void server_shutdown()
{
    printf("Server shutdown\n");
    lsquic_global_cleanup();
    exit(EXIT_SUCCESS);
}