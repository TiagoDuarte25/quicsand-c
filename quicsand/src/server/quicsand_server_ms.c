#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <log.h>
#include "quicsand_api.h"

#define CHUNK_SIZE 1024

char* reverse_string(char *str)
{
    char *start = str;
    char *end = start + strlen(str) - 1;
    while (end > start)
    {
        char temp = *start;
        *start = *end;
        *end = temp;
        ++start;
        --end;
    }
    return str;
}

typedef struct {
    context_t ctx;
    connection_t connection;
} thread_data_t;

typedef struct {
    context_t ctx;
    connection_t connection;
    int stream_fd;
} thread_data_stream_t;

void* handle_stream(void * arg) {
    thread_data_stream_t *data = (thread_data_stream_t *)arg;
    context_t ctx = data->ctx;
    connection_t connection = data->connection;
    int stream_fd = data->stream_fd;
    log_info("handling stream");

    while (1) {
        char buffer[65536];
        // receive data from the client
        int len = read(stream_fd, buffer, sizeof(buffer));
        if (len > 0) {
            log_debug("received data: %.*s", len, buffer);

            // write the response back to the client
            char *response = reverse_string(buffer);
            write(stream_fd, response, strlen(response) + 1);
            log_debug("response sent: %s", response);
        } else {
            log_error("error: %s", quic_error_message(quic_error));
            break;
        }
    }
    close(stream_fd);
    log_info("stream closed");
    return NULL;
}

void *handle_connection(void *arg)
{
    thread_data_t *data = (thread_data_t *)arg;
    context_t ctx = data->ctx;
    connection_t connection = data->connection;
    log_info("handling connection");

    while (1) {

        int stream_fd = accept_stream(ctx, connection, 0);
        if (stream_fd < 0) {
            log_error("error: %s", quic_error_message(quic_error));
            close_connection(ctx, connection);
            continue;
        }

        // Allocate memory for thread data
        thread_data_stream_t *stream_data = (thread_data_stream_t *)malloc(sizeof(thread_data_stream_t));
        stream_data->ctx = ctx;
        stream_data->connection = connection;
        stream_data->stream_fd = stream_fd;

        // Create a new thread to handle the connection
        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, handle_stream, (void *)stream_data) != 0)
        {
            log_info("error: failed to create thread");
            free(stream_data);
            continue;
        }
        log_info("created thread to handle connection");

        // Detach the thread so that it cleans up after itself
        pthread_detach(thread_id);
    }
    return NULL;
}

int main(int argc, char *argv[])
{
    char *cert_path = NULL;
    char *key_path = NULL;
    char *ip_address = NULL;
    int port = 0;
    int opt;

    // Open the log file
    FILE *fp = fopen("server.log", "w+");
    if (!fp) {
        perror("Failed to open log file");
        return 1;
    }

    // Add file callback with LOG_TRACE level
    if (log_add_fp(fp, LOG_TRACE) != 0) {
        fprintf(fp, "Failed to add file callback\n");
        return 1;
    }

    // Set global log level to LOG_TRACE
    log_set_level(LOG_TRACE);

    // Parse command-line arguments
    while ((opt = getopt(argc, argv, "c:k:i:p:")) != -1)
    {
        switch (opt)
        {
        case 'c':
            cert_path = strdup(optarg);
            break;
        case 'k':
            key_path = strdup(optarg);
            break;
        case 'i':
            ip_address = strdup(optarg);
            break;
        case 'p':
            port = atoi(optarg);
            break;
        default:
            log_info("usage: %s -c <cert_path> -k <key_path> -i <ip_address> -p <port>", argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    // Ensure required options are provided
    if (!cert_path || !key_path || !ip_address || port == 0)
    {
        log_info("usage: %s -c <cert_path> -k <key_path> -i <ip_address> -p <port>", argv[0]);
        exit(EXIT_FAILURE);
    }

    context_t ctx = create_quic_context(cert_path, key_path);
    log_info("context created");
    bind_addr(ctx, ip_address, port);
    log_info("bound address");
    set_listen(ctx);
    log_info("listening");

    while (1)
    {
        log_info("waiting for connection");
        connection_t connection = accept_connection(ctx, 0);
        if (!connection)
        {
            log_info("error: %s", quic_error_message(quic_error));
            continue;
        }
        log_info("connection accepted");

        // Allocate memory for thread data
        thread_data_t *data = (thread_data_t *)malloc(sizeof(thread_data_t));
        data->ctx = ctx;
        data->connection = connection;

        // Create a new thread to handle the connection
        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, handle_connection, (void *)data) != 0)
        {
            log_info("error: failed to create thread");
            free(data);
            continue;
        }
        // Detach the thread so that it cleans up after itself
        pthread_detach(thread_id);
    }
    return 0;
}