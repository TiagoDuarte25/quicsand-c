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

int random_data(size_t len, char **data) {
    *data = (char *)malloc(len);
    for (int i = 0; i < len - 1; i++) {
        (*data)[i] = 'A' + (rand() % 26);
    }
    (*data)[len - 1] = '\0';
    return 0;
}

typedef struct {
    context_t ctx;
    connection_t connection;
    int factor;
} thread_data_t;

typedef struct {
    context_t ctx;
    connection_t connection;
    int stream_fd;
    int factor;
} thread_data_stream_t;

void* handle_stream(void * arg) {
    thread_data_stream_t *data = (thread_data_stream_t *)arg;
    context_t ctx = data->ctx;
    connection_t connection = data->connection;
    int stream_fd = data->stream_fd;
    log_debug("handling stream");

    while (1) {
        char buffer[65536];
        // receive data from the client
        int len = read(stream_fd, buffer, sizeof(buffer));
        if (len > 0) {
            log_debug("received data: %.*s", len, buffer);

            // response size multiplied by factor
            int response_len = len * data->factor;
            char* response;
            random_data(response_len, &response);
            // send the response in chunks
            size_t chunk_size = 65536;
            size_t bytes_sent = 0;
            while (bytes_sent < response_len) {
                size_t bytes_to_send = (response_len - bytes_sent) < chunk_size ? (response_len - bytes_sent) : chunk_size;
                write(stream_fd, response + bytes_sent, bytes_to_send);
                bytes_sent += bytes_to_send;
                log_debug("sent %zu bytes", bytes_sent);
            }
            shutdown(stream_fd, SHUT_WR);
            log_debug("stream closed");
        } else if (len == 0) {
            log_debug("stream closed by client");
            break;
        } else {
            log_error("error: %s", quic_error_message(quic_error));
            break;
        }
    }

    return NULL;
}

void *handle_connection(void *arg)
{
    thread_data_t *data = (thread_data_t *)arg;
    context_t ctx = data->ctx;
    connection_t connection = data->connection;
    log_debug("handling connection");

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
        stream_data->factor = data->factor;

        // Create a new thread to handle the stream
        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, handle_stream, (void *)stream_data) != 0)
        {
            log_error("error: failed to create thread");
            free(stream_data);
            continue;
        }
        log_debug("created thread to handle stream");

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
    char *log_file = NULL;
    int factor = 1;
    int port = 0;
    int opt;

    // Parse command-line arguments
    while ((opt = getopt(argc, argv, "c:k:i:p:l:m:")) != -1)
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
        case 'l':
            log_file = strdup(optarg);
            break;
        case 'm':
            factor = atoi(optarg);
            break;
        default:
            fprintf(stdout, "usage: %s -c <cert_path> -k <key_path> -i <ip_address> -p <port>", argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    // Open the log file
    FILE *fp = fopen(log_file, "w+");
    if (!fp) {
        perror("Failed to open log file");
        return 1;
    }

    // Add file callback with the level
    if (log_add_fp(fp, LOG_TRACE) != 0) {
        fprintf(fp, "Failed to add file callback\n");
        return 1;
    }

    // Ensure required options are provided
    if (!cert_path || !key_path || !ip_address || port == 0)
    {
        fprintf(fp, "usage: %s -c <cert_path> -k <key_path> -i <ip_address> -p <port>", argv[0]);
        exit(EXIT_FAILURE);
    }

    context_t ctx = create_quic_context(cert_path, key_path);
    log_debug("context created");
    bind_addr(ctx, ip_address, port);
    log_debug("bound address");
    set_listen(ctx);
    log_debug("listening");

    log_info("server running...");
    while (1)
    {
        log_debug("waiting for connection");
        connection_t connection = accept_connection(ctx, 0);
        if (!connection)
        {
            log_error("error: %s", quic_error_message(quic_error));
            continue;
        }
        log_debug("connection accepted");

        // Allocate memory for thread data
        thread_data_t *data = (thread_data_t *)malloc(sizeof(thread_data_t));
        data->ctx = ctx;
        data->connection = connection;
        data->factor = factor;

        // Create a new thread to handle the connection
        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, handle_connection, (void *)data) != 0)
        {
            log_error("error: failed to create thread");
            free(data);
            continue;
        }
        // Detach the thread so that it cleans up after itself
        pthread_detach(thread_id);
    }
    return 0;
}