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

char *random_data(int len)
{
    char *data = (char *)malloc(len);
    for (int i = 0; i < len - 1; i++)
    {
        data[i] = 'A' + (rand() % 26);
    }
    data[len - 1] = '\0';
    return data;
}

typedef struct {
    context_t ctx;
    connection_t connection;
} thread_data_t;

void send_control_message(context_t ctx, connection_t connection, const char *message) {
    stream_t stream = open_stream(ctx, connection);
    send_data(ctx, connection, stream, (void *)message, strlen(message) + 1); // +1 to include null terminator
    close_stream(ctx, connection, stream);
}

void *handle_connection(void *arg)
{
    thread_data_t *data = (thread_data_t *)arg;
    context_t ctx = data->ctx;
    connection_t connection = data->connection;
    log_info("handling connection");

    stream_t stream = accept_stream(ctx, connection, 0);
    if (!stream) {
        log_error("error: %s", quic_error_message(quic_error));
        close_connection(ctx, connection);
        return NULL;
    }
    log_info("stream accepted");

    // Receive control message
    char control_message[256];
    ssize_t len = recv_data(ctx, connection, stream, control_message, sizeof(control_message), 0);
    if (len <= 0) {
        log_error("error: %s", quic_error_message(quic_error));
        close_stream(ctx, connection, stream);
        close_connection(ctx, connection);
        return NULL;
    }
    log_info("len: %ld", len);
    log_info("control message received: %s", control_message);
    send_data(ctx, connection, stream, control_message, len);

    // Handle control message
    if (strcmp(control_message, CONTROL_UPLOAD) == 0) {
        log_info("handling file upload");
        FILE *file = fopen("uploaded_file.txt", "w");
        if (!file) {
            log_error("error: %s", quic_error_message(quic_error));
            close_stream(ctx, connection, stream);
            close_connection(ctx, connection);
            return NULL;
        }

        char buffer[60000 + 1];
        time_t timeout = 30;
        while ((len = recv_data(ctx, connection, stream, buffer, 60000, 0)) > 0) {
            buffer[len] = '\0';
            log_info("received data: %.*s", (int)len, buffer);
            log_info("len: %ld", len);
            
            // check if the contains EOF some where in the buffer
            if (strstr(buffer, "EOF") != NULL) {
                fwrite(buffer, sizeof(char), len - 3, file);
                break;
            }
            size_t written = fwrite(buffer, sizeof(char), len, file);
            if (written != len) {
                log_error("error writing to file");
                perror("fwrite");
                fclose(file);
                exit(EXIT_FAILURE);
            }
        }
        fclose(file);
        log_info("file upload completed");
    } else if (strcmp(control_message, CONTROL_DOWNLOAD) == 0) {
        log_info("handling file download");

        size_t len;
        char file_path[256];
        len = (size_t)recv_data(ctx, connection, stream, (void *)file_path, sizeof(file_path), 0);
        if (len <= 0) {
            log_error("error: %s", quic_error_message(quic_error));
            close_stream(ctx, connection, stream);
            close_connection(ctx, connection);
            return NULL;
        }
        log_info("file path received: %s", file_path);

        // file_path as more size then needed, so we need to remove the extra bytes to fopen the file correctly
        file_path[len] = '\0';

        FILE *file = fopen(file_path, "r");
        if (!file) {
            log_error("error: failed to open file for writing");
            close_stream(ctx, connection, stream);
            close_connection(ctx, connection);
            return NULL;
        }

        char buffer[CHUNK_SIZE];
        while ((len = fread(buffer, sizeof(char), CHUNK_SIZE, file)) > 0) {
            log_info("read %zu bytes from file", len);
            log_info("sending: %s", buffer);
            send_data(ctx, connection, stream,(void *)buffer, len);
            memset(buffer, 0, CHUNK_SIZE);
        }
        send_data(ctx, connection, stream, (void *)"EOF", 3);
        fclose(file);
        log_info("file download completed");
    } else if (strcmp(control_message, CONTROL_SINGLE) == 0) {
        log_info("handling single send-receive");
        int error = 0;
        while (1)
        {
            char buffer[1024];
            ssize_t len = recv_data(ctx, connection, stream, buffer, sizeof(buffer), 0);
            if (len > 0)
            {
                log_debug("received data: %.*s", (int)len, buffer);
                log_debug("len: %ld", len);
                // if (strstr(buffer, "EOF") != NULL)
                // {
                //     // break;
                // }
            }
            else
            {
                log_error("error: %s", quic_error_message(quic_error));
                error = 0;
                break;
            }
            char *resp = "Hello, client!";
            int err = send_data(ctx, connection, stream, resp, strlen(resp));
            if (err < 0)
            {
                log_error("error: %s", quic_error_message(quic_error));
                break;
            }
            log_debug("data sent: %s", resp);
        }
    } else {
        log_info("error: unknown control message");
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

    // config_t *config = read_config("config.yaml");
    // if (!config)
    // {
    //     log_info("error: failed to read configuration file");
    //     exit(EXIT_FAILURE);
    // }
    config_t *config = NULL;

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
        log_info("created thread to handle connection");
        // Detach the thread so that it cleans up after itself
        pthread_detach(thread_id);
    }
    return 0;
}