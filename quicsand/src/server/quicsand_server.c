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
#include <log.h>
#include "quicsand_api.h"
#include "utils.h"

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
    FILE *fp;
} thread_data_t;

void send_control_message(context_t ctx, connection_t connection, const char *message) {
    stream_t stream = open_stream(ctx, connection);
    send_data(ctx, connection, stream, (void *)message, strlen(message) + 1); // +1 to include null terminator
    close_stream(ctx, connection, stream);
}

void upload_file(context_t ctx, connection_t connection, const char *file_path) {
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        fprintf(stderr, "Error: Failed to open file %s\n", file_path);
        return;
    }

    stream_t stream = open_stream(ctx, connection);
    char buffer[CHUNK_SIZE];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, CHUNK_SIZE, file)) > 0) {
        send_data(ctx, connection, stream, buffer, bytes_read);
    }

    fclose(file);
    close_stream(ctx, connection, stream);
}

void download_file(context_t ctx, connection_t connection, const char *file_path) {
    FILE *file = fopen(file_path, "wb");
    if (!file) {
        fprintf(stderr, "Error: Failed to open file for writing\n");
        return;
    }

    stream_t stream = open_stream(ctx, connection);
    char buffer[CHUNK_SIZE];
    ssize_t len;
    while ((len = recv_data(ctx, connection, buffer, sizeof(buffer), 0)) > 0) {
        fwrite(buffer, 1, len, file);
    }

    fclose(file);
    close_stream(ctx, connection, stream);
}

void single_send_receive(context_t ctx, connection_t connection) {
    stream_t stream = open_stream(ctx, connection);
    send_data(ctx, connection, stream, "Hello, server!", 14);
    char buffer[CHUNK_SIZE];
    ssize_t len = recv_data(ctx, connection, buffer, sizeof(buffer), 0);
    if (len > 0) {
        buffer[len] = '\0';
        printf("Received from server: %s\n", buffer);
    }
    close_stream(ctx, connection, stream);
}

void *handle_connection(void *arg)
{
    thread_data_t *data = (thread_data_t *)arg;
    context_t ctx = data->ctx;
    connection_t connection = data->connection;
    FILE *fp = data->fp;
    fprintf(fp, "Handling connection\n");

    stream_t stream = accept_stream(ctx, connection, 0);
    fprintf(fp, "Accepted stream\n");
    fflush(fp);

    // Receive control message
    char control_message[256];
    ssize_t len = recv_data(ctx, connection, control_message, sizeof(control_message), 0);
    if (len <= 0) {
        fprintf(fp, "Error: Failed to receive control message\n");
        close_stream(ctx, connection, stream);
        close_connection(ctx, connection);
        return NULL;
    }
    fprintf(fp, "Received control message: %s\n", control_message);
    send_data(ctx, connection, stream, control_message, len);
    fflush(fp);

    // Handle control message
    if (strcmp(control_message, CONTROL_UPLOAD) == 0) {
        fprintf(fp, "Handling file upload\n");
        fflush(fp);
        FILE *file = fopen("uploaded_file.txt", "w");
        if (!file) {
            fprintf(fp, "Error: Failed to open file for writing\n");
            close_stream(ctx, connection, stream);
            close_connection(ctx, connection);
            return NULL;
        }

        char buffer[CHUNK_SIZE];
        while ((len = recv_data(ctx, connection, buffer, CHUNK_SIZE, 0)) > 0) {
            fprintf(fp, "Received data: %.*s\n", (int)len, buffer);
            fprintf(fp, "len: %ld\n", len);
            fflush(fp);
            size_t written = fwrite(buffer, sizeof(char), len, file);
            if (written != len) {
                fprintf(fp, "Error writing to file\n");
                perror("fwrite");
                fclose(file);
                exit(EXIT_FAILURE);
            }
            fflush(file);
        }
        
        fclose(file);
        fprintf(fp, "File upload completed\n");
        fflush(fp);
    } else if (strcmp(control_message, CONTROL_DOWNLOAD) == 0) {
        fprintf(fp, "Handling file download\n");
        fflush(fp);
        FILE *fp = fopen("downloaded_file.txt", "r");
        if (!fp) {
            fprintf(fp, "Error: Failed to open file for writing\n");
            close_stream(ctx, connection, stream);
            close_connection(ctx, connection);
            return NULL;
        }
        char buffer[CHUNK_SIZE];
        size_t len;
        while (len = fread(buffer, sizeof(char), CHUNK_SIZE, fp) > 0) {
            send_data(ctx, connection, stream, buffer, CHUNK_SIZE);
            sleep(1);
        }
        fclose(fp);
        fprintf(fp, "File download completed\n");
        fflush(fp);
    } else if (strcmp(control_message, CONTROL_SINGLE) == 0) {
        fprintf(fp, "Handling single send-receive\n");
        fflush(fp);
        while (1)
        {
            char buffer[1024];
            ssize_t len;
            ssize_t total_len = 0;
            while (1)
            {
                len = recv_data(ctx, connection, buffer + total_len, sizeof(buffer) - total_len, 0);
                if (len > 0)
                {
                    total_len += len;
                    // Ensure termination
                    if (total_len < 1024)
                    {
                        buffer[total_len] = '\0';
                    }
                    else
                    {
                        buffer[1024 - 1] = '\0';
                    }

                    // Check if the entire message has been received
                    if (buffer[total_len] == '\0')
                    {
                        fprintf(fp, "Received data: %s\n", buffer);
                        fflush(fp);
                        break;
                    }
                }
                else
                {
                    // Handle error or end of data
                    break;
                }
            }
            // send_data(ctx, connection, stream, random_data(200), 200);
            send_data(ctx, connection, stream, "Hello, client!", 14);
        }
    } else {
        fprintf(fp, "Error: Unknown control message\n");
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

    FILE *fp = fopen("server.log", "w+");

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
            fprintf(fp, "Usage: %s -c <cert_path> -k <key_path> -i <ip_address> -p <port>\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    // Print the parsed options for debugging
    fprintf(fp, "Certificate Path: %s\n", cert_path);
    fprintf(fp, "Key Path: %s\n", key_path);
    fprintf(fp, "IP Address: %s\n", ip_address);
    fprintf(fp, "Port: %d\n", port);
    fflush(fp);

    // Ensure required options are provided
    if (!cert_path || !key_path || !ip_address || port == 0)
    {
        fprintf(fp, "Usage: %s -c <cert_path> -k <key_path> -i <ip_address> -p <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    log_add_fp(fp, LOG_INFO);

    config_t *config = read_config("config.yaml");
    if (!config)
    {
        fprintf(fp, "Error: Failed to read configuration file\n");
        exit(EXIT_FAILURE);
    }

    context_t ctx = create_quic_context(cert_path, key_path);
    fprintf(fp, "Created context\n");
    bind_addr(ctx, ip_address, port);
    fprintf(fp, "Bound address\n");
    set_listen(ctx);
    fprintf(fp, "Listening\n");
    fflush(fp);

    while (1)
    {
        fprintf(fp, "Waiting for connection\n");
        fflush(fp);
        connection_t connection = accept_connection(ctx, 0);
        fprintf(fp, "Accepted connection\n");
        fflush(fp);

        // Allocate memory for thread data
        thread_data_t *data = (thread_data_t *)malloc(sizeof(thread_data_t));
        data->ctx = ctx;
        data->connection = connection;
        data->fp = fp;

        // Create a new thread to handle the connection
        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, handle_connection, (void *)data) != 0)
        {
            fprintf(fp, "Error: Failed to create thread\n");
            free(data);
            continue;
        }
        fprintf(fp, "Created thread that handle connections\n");
        fflush(fp);
        // Detach the thread so that it cleans up after itself
        pthread_detach(thread_id);
    }

    fclose(fp);
    return 0;
}