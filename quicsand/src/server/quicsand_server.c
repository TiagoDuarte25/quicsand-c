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
                    fprintf(stderr, "Received data: %s\n", buffer);
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