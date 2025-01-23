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

#include <openssl/sha.h>
#include <openssl/evp.h>

typedef struct {
    context_t ctx;
    connection_t connection;
    int factor;
    char* filename;
} thread_data_t;

typedef struct {
    context_t ctx;
    connection_t connection;
    int stream_fd;
    int factor;
    char* filename;
} thread_data_stream_t;

// Function to convert binary data to a hexadecimal string
void bin_to_hex(const unsigned char *bin, size_t len, char *hex) {
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + (i * 2), "%02x", bin[i]);
    }
    hex[len * 2] = '\0';
}

void* handle_stream(void * arg) {
    thread_data_stream_t *data = (thread_data_stream_t *)arg;
    context_t ctx = data->ctx;
    connection_t connection = data->connection;
    int stream_fd = data->stream_fd;
    char* filename = data->filename;

    log_debug("handling stream");
    
    // Receive the file size from the client
    size_t file_size;
    if (read(stream_fd, &file_size, sizeof(file_size)) != sizeof(file_size)) {
        log_error("failed to receive file size");
        close(stream_fd);
        return NULL;
    }
    log_debug("file size received: %lu", file_size);

    // Open file for writing
    FILE *file = fopen(filename, "w");
    if (!file) {
        log_error("failed to open file for writing");
        close(stream_fd);
        return NULL;
    }

    EVP_MD_CTX *file_hash_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(file_hash_ctx, EVP_sha256(), NULL);

    char buffer[65536];
    size_t bytes_read = 0;
    while (bytes_read < file_size) {
        // receive data from the client
        size_t len = read(stream_fd, buffer, sizeof(buffer));
        log_debug("received %lu bytes", len);
        if (len > 0) {
            // Write received data to file
            fwrite(buffer, sizeof(char), len, file);
            log_debug("data written to file");
            // Update the hash
            EVP_DigestUpdate(file_hash_ctx, buffer, len);
        } else {
            break;
        }
        bytes_read += len;
        log_debug("total bytes read: %lu", bytes_read);
    }
    fflush(file);
    fclose(file);

    // Calculate the hash of the file
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    EVP_DigestFinal_ex(file_hash_ctx, hash, &hash_len);
    char hash_hex[hash_len * 2 + 1];
    bin_to_hex(hash, hash_len, hash_hex);
    log_info("file hash: %s", hash_hex);

    // send information of file upload completion
    char response[32];
    snprintf(response, sizeof(response), "file uploaded: %zu bytes", file_size);
    write(stream_fd, response, strlen(response) + 1);
    log_debug("response sent: %s", response);
    
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
        stream_data->filename = data->filename;

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
    char *test_name = NULL;
    int factor = 1;
    int port = 0;
    int opt;

    // Parse command-line arguments
    while ((opt = getopt(argc, argv, "c:k:i:p:l:m:t:")) != -1)
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
        case 't':
            test_name = strdup(optarg);
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
    if (log_add_fp(fp, LOG_INFO) != 0) {
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

    // Ensure test_name is not too long
    if (strlen(test_name) > 246) {
        log_error("test name is too long");
        exit(EXIT_FAILURE);
    }

    // Create the file name
    char filename[256] = "";
    strcat(filename, test_name);
    strcat(filename, ".txt");
    log_debug("filename: %s", filename);

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
        data->filename = filename;

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