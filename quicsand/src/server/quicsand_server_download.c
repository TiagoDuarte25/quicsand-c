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

#include <errno.h>

#define CHUNK_SIZE 1024

typedef struct {
    context_t ctx;
    connection_t connection;
} thread_data_t;

typedef struct {
    int stream_fd;
} thread_data_stream_t;

void bin_to_hex(const unsigned char *bin, size_t bin_len, char *hex) {
    for (size_t i = 0; i < bin_len; i++) {
        sprintf(hex + (i * 2), "%02x", bin[i]);
    }
}

void* handle_stream(void *arg) {
    thread_data_stream_t *data = (thread_data_stream_t *)arg;
    int stream_fd = data->stream_fd;
    log_debug("handling stream");

    char file_path[256];
    if (read(stream_fd, file_path, sizeof(file_path)) < 0) {
        log_error("error: %s", strerror(errno));
        close(stream_fd);
        free(data);
        return NULL;
    }
    log_debug("file path: %s", file_path);

    // Open file for reading
    FILE *file = fopen(file_path, "r");
    if (!file) {
        log_error("failed to open file for reading");
        close(stream_fd);
        return NULL;
    }

    // Get file size
    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Send file size to the client
    if (write(stream_fd, &file_size, sizeof(size_t)) < 0) {
        log_error("error: %s", strerror(errno));
        fclose(file);
        close(stream_fd);
        return NULL;
    }

    EVP_MD_CTX *file_hash_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(file_hash_ctx, EVP_sha256(), NULL);

    char buffer[65536];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        // send data to the client
        size_t bytes_sent = 0;
        while (bytes_sent < bytes_read) {
            ssize_t len = write(stream_fd, buffer, bytes_read);
            if (len < 0) {
                log_error("error: %s", quic_error_message(quic_error));
                fclose(file);
                close(stream_fd);
                return NULL;
            }
            bytes_sent += len;
            EVP_DigestUpdate(file_hash_ctx, buffer, len);
        }
        log_debug("stream_fd %d: sent %zu bytes", stream_fd, bytes_sent);
    }
    fclose(file);
    log_info("file download completed");

    unsigned char file_hash[EVP_MAX_MD_SIZE];
    unsigned int file_hash_len;
    EVP_DigestFinal_ex(file_hash_ctx, file_hash, &file_hash_len);
    char file_hash_hex[file_hash_len * 2 + 1];
    bin_to_hex(file_hash, file_hash_len, file_hash_hex);
    log_info("file hash: %s", file_hash_hex);

    return NULL;
}

void *handle_connection(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;
    context_t ctx = data->ctx;
    connection_t connection = data->connection;
    log_debug("handling connection");

    while (1) {
        int stream_fd = accept_stream(ctx, connection);
        if (stream_fd < 0) {
            log_error("error: %s", quic_error_message(quic_error));
            continue;
        }
        log_debug("accepted stream %d", stream_fd);

        // Allocate memory for thread data
        thread_data_stream_t *stream_data = (thread_data_stream_t *)malloc(sizeof(thread_data_stream_t));
        stream_data->stream_fd = stream_fd;

        // Create a new thread to handle the stream
        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, handle_stream, (void *)stream_data) != 0) {
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

int main(int argc, char *argv[]) {
    char *cert_path = NULL;
    char *key_path = NULL;
    char *ip_address = NULL;
    char *log_file = NULL;
    int port = 0;
    int opt;

    // Parse command-line arguments
    while ((opt = getopt(argc, argv, "c:k:i:p:l:m:")) != -1) {
        switch (opt) {
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
    if (!cert_path || !key_path || !ip_address || port == 0) {
        fprintf(fp, "usage: %s -c <cert_path> -k <key_path> -i <ip_address> -p <port>", argv[0]);
        exit(EXIT_FAILURE);
    }

    context_t ctx = create_quic_context(cert_path, key_path);
    log_debug("context created");
    bind_addr(ctx, ip_address, port);
    log_debug("bound address");
    set_listen(ctx);
    log_debug("listening");

    char test_name[256];
    sscanf(log_file, "%[^_]_", test_name);

    // Ensure test_name is not too long
    if (strlen(test_name) > 246) {
        log_error("test name is too long");
        exit(EXIT_FAILURE);
    }

    log_info("server running...");
    while (1) {
        log_debug("waiting for connection");
        connection_t connection = accept_connection(ctx);
        if (!connection) {
            log_error("error: %s", quic_error_message(quic_error));
            continue;
        }
        log_debug("connection accepted %p", (void *)connection);

        // Allocate memory for thread data
        thread_data_t *data = (thread_data_t *)malloc(sizeof(thread_data_t));
        data->ctx = ctx;
        data->connection = connection;

        // Create a new thread to handle the connection
        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, handle_connection, (void *)data) != 0) {
            log_error("error: failed to create thread");
            free(data);
            continue;
        }
        // Detach the thread so that it cleans up after itself
        pthread_detach(thread_id);
    }
    return 0;
}