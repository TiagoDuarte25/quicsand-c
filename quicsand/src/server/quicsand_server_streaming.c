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
#include <unistd.h>
#include "quicsand_api.h"

#include <openssl/sha.h>
#include <openssl/evp.h>

typedef struct {
    context_t ctx;
    connection_t connection;
    int duration;
} thread_data_t;

typedef struct {
    context_t ctx;
    connection_t connection;
    int stream_fd;
    int duration;
} thread_data_stream_t;

int random_data(size_t len, char **data) {
    *data = (char *)malloc(len);
    for (int i = 0; i < len; i++) {
        (*data)[i] = 'A' + (rand() % 26);
    }
    return 0;
}

// Function to convert binary data to a hexadecimal string
void bin_to_hex(const unsigned char *bin, size_t len, char *hex) {
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + (i * 2), "%02x", bin[i]);
    }
    hex[len * 2] = '\0';
}

void* handle_stream(void *arg) {
    thread_data_stream_t *data = (thread_data_stream_t *)arg;
    context_t ctx = data->ctx;
    connection_t connection = data->connection;
    int stream_fd = data->stream_fd;
    int duration = data->duration;
    log_debug("handling stream");

    char request[100];
    int bitrate;
    int len = read(stream_fd, request, sizeof(request));
    if (len <= 0) {
        log_error("failed to receive valid request");
        close(stream_fd);
        free(data);
        return NULL;
    }
    log_debug("bitrate request: %s", request);
    bitrate = atoi(request);

    // KB per s 
    int Kbytes_per_second = bitrate / 8;
    int bytes_per_second = Kbytes_per_second * 1024;
    size_t buffer_size = bytes_per_second / 20;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);


    time_t start_time = time(NULL);
    while (difftime(time(NULL), start_time) < duration) {
        char *buffer;
        random_data(buffer_size, &buffer);
        ssize_t sent = write(stream_fd, buffer, buffer_size);
        if (sent < 0) {
            log_error("error: %s", quic_error_message(quic_error));
            free(buffer);
            close(stream_fd);
            free(data);
            return NULL;
        }
        EVP_DigestUpdate(mdctx, buffer, buffer_size);
        free(buffer);
        log_debug("sent %zu bytes", sent);
        usleep(50000);
    }

    close(stream_fd);
    log_debug("stream closed");

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    unsigned char hash_hex[hash_len * 2 + 1];
    bin_to_hex(hash, hash_len, hash_hex);
    log_info("final hash: %s", hash_hex);

    free(data);
    return NULL;
}

void *handle_connection(void *arg) {
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
        stream_data->duration = data->duration;

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
    int factor = 1;
    int duration = 60;
    int port = 0;
    int opt;

    // Parse command-line arguments
    while ((opt = getopt(argc, argv, "c:k:i:p:l:m:d:")) != -1) {
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
        case 'm':
            factor = atoi(optarg);
            break;
        case 'd':
            duration = atoi(optarg);
            break;
        default:
            fprintf(stdout, "usage: %s -c <cert_path> -k <key_path> -i <ip_address> -p <port> -d <duration>", argv[0]);
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
        fprintf(fp, "usage: %s -c <cert_path> -k <key_path> -i <ip_address> -p <port> -d <duration>", argv[0]);
        exit(EXIT_FAILURE);
    }

    context_t ctx = create_quic_context(cert_path, key_path);
    log_debug("context created");
    bind_addr(ctx, ip_address, port);
    log_debug("bound address");
    set_listen(ctx);
    log_debug("listening");

    log_info("server running...");
    while (1) {
        log_debug("waiting for connection");
        connection_t connection = accept_connection(ctx, 0);
        if (!connection) {
            log_error("error: %s", quic_error_message(quic_error));
            continue;
        }
        log_debug("connection accepted");

        // Allocate memory for thread data
        thread_data_t *data = (thread_data_t *)malloc(sizeof(thread_data_t));
        data->ctx = ctx;
        data->connection = connection;
        data->duration = duration;

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