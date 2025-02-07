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

#include <openssl/evp.h>
#include <openssl/sha.h>

#include <errno.h>

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

// Function to convert binary data to a hexadecimal string
void bin_to_hex(const unsigned char *bin, size_t len, char *hex) {
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + (i * 2), "%02x", bin[i]);
    }
    hex[len * 2] = '\0';
}


int random_data(size_t len, char **data) {
    *data = (char *)malloc(len);
    for (size_t i = 0; i < len - 1; i++) {
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
    EVP_MD_CTX *req_sha256_ctx;
    EVP_MD_CTX *res_sha256_ctx;
} thread_data_stream_t;

void* handle_stream(void * arg) {
    thread_data_stream_t *data = (thread_data_stream_t *)arg;
    int stream_fd = data->stream_fd;
    EVP_MD_CTX *req_sha256_ctx = data->req_sha256_ctx;
    EVP_MD_CTX *res_sha256_ctx = data->res_sha256_ctx;

    log_debug("handling stream");
    while (1) {
        char buffer[65536];
        // receive data from the client
        ssize_t len = read(stream_fd, buffer, sizeof(buffer));
        if (len > 0) {
            EVP_DigestUpdate(req_sha256_ctx, buffer, len);
            log_debug("received %d bytes", len);

            // response size multiplied by factor
            size_t response_len = len * data->factor / 4; // 4 bytes per character
            char* response;
            random_data(response_len, &response);
            log_debug("generated response of %d bytes", response_len);
            EVP_DigestUpdate(res_sha256_ctx, response, response_len);
            // send the response in chunks
            size_t chunk_size = 65536;
            size_t bytes_sent = 0;
            while (bytes_sent < response_len) {
                ssize_t bytes_to_send = (response_len - bytes_sent) < chunk_size ? (response_len - bytes_sent) : chunk_size;
                
                // Ensure the response pointer is valid
                if (response == NULL) {
                    log_error("response pointer is NULL");
                    break;
                }

                // Log the current state before sending
                log_debug("sending chunk: bytes_sent=%zu, bytes_to_send=%zu, response_len=%zu", bytes_sent, bytes_to_send, response_len);

                // Ensure the pointer arithmetic is correct
                char *current_position = response + bytes_sent;
                if (current_position < response || current_position >= response + response_len) {
                    log_error("invalid pointer arithmetic: current_position=%p, response=%p, response_len=%zu", current_position, response, response_len);
                    break;
                }

                
                ssize_t result = write(stream_fd, current_position, bytes_to_send);
                if (result < 0) {
                    log_error("failed to send data: %s", strerror(errno));
                    break;
                }


                bytes_sent += result;
                log_debug("sent %zu bytes, total bytes sent: %zu", result, bytes_sent);
            }
            
            // close stream
            close(stream_fd);
            log_debug("stream closed");

            free(response);
            break;
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

    // Initialize the SHA-256 context
    EVP_MD_CTX *req_sha256_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(req_sha256_ctx, EVP_sha256(), NULL);

    EVP_MD_CTX *res_sha256_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(res_sha256_ctx, EVP_sha256(), NULL);
    
    int num_requests = 0;

    while (1) {

        log_debug("waiting for stream");
        int stream_fd = accept_stream(ctx, connection);
        log_debug("stream accepted");
        if (stream_fd < 0) {
            log_error("error: %s", quic_error_message(quic_error));
            // close_connection(ctx, connection);
            break;
        }

        num_requests++;

        // Allocate memory for thread data
        thread_data_stream_t *stream_data = (thread_data_stream_t *)malloc(sizeof(thread_data_stream_t));
        stream_data->stream_fd = stream_fd;
        stream_data->factor = data->factor;
        stream_data->req_sha256_ctx = req_sha256_ctx;
        stream_data->res_sha256_ctx = res_sha256_ctx;

        // Create a new thread to handle the stream
        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, handle_stream, (void *)stream_data) != 0)
        {
            log_error("error: failed to create thread");
            free(stream_data);
            break;
        }
        log_debug("created thread to handle stream");

        // Detach the thread so that it cleans up after itself
        pthread_detach(thread_id);
    }

    // Finalize the SHA-256 hash
    unsigned char req_hash[SHA256_DIGEST_LENGTH];
    unsigned char res_hash[SHA256_DIGEST_LENGTH];
    EVP_DigestFinal_ex(req_sha256_ctx, req_hash, NULL);
    EVP_DigestFinal_ex(res_sha256_ctx, res_hash, NULL);

    // Convert hashes to hexadecimal strings
    char req_hash_hex[SHA256_DIGEST_LENGTH * 2 + 1];
    char res_hash_hex[SHA256_DIGEST_LENGTH * 2 + 1];
    bin_to_hex(req_hash, SHA256_DIGEST_LENGTH, req_hash_hex);
    bin_to_hex(res_hash, SHA256_DIGEST_LENGTH, res_hash_hex);

    log_info("request hash: %s", req_hash_hex);
    log_info("response hash: %s", res_hash_hex);

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
        connection_t connection = accept_connection(ctx);
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