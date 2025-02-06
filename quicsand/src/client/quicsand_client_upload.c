#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h> // inet_addr()
#include <sys/times.h>
#include <sys/resource.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <stdio.h>
#include <time.h>
#include <thpool.h>

#include "quicsand_api.h"
#include "log.h"
#include <bits/time.h>

#include <openssl/sha.h>
#include <openssl/evp.h>

struct args {
  FILE *fp;
  char *ip_address;
  int port;
  char *file_path;
};

// Function to convert binary data to a hexadecimal string
void bin_to_hex(const unsigned char *bin, size_t len, char *hex) {
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + (i * 2), "%02x", bin[i]);
    }
    hex[len * 2] = '\0';
}

void *upload_file(void *args) {
    struct args *arguments = (struct args *)args;
    FILE *fp = arguments->fp;
    char *ip_address = arguments->ip_address;
    int port = arguments->port;
    char *file_path = arguments->file_path;

    log_info("starting file upload");

    context_t ctx = create_quic_context(NULL, NULL);
    log_debug("context created");
    connection_t connection = open_connection(ctx, ip_address, port);
    log_debug("connection opened");

    FILE *file = fopen(file_path, "r");
    if (!file) {
        log_error("failed to open file: %s", file_path);
        return NULL;
    }

    // get the file size
    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    EVP_MD_CTX *file_hash_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(file_hash_ctx, EVP_sha256(), NULL);

    // open a new stream
    int stream_fd = open_stream(ctx, connection);
    log_debug("stream opened");

    // send the file size
    log_debug("file size: %lu", file_size);
    if (write(stream_fd, &file_size, sizeof(file_size)) != sizeof(file_size)) {
        log_error("failed to send file size");
        close(stream_fd);
        fclose(file);
        return NULL;
    }
    log_debug("file size sent: %lu", file_size);

    size_t bytes_sent = 0;
    static char buffer[65536];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        // send data to the server
        write(stream_fd, buffer, bytes_read);
        EVP_DigestUpdate(file_hash_ctx, buffer, bytes_read);
        log_debug("data sent: %zu bytes", bytes_read);
        bytes_sent += bytes_read;
        log_debug("total bytes sent: %d", bytes_sent);
    }
    fclose(file);

    // receive information of file upload completion
    char response[32];
    read(stream_fd, response, sizeof(response));
    log_info("server response: %s", response);

    //close the stream
    close(stream_fd);

    // close_connection(ctx, connection);

    log_info("file upload completed");

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    EVP_DigestFinal_ex(file_hash_ctx, hash, &hash_len);
    char hash_hex[hash_len * 2 + 1];
    bin_to_hex(hash, hash_len, hash_hex);
    log_info("file hash: %s", hash_hex);

    statistics_t stats;
    get_conneciton_statistics(ctx, connection, &stats);

    fprintf(fp, "\n");
    fprintf(fp, "\n");
    fprintf(fp, "-------------- Applicational Statistics --------------\n");
    fprintf(fp, "total bytes sent: %ld\n", file_size);
    fprintf(fp, "\n");
    fprintf(fp, "-------------- Protocol Statistics --------------\n");
    fprintf(fp, "rtt: %ld ms\n", stats.avg_rtt);
    fprintf(fp, "total sent packets: %ld\n", stats.total_sent_packets);
    fprintf(fp, "total received packets: %ld\n", stats.total_received_packets);
    fprintf(fp, "packet loss (%c): %ld\n", '%', (size_t)((stats.total_lost_packets / stats.total_sent_packets) * 100));
    fprintf(fp, "retransmitted packets: %ld\n", stats.total_retransmitted_packets);
    fprintf(fp, "total bytes sent: %ld\n", stats.total_sent_bytes);
    fprintf(fp, "total bytes received: %ld\n", stats.total_received_bytes);

    return NULL;
}

int main(int argc, char *argv[]) {
    char *ip_address = NULL;
    char *file_path = NULL;
    char *log_file = NULL;
    int port = 0;
    int opt;

    // Parse command-line arguments
    while ((opt = getopt(argc, argv, "i:p:f:d:s:l:")) != -1) {
        switch (opt) {
                case 'i':
                ip_address = strdup(optarg);
                break;
                case 'p':
                port = atoi(optarg);
                break;
                case 'f':
                file_path = strdup(optarg);
                break;
                case 'l':
                log_file = strdup(optarg);
                break;
            default:
                fprintf(stdout, "usage: %s -i <ip_address> -p <port> [-f <file_path>]", argv[0]);
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

    // Check if required arguments are provided
    if (ip_address == NULL || port == 0) {
        log_info("usage: %s -i <ip_address> -p <port> [-f <file_path>]", argv[0]);
        fclose(fp);
        return EXIT_FAILURE;
    }

    log_info("starting client");

    struct args *arguments = (struct args *)malloc(sizeof(struct args));
    arguments->fp = fp;
    arguments->ip_address = ip_address;
    arguments->port = port;
    arguments->file_path = file_path;
    upload_file(arguments);

    log_info("client finished");
    fclose(fp);

    return 0;
}