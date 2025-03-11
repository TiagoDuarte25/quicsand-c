#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h> // inet_addr()
#include <sys/times.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <stdio.h>
#include <time.h>

#include "quicsand_api.h"
#include "log.h"
#include <bits/time.h>

#include <openssl/sha.h>
#include <openssl/evp.h>

struct args {
  char *ip_address;
  int port;
  char *file_path;
  size_t data_size;
  double duration;
  int bitrate;
};

// Function to check if the file is empty
bool is_file_empty(FILE *file) {
    long saved_offset = ftell(file);
    fseek(file, 0, SEEK_END);
    bool is_empty = (ftell(file) == 0);
    fseek(file, saved_offset, SEEK_SET);
    return is_empty;
}

void write_metrics_to_csv(int rtt, int total_bytes_sent, int total_bytes_received, 
                          double cpu_time_used, struct rusage usage_diff, statistics_t *stats) {
    
    FILE *fp = fopen("client.csv", "a");
    if (!fp) {
        perror("Failed to open log file");
        return;
    }

    // Check if the file is empty and write the header if it is
    if (is_file_empty(fp)) {
        fprintf(fp, "rtt,total_bytes_sent,total_bytes_received,cpu_time_used,user_cpu_time_used,system_cpu_time_used,max_resident_set_size,avg_rtt,max_rtt,min_rtt,packet_loss,retransmitted_packets,total_sent_bytes,total_received_bytes\n");
    }

    // Write the metrics
    fprintf(fp, "%d,%d,%d,%f,%ld.%06ld,%ld.%06ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld\n",
            rtt, total_bytes_sent, total_bytes_received, cpu_time_used,
            usage_diff.ru_utime.tv_sec, usage_diff.ru_utime.tv_usec,
            usage_diff.ru_stime.tv_sec, usage_diff.ru_stime.tv_usec,
            usage_diff.ru_maxrss, stats->avg_rtt, stats->max_rtt, stats->min_rtt,
            (size_t)((stats->total_lost_packets / stats->total_sent_packets) * 100),
            stats->total_retransmitted_packets, stats->total_sent_bytes, stats->total_received_bytes);
    
    fclose(fp);
}

// Function to convert binary data to a hexadecimal string
void bin_to_hex(const unsigned char *bin, size_t len, char *hex) {
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + (i * 2), "%02x", bin[i]);
    }
    hex[len * 2] = '\0';
}

void *stream_data(void *args) {
    struct args *arguments = (struct args *)args;
    char *ip_address = arguments->ip_address;
    int port = arguments->port;
    int bitrate = arguments->bitrate;

    log_info("starting streaming client");

    clock_t start_time, end_time;
    start_time = clock();

    // Capture resource usage before create_quic_context
    struct rusage usage_start;
    getrusage(RUSAGE_SELF, &usage_start);

    context_t ctx = create_quic_context(NULL, NULL);
    if (ctx == NULL) {
        log_error("failed to create context");
        return NULL;
    }
    log_debug("context created");

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    connection_t connection = open_connection(ctx, ip_address, port);
    if (connection == NULL) {
        log_error("failed to open connection");
        return NULL;
    }
    log_debug("connection opened");

    // open a new stream
    int stream_fd = open_stream(ctx, connection);
    if (stream_fd < 0) {
        log_error("failed to open stream");
        return NULL;
    }
    log_debug("stream opened");

    // Send the "bitrate" string
    char request[32];
    snprintf(request, sizeof(request), "%d", bitrate);
    write(stream_fd, request, strlen(request));
    log_debug("sent request: %s", request);

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);

    // Receive streaming data
    static char buffer[65536];
    ssize_t total_bytes_received = 0;
    ssize_t bytes_received;
    while ((bytes_received = read(stream_fd, buffer, sizeof(buffer))) > 0) {
        EVP_DigestUpdate(mdctx, buffer, bytes_received);
        log_debug("received data: %zu bytes", bytes_received);
        total_bytes_received += bytes_received;
    }

    log_info("streaming client completed");
    
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    char hash_hex[hash_len * 2 + 1];
    bin_to_hex(hash, hash_len, hash_hex);
    log_info("final hash: %s", hash_hex);

    EVP_MD_CTX_free(mdctx);

    clock_gettime(CLOCK_MONOTONIC, &end);
    // Calculate the elapsed time
    double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    log_info("elapsed time: %f seconds", elapsed);

    statistics_t stats;
    get_connection_statistics(ctx, connection, &stats);

    close_connection(ctx, connection);

    end_time = clock();
    double cpu_time_used = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;

    // Capture resource usage before printing statistics
    struct rusage usage_end;
    getrusage(RUSAGE_SELF, &usage_end);

    // Calculate the difference in resource usage
    struct rusage usage_diff;
    timersub(&usage_end.ru_utime, &usage_start.ru_utime, &usage_diff.ru_utime);
    timersub(&usage_end.ru_stime, &usage_start.ru_stime, &usage_diff.ru_stime);
    usage_diff.ru_maxrss = usage_end.ru_maxrss - usage_start.ru_maxrss;
    usage_diff.ru_ixrss = usage_end.ru_ixrss - usage_start.ru_ixrss;
    usage_diff.ru_idrss = usage_end.ru_idrss - usage_start.ru_idrss;
    usage_diff.ru_isrss = usage_end.ru_isrss - usage_start.ru_isrss;

    write_metrics_to_csv(-1, -1, total_bytes_received, cpu_time_used, usage_diff, &stats);

    destroy_quic_context(ctx);

    return NULL;
}

int main(int argc, char *argv[]) {
    char *ip_address = NULL;
    char *log_file = NULL;
    int port = 0;
    int duration = 0;
    int bitrate = 0;
    int opt;

    fprintf(stdout, "quicsand client\n");

    // Parse command-line arguments
    while ((opt = getopt(argc, argv, "i:p:d:l:b:")) != -1) {
        switch (opt) {
            case 'i':
            ip_address = strdup(optarg);
            break;
            case 'p':
            port = atoi(optarg);
            break;
            case 'd':
            duration = atoi(optarg);
            break;
            case 'l':
            log_file = strdup(optarg);
            break;
            case 'b':
            bitrate = atoi(optarg);
            break;
            default:
            fprintf(stdout, "usage: %s -i <ip_address> -p <port> [-f <file_path>]", argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    fprintf(stdout, "ip_address: %s\n", ip_address);
    fprintf(stdout, "port: %d\n", port);
    fprintf(stdout, "duration: %d\n", duration);
    fprintf(stdout, "log_file: %s\n", log_file);
    fprintf(stdout, "bitrate: %d\n", bitrate);

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

    // Check if required arguments are provided
    if (ip_address == NULL || port == 0) {
        log_info("usage: %s -i <ip_address> -p <port> [-f <file_path>]", argv[0]);
        fclose(fp);
        return EXIT_FAILURE;
    }

    log_info("starting client");

    struct args *arguments = (struct args *)malloc(sizeof(struct args));
    arguments->ip_address = ip_address;
    arguments->port = port;
    arguments->duration = duration;
    arguments->bitrate = bitrate;
    stream_data(arguments);

    free(ip_address);
    free(arguments);
    free(log_file);
    fclose(fp);
}