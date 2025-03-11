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

#include <openssl/evp.h>
#include <openssl/sha.h>

struct args {
  char *ip_address;
  int port;
  char *file_path;
  size_t data_size;
  double duration;
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

int random_data(size_t len, char **data) {
    *data = (char *)malloc(len);
    if (*data == NULL) {
        return -1; // Return an error if memory allocation fails
    }
    for (size_t i = 0; i < len - 1; i++) {
        (*data)[i] = 'A' + (rand() % 26);
    }
    (*data)[len - 1] = '\0';
    return 0;
}

// Function to convert binary data to a hexadecimal string
void bin_to_hex(const unsigned char *bin, size_t len, char *hex) {
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + (i * 2), "%02x", bin[i]);
    }
    hex[len * 2] = '\0';
}

void * request_response_test(void *args) {
    struct args *arguments = (struct args *)args;
    char *ip_address = arguments->ip_address;
    int port = arguments->port;
    size_t data_size = arguments->data_size;
    double duration = arguments->duration;

    int sum_rtt = 0;
    int num_requests = 0;
    int rtt = 0;
    struct timespec rtt_start, rtt_end;

    log_info("testing request/response communication");

    clock_t start_time, end_time;
    start_time = clock();

    // Capture resource usage before create_quic_context
    struct rusage usage_start;
    getrusage(RUSAGE_SELF, &usage_start);

    struct timespec start, current;
    double elapsed_time = 0;
    context_t ctx = create_quic_context(NULL, NULL);
    if (ctx == NULL) {
        log_error("failed to create context");
        return NULL;
    }
    log_debug("context created");
    connection_t connection = open_connection(ctx, ip_address, port);
    if (connection == NULL) {
        log_error("failed to open connection");
        return NULL;
    }
    log_debug("connection opened");
    char buffer[65536];

    // Initialize the SHA-256 context
    EVP_MD_CTX *req_sha256_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(req_sha256_ctx, EVP_sha256(), NULL);

    EVP_MD_CTX *res_sha256_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(res_sha256_ctx, EVP_sha256(), NULL);

    // Start the timer
    clock_gettime(CLOCK_MONOTONIC, &start);
    int total_bytes_sent = 0;
    int total_bytes_received = 0;
    while (elapsed_time < duration) {
        num_requests++;
        // open a new stream
        int stream_fd = open_stream(ctx, connection);
        if (stream_fd < 0) {
            log_error("failed to open stream");
            return NULL;
        }
        log_debug("stream opened");

        // generate random data
        char *data;
        random_data(data_size, &data);

        EVP_DigestUpdate(req_sha256_ctx, data, data_size);

        // start the round-trip timer
        clock_gettime(CLOCK_MONOTONIC, &rtt_start);

        // send data to the server
        int wrote = write(stream_fd, data, data_size);
        if (wrote < 0) {
            log_error("failed to write data to the stream");
            return NULL;
        }
        total_bytes_sent += wrote;
        log_debug("sent %d bytes", data_size);

        // receive data from the server
        size_t total_received = 0;
        ssize_t len;
        while ((len = read(stream_fd, buffer, sizeof(buffer))) > 0) {
            EVP_DigestUpdate(res_sha256_ctx, buffer, len);
            total_received += len;
            total_bytes_received += len;
            log_debug("received_bytes=%d, total_bytes_received=%d", len, total_received);
        }
        if (len <= 0) {
            log_debug("stream closed by server");
        }

        // calculate round-trip time
        clock_gettime(CLOCK_MONOTONIC, &rtt_end);

        free(data);

        // Sleep for a short duration to avoid tight loop
        usleep(500000); // 500 milliseconds

        // Update the elapsed time
        clock_gettime(CLOCK_MONOTONIC, &current);
        elapsed_time = (current.tv_sec - start.tv_sec) + (current.tv_nsec - start.tv_nsec) / 1e9;
        sum_rtt += (rtt_end.tv_sec - rtt_start.tv_sec) * 1000 + (rtt_end.tv_nsec - rtt_start.tv_nsec) / 1e6;
    }

    // Get connection statistics
    statistics_t stats;
    get_connection_statistics(ctx, connection, &stats);

    close_connection(ctx, connection);

    // Finalize the SHA-256 hash
    unsigned char req_hash[SHA256_DIGEST_LENGTH];
    EVP_DigestFinal_ex(req_sha256_ctx, req_hash, NULL);

    unsigned char res_hash[SHA256_DIGEST_LENGTH];
    EVP_DigestFinal_ex(res_sha256_ctx, res_hash, NULL);

    // Convert hashes to hexadecimal strings
    char req_hash_hex[SHA256_DIGEST_LENGTH * 2 + 1];
    char res_hash_hex[SHA256_DIGEST_LENGTH * 2 + 1];
    bin_to_hex(req_hash, SHA256_DIGEST_LENGTH, req_hash_hex);
    bin_to_hex(res_hash, SHA256_DIGEST_LENGTH, res_hash_hex);

    log_info("request hash: %s", req_hash_hex);
    log_info("response hash: %s", res_hash_hex);
    log_info("end of test");

    rtt = sum_rtt / num_requests;

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

    write_metrics_to_csv(rtt, total_bytes_sent, total_bytes_received, cpu_time_used, usage_diff, &stats);

    EVP_MD_CTX_free(req_sha256_ctx);
    EVP_MD_CTX_free(res_sha256_ctx);

    // Destroy the QUIC context
    destroy_quic_context(ctx);

    return NULL;
}

int main(int argc, char *argv[]) {
  char *ip_address = NULL;
  char *log_file = NULL;
  int port = 0;
  int duration = 0;
  int data_size = 0;
  int opt;

  fprintf(stdout, "quicsand client\n");

  // Parse command-line arguments
  while ((opt = getopt(argc, argv, "i:p:f:d:s:l:")) != -1) {
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
            case 's':
            data_size = atoi(optarg);
            break;
            case 'l':
            log_file = strdup(optarg);
            break;
          default:
            fprintf(stdout, "usage: %s -i <ip_address> -p <port>", argv[0]);
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
  arguments->data_size = data_size;
  request_response_test(arguments);

  log_info("client finished");

  free(ip_address);
  free(arguments);
  free(log_file);
  fclose(fp);
  
  return 0;
}