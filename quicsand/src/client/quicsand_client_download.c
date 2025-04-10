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
};

// Function to check if the file is empty
bool is_file_empty(FILE *file) {
    long saved_offset = ftell(file);
    fseek(file, 0, SEEK_END);
    bool is_empty = (ftell(file) == 0);
    fseek(file, saved_offset, SEEK_SET);
    return is_empty;
}

void write_metrics_to_csv(int app_throughput, int total_bytes_sent, int total_bytes_received, 
                          double cpu_time_used, struct rusage usage_diff, statistics_t *stats, double time) {
    
    FILE *fp = fopen("client.csv", "a");
    if (!fp) {
        perror("Failed to open log file");
        return;
    }

    // Check if the file is empty and write the header if it is
    if (is_file_empty(fp)) {
        fprintf(fp, "time,app_throughput,total_bytes_sent,total_bytes_received,cpu_time_used,user_cpu_time_used,system_cpu_time_used,max_resident_set_size,avg_rtt,max_rtt,min_rtt,packet_loss,retransmitted_packets,total_sent_bytes,total_received_bytes, throughput\n");
    }

    // Write the metrics
    fprintf(fp, "%f,%d,%d,%d,%f,%ld.%06ld,%ld.%06ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld, %d\n",
            time, app_throughput, total_bytes_sent, total_bytes_received, cpu_time_used,
            usage_diff.ru_utime.tv_sec, usage_diff.ru_utime.tv_usec,
            usage_diff.ru_stime.tv_sec, usage_diff.ru_stime.tv_usec,
            usage_diff.ru_maxrss, stats->avg_rtt, stats->max_rtt, stats->min_rtt,
            (size_t)((stats->total_lost_packets / stats->total_sent_packets) * 100),
            stats->total_retransmitted_packets, stats->total_sent_bytes, stats->total_received_bytes, (int)((stats->total_received_bytes / time) * 8));
    
    fclose(fp);
}

void bin_to_hex(const unsigned char *bin, size_t bin_len, char *hex) {
    for (size_t i = 0; i < bin_len; i++) {
        sprintf(hex + (i * 2), "%02x", bin[i]);
    }
}

void *download_file(void *args) {
    struct args *arguments = (struct args *)args;
    char *ip_address = arguments->ip_address;
    int port = arguments->port;
    char *file_path = arguments->file_path;

    log_info("starting file download");

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

    write(stream_fd, file_path, strlen(file_path) + 1);

    // get the file name from the path in the last part of the path
    char *file_name = strrchr(file_path, '/');
    if (file_name == NULL) {
        file_name = file_path;
    } else {
        file_name++;
    }

    FILE *file = fopen(file_name, "w");
    if (!file) {
        log_error("failed to open file: %s", file_name);
        return NULL;
    }

    ssize_t file_size;
    ssize_t len = read(stream_fd, &file_size, sizeof(size_t));
    if (len < 0) {
        log_error("error: %s", quic_error_message(quic_error));
        fclose(file);
        close(stream_fd);
        return NULL;
    }
    log_debug("file size: %ld", file_size);

    EVP_MD_CTX *file_hash_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(file_hash_ctx, EVP_sha256(), NULL);

    static char buffer[65536];
    ssize_t total_bytes_read = 0;
    while (total_bytes_read < file_size) {
        ssize_t bytes_read = read(stream_fd, buffer, sizeof(buffer));
        if (bytes_read < 0) {
            log_error("error: %s", quic_error_message(quic_error));
            fclose(file);
            close(stream_fd);
            return NULL;
        }
        total_bytes_read += bytes_read;
        fwrite(buffer, 1, bytes_read, file);
        EVP_DigestUpdate(file_hash_ctx, buffer, bytes_read);
        log_debug("bytes_read=%ld, total_bytes_read=%ld", bytes_read, total_bytes_read);
    }

    fclose(file);

    //close the stream
    close(stream_fd);

    log_info("file download completed");

    unsigned char file_hash[EVP_MAX_MD_SIZE];
    unsigned int file_hash_len;
    EVP_DigestFinal_ex(file_hash_ctx, file_hash, &file_hash_len);
    char file_hash_hex[file_hash_len * 2 + 1];
    bin_to_hex(file_hash, file_hash_len, file_hash_hex);
    log_info("file hash: %s", file_hash_hex);

    EVP_MD_CTX_free(file_hash_ctx);

    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    log_debug("elapsed time: %f seconds", elapsed);

    statistics_t stats;
    get_connection_statistics(ctx, connection, &stats);

    log_debug("closing connection");
    close_connection(ctx, connection);
    log_debug("connection closed");

    end_time = clock();
    double cpu_time_used = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;

    int throughput = (int)(file_size / elapsed) * 8;

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

    write_metrics_to_csv(throughput, -1, total_bytes_read, cpu_time_used, usage_diff, &stats, elapsed);

    destroy_quic_context(ctx);

    return NULL;
}

int main(int argc, char *argv[]) {
  char *ip_address = NULL;
  char *file_path = NULL;
  char *log_file = NULL;
  int port = 0;
  int opt;

  fprintf(stdout, "quicsand client\n");

  // Parse command-line arguments
  while ((opt = getopt(argc, argv, "i:p:f:l:")) != -1) {
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
  arguments->file_path = file_path;
  download_file(arguments);

  free(ip_address);
  free(file_path);
  free(arguments);
  free(log_file);
  fclose(fp);
  return 0;
}