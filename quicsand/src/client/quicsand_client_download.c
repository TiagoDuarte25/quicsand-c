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

void bin_to_hex(const unsigned char *bin, size_t bin_len, char *hex) {
    for (size_t i = 0; i < bin_len; i++) {
        sprintf(hex + (i * 2), "%02x", bin[i]);
    }
}

void *download_file(void *args) {
    struct args *arguments = (struct args *)args;
    FILE *fp = arguments->fp;
    char *ip_address = arguments->ip_address;
    int port = arguments->port;
    char *file_path = arguments->file_path;

    log_info("starting file download");

    context_t ctx = create_quic_context(NULL, NULL);
    log_debug("context created");
    connection_t connection = open_connection(ctx, ip_address, port);
    log_debug("connection opened");

    // open a new stream
    int stream_fd = open_stream(ctx, connection);
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

    statistics_t stats;
    get_conneciton_statistics(ctx, connection, &stats);

    close_connection(ctx, connection);

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
  arguments->fp = fp;
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