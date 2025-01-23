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
  size_t data_size;
  double duration;
  int bitrate;
};

// Function to convert binary data to a hexadecimal string
void bin_to_hex(const unsigned char *bin, size_t len, char *hex) {
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + (i * 2), "%02x", bin[i]);
    }
    hex[len * 2] = '\0';
}

void *stream_data(void *args) {
    struct args *arguments = (struct args *)args;
    FILE *fp = arguments->fp;
    char *ip_address = arguments->ip_address;
    int port = arguments->port;
    int bitrate = arguments->bitrate;

    log_info("starting streaming client");

    context_t ctx = create_quic_context(NULL, NULL);
    log_debug("context created");
    connection_t connection = open_connection(ctx, ip_address, port);
    log_debug("connection opened");

    // open a new stream
    int stream_fd = open_stream(ctx, connection);
    log_debug("stream opened");

    // Send the "bitrate" string
    char *request = "%d";
    dprintf(stream_fd, request, bitrate);
    write(stream_fd, request, strlen(request));
    log_debug("sent request: %s", request);

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);

    // Receive streaming data
    static char buffer[65536];
    size_t bytes_received;
    while ((bytes_received = read(stream_fd, buffer, sizeof(buffer))) > 0) {
        EVP_DigestUpdate(mdctx, buffer, bytes_received);
        log_debug("received data: %zu bytes", bytes_received);
    }

    // Close the connection
    close_connection(ctx, connection);

    log_info("streaming client completed");
    
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    unsigned char hash_hex[hash_len * 2 + 1];
    bin_to_hex(hash, hash_len, hash_hex);
    log_info("final hash: %s", hash_hex);

    statistics_t stats;
    get_conneciton_statistics(ctx, connection, &stats);

    fprintf(fp, "\n");
    fprintf(fp, "\n");
    fprintf(fp, "-------------- Statistics --------------\n");
    fprintf(fp, "rtt: %d ms\n", stats.avg_rtt);
    fprintf(fp, "max_rtt: %d ms\n", stats.max_rtt);
    fprintf(fp, "min_rtt: %d ms\n", stats.min_rtt);
    fprintf(fp, "total_sent_packets: %d\n", stats.total_sent_packets);
    fprintf(fp, "total_received_packets: %d\n", stats.total_received_packets);
    fflush(fp);

    return NULL;
}

int main(int argc, char *argv[]) {
  char *ip_address = NULL;
  char *file_path = NULL;
  char *log_file = NULL;
  int port = 0;
  int duration = 0;
  int data_size = 0;
  int bitrate = 0;
  int opt;

  fprintf(stdout, "quicsand client\n");

  // Parse command-line arguments
  while ((opt = getopt(argc, argv, "i:p:f:d:s:l:b:")) != -1) {
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
            case 'd':
            duration = atoi(optarg);
            break;
            case 's':
            data_size = atoi(optarg);
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
  fprintf(stdout, "file_path: %s\n", file_path);
  fprintf(stdout, "duration: %d\n", duration);
  fprintf(stdout, "data_size: %d\n", data_size);
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
  arguments->fp = fp;
  arguments->ip_address = ip_address;
  arguments->port = port;
  arguments->file_path = file_path;
  arguments->duration = duration;
  arguments->bitrate = bitrate;
  stream_data(arguments);

  free(ip_address);
  free(file_path);
  fclose(fp);
}