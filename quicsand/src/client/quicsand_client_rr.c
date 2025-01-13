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

struct args {
  FILE *fp;
  char *ip_address;
  int port;
  char *file_path;
  size_t data_size;
  double duration;
};

int random_data(size_t len, char **data) {
    *data = (char *)malloc(len);
    for (size_t i = 0; i < len - 1; i++) {
        (*data)[i] = 'A' + (rand() % 26);
    }
    (*data)[len - 1] = '\0';
    return 0;
}

void * request_response_test(void *args) {
    struct args *arguments = (struct args *)args;
    FILE *fp = arguments->fp;
    char *ip_address = arguments->ip_address;
    int port = arguments->port;
    char *file_path = arguments->file_path;
    size_t data_size = arguments->data_size;
    double duration = arguments->duration;

    int sum_rtt = 0;
    int num_requests = 0;
    int rtt = 0;
    struct timespec rtt_start, rtt_end;

    log_info("testing request/response communication");

    struct timespec start, current;
    double elapsed_time = 0;
    context_t ctx = create_quic_context(NULL, NULL);
    log_debug("context created");
    connection_t connection = open_connection(ctx, ip_address, port);
    log_debug("connection opened");
    char buffer[65536];

    // Start the timer
    clock_gettime(CLOCK_MONOTONIC, &start);
    while (elapsed_time < duration) {
        num_requests++;
        // start the round-trip timer
        clock_gettime(CLOCK_MONOTONIC, &rtt_start);

        // open a new stream
        int stream_fd = open_stream(ctx, connection);
        log_debug("stream opened");

        // generate random data
        char *data;
        random_data(data_size, &data);
        log_debug("data generated");

        // send data to the server
        write(stream_fd, data, strlen(data) + 1);
        log_debug("data sent: %s", data);

        // receive data from the server
        int len;
        while ((len = read(stream_fd, buffer, sizeof(buffer))) > 0) {
            log_debug("data received: %.*s", len, buffer);
        }
        if (len <= 0) {
            log_debug("stream closed by server");
        }

        // calculate round-trip time
        clock_gettime(CLOCK_MONOTONIC, &rtt_end);

        //close the stream
        close(stream_fd);
        log_debug("stream closed");

        free(data);

        // Sleep for a short duration to avoid tight loop
        usleep(500000); // 500 milliseconds

        // Update the elapsed time
        clock_gettime(CLOCK_MONOTONIC, &current);
        elapsed_time = (current.tv_sec - start.tv_sec) + (current.tv_nsec - start.tv_nsec) / 1e9;
        sum_rtt += (rtt_end.tv_sec - rtt_start.tv_sec) * 1000 + (rtt_end.tv_nsec - rtt_start.tv_nsec) / 1e6;
    }

    close_connection(ctx, connection);

    log_info("end of test");

    rtt = sum_rtt / num_requests;

    fprintf(fp, "\n");
    fprintf(fp, "\n");
    fprintf(fp, "-------------- Statistics --------------\n");
    fprintf(fp, "rtt: %d ms\n", rtt);
    fprintf(fp, "num_requests: %d\n", num_requests);
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
  arguments->duration = duration;
  arguments->data_size = data_size;
  request_response_test(arguments);

  free(ip_address);
  free(file_path);
  fclose(fp);
}