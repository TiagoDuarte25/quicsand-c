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
    for (int i = 0; i < len - 1; i++) {
        (*data)[i] = 'A' + (rand() % 26);
    }
    (*data)[len - 1] = '\0';
    return 0;
}

void * open_multiple_streams(void *args) {
    struct args *arguments = (struct args *)args;
    FILE *fp = arguments->fp;
    char *ip_address = arguments->ip_address;
    int port = arguments->port;
    char *file_path = arguments->file_path;
    size_t data_size = arguments->data_size;
    double duration = arguments->duration;

    log_info("testing multiple streams");

    struct timespec start, end;
    double total_time = 0;
    context_t ctx = create_quic_context(NULL, NULL);
    log_info("context created");
    connection_t connection = open_connection(ctx, ip_address, port);
    log_info("connection opened");
    char buffer[65536];
    for (int i = 0; i < 10; i++) {
        int stream_fd = open_stream(ctx, connection);
        log_info("stream opened");

        // generate random data
        char *data;
        random_data(1024, &data);

        // send data to the server
        write(stream_fd, data, strlen(data) + 1);
        log_debug("data sent: %s", data);

        // receive data from the server
        int len = read(stream_fd, buffer, sizeof(buffer));
        log_debug("data received: %.*s", len, buffer);

        // free memory and close the stream
        free(data);
    }

    close_connection(ctx, connection);

    log_info("end of test");
    return NULL;
}

int main(int argc, char *argv[]) {
  // Open the log file
  FILE *fp = fopen("client.log", "w+");
  if (!fp) {
      perror("Failed to open log file");
      return 1;
  }

  // Add file callback with LOG_TRACE level
  if (log_add_fp(fp, LOG_TRACE) != 0) {
      fprintf(fp, "Failed to add file callback\n");
      return 1;
  }

  // Set global log level to LOG_TRACE
  log_set_level(LOG_TRACE);
  // FILE *fp = stdout;

  char *ip_address = NULL;
  char *file_path = NULL;
  int port = 0;
  int opt;

  // Parse command-line arguments
  while ((opt = getopt(argc, argv, "i:p:f:")) != -1) {
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
          default:
            log_info("usage: %s -i <ip_address> -p <port> [-f <file_path>]", argv[0]);
            fclose(fp);
            exit(EXIT_FAILURE);
      }
  }

  // Check if required arguments are provided
  if (ip_address == NULL || port == 0) {
      log_info("usage: %s -i <ip_address> -p <port> [-f <file_path>]", argv[0]);
      fclose(fp);
      return EXIT_FAILURE;
  }

  log_info("ip_address: %s", ip_address);
  log_info("port: %d", port);

  log_info("client starting");
  if (file_path != NULL) {
      log_info("file_path: %s", file_path);
  } else {
      log_info("file_path: (none)");
  }

  #define NUM_THREADS 1
  pthread_t thread[NUM_THREADS];
  for (int i = 0; i < NUM_THREADS; i++) {
    struct args *arguments = (struct args *)malloc(sizeof(struct args));
    arguments->fp = fp;
    arguments->ip_address = ip_address;
    arguments->port = port;
    arguments->file_path = file_path;
    arguments->data_size = 1024;
    arguments->duration = 10;
    log_info("creating thread %d", i);
    pthread_create(&thread[i], NULL, open_multiple_streams, arguments);
  }
  for (int i = 0; i < NUM_THREADS; i++) {
    pthread_join(thread[i], NULL);
  }

  free(ip_address);
  free(file_path);
  fclose(fp);
  getchar();
}