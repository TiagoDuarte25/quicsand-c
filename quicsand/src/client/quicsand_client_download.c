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

    size_t file_size;
    size_t len = read(stream_fd, &file_size, sizeof(size_t));
    if (len < 0) {
        log_error("error: %s", quic_error_message(quic_error));
        fclose(file);
        close(stream_fd);
        return NULL;
    }
    log_debug("file size: %ld", file_size);

    static char buffer[65536];
    size_t total_bytes_read = 0;
    size_t bytes_read;
    while (total_bytes_read < file_size) {
        bytes_read = read(stream_fd, buffer, sizeof(buffer));
        if (bytes_read < 0) {
            log_error("error: %s", quic_error_message(quic_error));
            fclose(file);
            close(stream_fd);
            return NULL;
        }
        total_bytes_read += bytes_read;
        fwrite(buffer, 1, bytes_read, file);
    }

    fclose(file);

    //close the stream
    close(stream_fd);

    log_info("file download completed");

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
  download_file(arguments);

  free(ip_address);
  free(file_path);
  fclose(fp);
  return 0;
}