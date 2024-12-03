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
#include "utils.h"
#include "log.h"
#include <bits/time.h>
// #include <linux/time.h>

#define LOGS_FORMAT "[%s] %f %s"
#define TTFB "TTFB"
#define HANDSHAKE "HDSK"
#define CPU "CPU"
#define NUM_REPETITIONS 10
#define CHUNK_SIZE 1024

// #define LOG_USE_COLOR

char *random_data(int len)
{
  char *data = (char *)malloc(len);
  for (int i = 0; i < len - 1; i++)
  {
      data[i] = 'A' + (rand() % 26);
  }
  data[len - 1] = '\0';
  return data;
}

typedef struct
{
  context_t ctx;
  char *ip;
  int port;
  connection_t connection;
} task_open_connection_t;

typedef struct qs_stream_node
{
  stream_t stream;
  struct qs_stream_node *next;
} qs_stream_node_t;

typedef struct qs_connection_node {
  connection_t connection;
  struct qs_stream_node *streams;
  struct qs_connection_node *next;
} qs_connection_node_t;

typedef struct qs_context {
  context_t ctx;
  qs_connection_node_t *connections;
} qs_context_t;

qs_connection_node_t* qs_push_connection(qs_connection_node_t *head, connection_t connection) {
  qs_connection_node_t *current = head;
  while (current->next != NULL) {
      current = current->next;
  }
  current->next = (qs_connection_node_t *)malloc(sizeof(qs_connection_node_t));
  current->connection = connection;
  current->streams = NULL;
  current->next->next = NULL;
  return current->next;
}

qs_stream_node_t* qs_push_stream(qs_stream_node_t *head, stream_t stream) {
  qs_stream_node_t *current = head;
  while (current->next != NULL) {
      current = current->next;
  }
  current->next = (qs_stream_node_t *)malloc(sizeof(qs_stream_node_t));
  current->next->stream = stream;
  current->next->next = NULL;
  return current->next;
}

void qs_remove_connection(qs_connection_node_t *head, qs_connection_node_t *node) {
  qs_connection_node_t *current = head;
  while (current->next != node) {
      current = current->next;
  }
  current->next = node->next;
  free(node);
}

void qs_remove_stream(qs_stream_node_t *head, qs_stream_node_t *node) {
  qs_stream_node_t *current = head;
  while (current->next != node) {
      current = current->next;
  }
  current->next = node->next;
  free(node);
}

void open_connection_task(void *arg)
{
    task_open_connection_t *task = (task_open_connection_t *)arg;
    task->connection = open_connection(task->ctx, task->ip, task->port);
}

void test_multiple_sends(FILE *fp, config_t *config, char *ip_address, int port) {
  log_info("testing multiple sends");
  struct timespec start, end;
  double rtt = 0;
  double handshake = 0;
  double cpu = 0;
  qs_context_t *qs = (qs_context_t *)malloc(sizeof(qs_context_t));
  qs->ctx = create_quic_context(NULL, NULL);
  qs->connections = (qs_connection_node_t *)malloc(sizeof(qs_connection_node_t));
  qs->connections->next = NULL;
  for (int i = 0; i < 2; i++) {
    connection_t connection = open_connection(qs->ctx, ip_address, port);
    qs_push_connection(qs->connections, connection);
  }
  qs_connection_node_t *current = qs->connections;
  while (current->next != NULL) {
    connection_t connection = current->connection;
    stream_t stream = open_stream(qs->ctx, connection);
    for (int i = 0; i < NUM_REPETITIONS; i++) {
      clock_gettime(CLOCK_MONOTONIC, &start);
      char *data = random_data(200);
      send_data(qs->ctx, connection, stream, data, strlen(data));
      clock_gettime(CLOCK_MONOTONIC, &end);
      rtt += ((end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9) * 1e3;
    }
    close_stream(qs->ctx, connection, stream);
    close_connection(qs->ctx, connection);
    current = current->next;
  }
  rtt /= NUM_REPETITIONS;
  log_info("rtt: %.2f ms", rtt);
  log_info("end of test");
}

void test_download_file(FILE *fp, config_t *config, char *ip_address, int port, const char *file_path) {
    log_info("testing file download");
    struct timespec start, end;
    double total_time = 0;
    context_t ctx = create_quic_context(NULL, NULL);
    log_info("context created");
    log_info("client connecting to %s:%d", ip_address, port);
    connection_t connection = open_connection(ctx, ip_address, port);
    log_info("connection opened");
    stream_t stream = open_stream(ctx, connection);
    log_info("stream opened");

    // Send control message
    const char *control_message = CONTROL_DOWNLOAD;
    send_data(ctx, connection, stream, (void *)control_message, strlen(control_message) + 1);
    log_info("control message sent: %s", control_message);
    char ack[256];
    ssize_t len = recv_data(ctx, connection, stream, ack, sizeof(ack), 0);
    log_info("ack received: %s", ack);

    // send another message with a file path request
    send_data(ctx, connection, stream, (void *)file_path, strlen(file_path) + 1);
    log_info("file path sent: %s", file_path);

    struct rusage usage_start, usage_end;
    double bandwidth, cpu_time, memory_usage;
    size_t total_bytes = 0;
    size_t num_chunks = 0;

    // Start time and resource usage
    clock_gettime(CLOCK_MONOTONIC, &start);
    getrusage(RUSAGE_SELF, &usage_start);

    char buffer[CHUNK_SIZE + 1];
    FILE *file = fopen("downloaded_file.txt", "w");
    if (!file) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }

    while ((len = recv_data(ctx, connection, stream, buffer, CHUNK_SIZE, 0)) > 0) {
        log_info("received data: %.*s", (int)len, buffer);
        if (len == 0) {
            break;
        }
        buffer[len] = '\0';
        if (strcmp(buffer, "EOF") == 0) {
            break;
        }
        fwrite(buffer, sizeof(char), len, file);
        total_bytes += len;
        num_chunks++;
    }
    fclose(file);

    // End time and resource usage
    clock_gettime(CLOCK_MONOTONIC, &end);
    getrusage(RUSAGE_SELF, &usage_end);

    // Calculate total time in milliseconds
    total_time = ((end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9) * 1e3;

    // Calculate bandwidth in bytes per second
    bandwidth = (total_bytes / total_time) * 1e3;

    // Calculate CPU time in seconds
    cpu_time = (usage_end.ru_utime.tv_sec - usage_start.ru_utime.tv_sec) +
               (usage_end.ru_utime.tv_usec - usage_start.ru_utime.tv_usec) / 1e6;

    // Calculate memory usage in kilobytes
    memory_usage = usage_end.ru_maxrss - usage_start.ru_maxrss;

    // Log metrics
    log_info("download time: %.2f ms", total_time);
    log_info("bandwith: %.2f bytes/sec", bandwidth);
    log_info("cpu time: %.2f sec", cpu_time);
    log_info("memory usage: %.2f KB", memory_usage);
    log_info("total bytes transfered: %zu bytes", total_bytes);
    log_info("number of chunks sent: %zu", num_chunks);
    log_info("average chunk size: %.2f bytes", (double)total_bytes / num_chunks);
    log_info("file download completed");
    log_info("end of test");
}

struct args {
  FILE *fp;
  config_t *config;
  char *ip_address;
  int port;
  char *file_path;
};

void *test_normal_send_receive(void *args) {
  struct args *arguments = (struct args *)args;
  FILE *fp = arguments->fp;
  config_t *config = arguments->config;
  char *ip_address = arguments->ip_address;
  int port = arguments->port;
  log_info("testing normal send/receive communication");
  struct timespec start, end;
  double rtt = 0;
  context_t ctx = create_quic_context(NULL, NULL);
  log_info("context created");
  log_info("client connecting to %s:%d", ip_address, port);
  connection_t connection = open_connection(ctx, ip_address, port);
  log_info("connection opened");
  stream_t stream = open_stream(ctx, connection);
  log_info("[conn] %p: stream opened", connection);

  // Send control message
  const char *control_message = CONTROL_SINGLE;
  send_data(ctx, connection, stream, (void *)control_message, strlen(control_message) + 1);
  log_info("[conn] %p: control message sent: %s", connection, control_message);
  char ack[256];
  ssize_t len = recv_data(ctx, connection, stream, ack, sizeof(ack), 0);
  log_info("[conn] %p: ack received: %s", connection, ack);

  for (int i = 0; 1 ; i++) {
    char *data = "Hello, server!";
    clock_gettime(CLOCK_MONOTONIC, &start);
    send_data(ctx, connection, stream, data, strlen(data));
    log_info("[conn] %p: data sent: %s", connection, data);
    char response[1024];
    ssize_t len;
    ssize_t total_len = 0;
    int error = 0;
    while (len = recv_data(ctx, connection, stream, response + total_len, 1024 - total_len, 0)) {
        if (len > 0) {
            total_len += len;
            // Ensure termination
            if (total_len < 1024) {
                response[total_len] = '\0';
            } else {
                response[1024 - 1] = '\0';
            }

            // Check if the entire message has been received
            if (response[total_len] == '\0') {
              log_info("[conn] %p: data received: %s", connection, response);
              break;
            }
        } else {
            // Handle error or end of data
            log_error("[conn] %p: recv timeout", connection);
            error = 1;
            break;
        }
    }
    if (len < 0 || error) {
      break;
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    rtt += ((end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9) * 1e3;
  }
  log_info("rtt: %.2f ms", rtt / NUM_REPETITIONS);
  log_info("normal send/receive completed");
  log_info("end of test");
}

void *test_upload_file(void *args) {
    struct args *arguments = (struct args *)args;
    FILE *fp = arguments->fp;
    config_t *config = arguments->config;
    char *ip_address = arguments->ip_address;
    int port = arguments->port;
    char *file_path = arguments->file_path;
    log_info("Uploading large file: %s", file_path);
    struct timespec start, end;
    struct rusage usage_start, usage_end;
    double total_time = 0;
    double bandwidth, cpu_time, memory_usage;
    size_t total_bytes = 0;
    size_t num_chunks = 0;

    // Start time and resource usage
    clock_gettime(CLOCK_MONOTONIC, &start);
    getrusage(RUSAGE_SELF, &usage_start);

    context_t ctx = create_quic_context(NULL, NULL);
    log_info("context created");
    log_info("connecting to %s:%d", ip_address, port);
    connection_t connection = open_connection(ctx, ip_address, port);
    log_info("connection opened");
    stream_t stream = open_stream(ctx, connection);
    log_info("stream opened");

    // Send control message
    const char *control_message = CONTROL_UPLOAD;
    send_data(ctx, connection, stream, (void *)control_message, strlen(control_message) + 1);
    log_info("control message sent: %s", control_message);
    char ack[256];
    ssize_t len = recv_data(ctx, connection, stream, ack, sizeof(ack), 0);
    log_info("ack received: %s", ack);

    FILE *file = fopen(file_path, "r");
    if (!file) {
        log_error("failed to open file %s", file_path);
        return NULL;
    }

    char buffer[CHUNK_SIZE];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, sizeof(char), CHUNK_SIZE, file)) > 0) {
        log_info("read %zu bytes from file", bytes_read);
        log_info("sending: %s", buffer);
        clock_gettime(CLOCK_MONOTONIC, &start);
        send_data(ctx, connection, stream, buffer, bytes_read);
        clock_gettime(CLOCK_MONOTONIC, &end);
        total_time += ((end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9) * 1e3;
        total_bytes += bytes_read;
        num_chunks++;
        //clear buffer
        memset(buffer, 0, CHUNK_SIZE);
    }
    fclose(file);
    send_data(ctx, connection, stream, (void *)"EOF", 3);
    log_info("sending EOF");

    // End time and resource usage
    clock_gettime(CLOCK_MONOTONIC, &end);
    getrusage(RUSAGE_SELF, &usage_end);

    // Calculate total time in milliseconds
    total_time = ((end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9) * 1e3;

    // Calculate bandwidth in bytes per second
    bandwidth = (total_bytes / total_time) * 1e3;

    // Calculate CPU time in seconds
    cpu_time = (usage_end.ru_utime.tv_sec - usage_start.ru_utime.tv_sec) +
               (usage_end.ru_utime.tv_usec - usage_start.ru_utime.tv_usec) / 1e6;

    // Calculate memory usage in kilobytes
    memory_usage = usage_end.ru_maxrss - usage_start.ru_maxrss;

    // Log metrics
    log_info("upload time: %.2f ms", total_time);
    log_info("bandwith: %.2f bytes/sec", bandwidth);
    log_info("cpu time: %.2f sec", cpu_time);
    log_info("memory usage: %.2f KB", memory_usage);
    log_info("total bytes transfered: %zu bytes", total_bytes);
    log_info("number of chunks sent: %zu", num_chunks);
    log_info("average chunk size: %.2f bytes", (double)total_bytes / num_chunks);
    log_info("file upload completed");
    log_info("end of test");
}

int main(int argc, char *argv[]) {
  FILE *fp = fopen("client.log", "w+");
  log_add_fp(fp, LOG_TRACE);
  // FILE *fp = stdout;
  // log_set_level(LOG_TRACE);

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

  log_info("client starting");
  if (file_path != NULL) {
      log_info("file_path: %s", file_path);
  } else {
      log_info("file_path: (none)");
  }

  config_t *config = read_config("config.yaml");
  if (!config) {
      log_error("error: failed to read configuration file");
      fclose(fp);
      return EXIT_FAILURE;
  }

  #define NUM_THREADS 1
  pthread_t thread[NUM_THREADS];
  for (int i = 0; i < NUM_THREADS; i++) {
    struct args *arguments = (struct args *)malloc(sizeof(struct args));
    arguments->fp = fp;
    arguments->config = config;
    arguments->ip_address = ip_address;
    arguments->port = port;
    arguments->file_path = file_path;
    log_info("creating thread %d", i);
    pthread_create(&thread[i], NULL, test_normal_send_receive, arguments);
  }
  for (int i = 0; i < NUM_THREADS; i++) {
    pthread_join(thread[i], NULL);
  }

  // test_normal_send_receive(fp, config, ip_address, port);
  // test_upload_file(fp, config, ip_address, port, file_path);
  // test_download_file(fp, config, ip_address, port, file_path);
  free(ip_address);
  free(file_path);
  fclose(fp);
  getchar();
}
