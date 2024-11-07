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
  fprintf(fp, "Testing multiple sends\n");
  struct timespec start, end;
  double rtt = 0;
  double handshake = 0;
  double cpu = 0;
  qs_context_t *qs = (qs_context_t *)malloc(sizeof(qs_context_t));
  qs->ctx = create_quic_context(NULL, NULL);
  qs->connections = (qs_connection_node_t *)malloc(sizeof(qs_connection_node_t));
  qs->connections->next = NULL;
  // threadpool thpool = thpool_init(50);
  // task_open_connection_t *task = (task_open_connection_t *)malloc(sizeof(task_open_connection_t));
  // task->ctx = ctx;
  // task->ip = target_ip;
  // task->port = atoi(config->port);
  // thpool_add_work(thpool, open_connection_task, (void *)task);
  for (int i = 0; i < 2; i++) {
    connection_t connection = open_connection(qs->ctx, ip_address, port);
    qs_push_connection(qs->connections, connection);
  }
  qs_connection_node_t *current = qs->connections;
  while (current->next != NULL) {
    connection_t connection = current->connection;
    stream_t stream = open_stream(qs->ctx, connection);
    // sleep(1);
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
  log_info(LOGS_FORMAT, "RTT", rtt, "ms");
  fprintf(fp, "End of test\n");
}

void test_download_file(FILE *fp, config_t *config, char *ip_address, int port, const char *file_path) {
    fprintf(fp, "Testing file download\n");
    struct timespec start, end;
    double total_time = 0;
    context_t ctx = create_quic_context(NULL, NULL);
    fprintf(fp, "Created context\n");
    fprintf(fp, "Connecting to %s:%d\n", ip_address, port);
    fflush(fp);
    connection_t connection = open_connection(ctx, ip_address, port);
    fprintf(fp, "Opened connection\n");
    fflush(fp);
    stream_t stream = open_stream(ctx, connection);
    fprintf(fp, "Opened stream\n");
    fflush(fp);

    // Send control message
    const char *control_message = CONTROL_DOWNLOAD;
    send_data(ctx, connection, stream, (void *)control_message, strlen(control_message) + 1);
    fprintf(fp, "Sent control message: %s\n", control_message);
    fflush(fp);
    char ack[256];
    ssize_t len = recv_data(ctx, connection, stream, ack, sizeof(ack), 0);
    fprintf(fp, "Received ack: %s\n", ack);

    // send another message with a file path request
    send_data(ctx, connection, stream, (void *)file_path, strlen(file_path) + 1);
    fprintf(fp, "Sent file path: %s\n", file_path);
    fflush(fp);

    struct rusage usage_start, usage_end;
    double bandwidth, cpu_time, memory_usage;
    size_t total_bytes = 0;
    size_t num_chunks = 0;

    // Start time and resource usage
    clock_gettime(CLOCK_MONOTONIC, &start);
    getrusage(RUSAGE_SELF, &usage_start);

    char buffer[CHUNK_SIZE];
    FILE *file = fopen("downloaded_file.txt", "w");
    if (!file) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }

    while ((len = recv_data(ctx, connection, stream, buffer, CHUNK_SIZE, 0)) > 0) {
        if (len == 0) {
            break;
        }
        fflush(fp);
        fwrite(buffer, sizeof(char), len, file);
        fflush(file);
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
    log_info("DOWNLOAD_TIME: %.2f ms", total_time);
    log_info("BANDWIDTH: %.2f bytes/sec", bandwidth);
    log_info("CPU_TIME: %.2f sec", cpu_time);
    log_info("MEMORY_USAGE: %.2f KB", memory_usage);
    log_info("TOTAL_BYTES: %zu bytes", total_bytes);
    log_info("NUM_CHUNKS: %zu", num_chunks);
    log_info("AVERAGE_CHUNK_SIZE: %.2f bytes", (double)total_bytes / num_chunks);
    log_info("File download completed");
    log_info("End of test");
    fflush(fp);
    fclose(fp);
}

void test_normal_send_receive(FILE *fp, config_t *config, char *ip_address, int port) {
  fprintf(fp, "Testing normal send/receive communication\n");
  struct timespec start, end;
  double rtt = 0;
  context_t ctx = create_quic_context(NULL, NULL);
  fprintf(fp, "Created context\n");
  fprintf(fp, "Connecting to %s:%d\n", ip_address, port);
  fflush(fp);
  connection_t connection = open_connection(ctx, ip_address, port);
  fprintf(fp, "Opened connection\n");
  fflush(fp);
  stream_t stream = open_stream(ctx, connection);
  fprintf(fp, "Opened stream\n");
  fflush(fp);
  // Send control message
  const char *control_message = CONTROL_SINGLE;
  send_data(ctx, connection, stream, (void *)control_message, strlen(control_message) + 1);
  fprintf(fp, "Sent control message: %s\n", control_message);
  fflush(fp);
  char ack[256];
  ssize_t len = recv_data(ctx, connection, stream, ack, sizeof(ack), 0);
  fprintf(fp, "Received ack: %s\n", ack);

  for (int i = 0; i < NUM_REPETITIONS; i++)
	{
		char *data = "Hello, server!";
    clock_gettime(CLOCK_MONOTONIC, &start);
		send_data(ctx, connection, stream, data, strlen(data));
    char response[1024];
    ssize_t len;
    ssize_t total_len = 0;
    while (1) {
        len = recv_data(ctx, connection, stream, response + total_len, 1024 - total_len, 0);
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
              fprintf(fp, "Received data: %s\n", response);
              fflush(fp);
              break;
            }
        } else {
            // Handle error or end of data
            break;
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    rtt += ((end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9) * 1e3;
    fflush(fp);
	}
  log_info(LOGS_FORMAT, "RTT", rtt / NUM_REPETITIONS, "ms");
  fprintf(fp, "Normal send/receive completed\n");
  fprintf(fp, "End of test\n");
  fflush(fp);
  // close_stream(ctx, connection, stream);
  // close_connection(ctx, connection);
}

void test_upload_file(FILE *fp, config_t *config, char *ip_address, int port, const char *file_path) {
    fprintf(fp, "Uploading large file: %s\n", file_path);
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
    fprintf(fp, "Created context\n");
    fprintf(fp, "Connecting to %s:%d\n", ip_address, port);
    fflush(fp);
    connection_t connection = open_connection(ctx, ip_address, port);
    fprintf(fp, "Opened connection\n");
    fflush(fp);
    stream_t stream = open_stream(ctx, connection);
    fprintf(fp, "Opened stream\n");
    fflush(fp);

    // Send control message
    const char *control_message = CONTROL_UPLOAD;
    send_data(ctx, connection, stream, (void *)control_message, strlen(control_message) + 1);
    fprintf(fp, "Sent control message: %s\n", control_message);
    fflush(fp);
    char ack[256];
    ssize_t len = recv_data(ctx, connection, stream, ack, sizeof(ack), 0);
    fprintf(fp, "Received ack: %s\n", ack);


    FILE *file = fopen(file_path, "r");
    if (!file) {
        fprintf(fp, "Error: Failed to open file %s\n", file_path);
        return;
    }

    char buffer[CHUNK_SIZE];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, sizeof(char), CHUNK_SIZE, file)) > 0) {
        printf("Bytes read: %ld\n", bytes_read);
        clock_gettime(CLOCK_MONOTONIC, &start);
        send_data(ctx, connection, stream, buffer, bytes_read);
        printf("Buffer content: %.*s\n", (int)bytes_read, buffer);
        clock_gettime(CLOCK_MONOTONIC, &end);
        total_time += ((end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9) * 1e3;
        // sleep(1);
    }

    fclose(file);
    // close_stream(ctx, connection, stream);
    // close_connection(ctx, connection);

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
    log_info("UPLOAD_TIME: %.2f ms", total_time);
    log_info("BANDWIDTH: %.2f bytes/sec", bandwidth);
    log_info("CPU_TIME: %.2f sec", cpu_time);
    log_info("MEMORY_USAGE: %.2f KB", memory_usage);
    log_info("TOTAL_BYTES: %zu bytes", total_bytes);
    log_info("NUM_CHUNKS: %zu", num_chunks);
    log_info("AVERAGE_CHUNK_SIZE: %.2f bytes", (double)total_bytes / num_chunks);
    fprintf(fp, "File upload completed\n");
    fprintf(fp, "End of test\n");
    fflush(fp);
}

int main(int argc, char *argv[])
{
  // FILE *fp = fopen("client.log", "w+");
  FILE *fp = stdout;
  log_add_fp(fp, LOG_INFO);
  // log_set_level(LOG_INFO);

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
            fprintf(fp, "Usage: %s -i <ip_address> -p <port> [-f <file_path>]\n", argv[0]);
            fflush(fp);
            fclose(fp);
            exit(EXIT_FAILURE);
      }
  }

  // Check if required arguments are provided
  if (ip_address == NULL || port == 0) {
      fprintf(fp, "Usage: %s -i <ip_address> -p <port> [-f <file_path>]\n", argv[0]);
      fclose(fp);
      return EXIT_FAILURE;
  }

  fprintf(fp, "Starting client\n");
  fflush(fp);
  fprintf(fp, "ip_address: %s\n", ip_address);
  fflush(fp);
  fprintf(fp, "port: %d\n", port);
  fflush(fp);
  if (file_path != NULL) {
      fprintf(fp, "file_path: %s\n", file_path);
  } else {
      fprintf(fp, "file_path: (none)\n");
  }
  fflush(fp);

  config_t *config = read_config("config.yaml");
  if (!config) {
      fprintf(fp, "Error: Failed to read configuration file\n");
      fclose(fp);
      return EXIT_FAILURE;
  }

  test_normal_send_receive(fp, config, ip_address, port);
  // test_multiple_sends(fp, config, ip_address, port);
  // test_upload_file(fp, config, ip_address, port, file_path);
  //test_download_file(fp, config, ip_address, port, file_path);
  free(ip_address);
  free(file_path);
  fclose(fp);
}
