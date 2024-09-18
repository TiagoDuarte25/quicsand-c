#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h> // inet_addr()
#include <sys/times.h>
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

#define LOGS_FORMAT "[%s] %f"
#define TTFB "TTFB"
#define HANDSHAKE "HDSK"
#define CPU "CPU"
#define NUM_REPETITIONS 100

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

void network_experiment(config_t *config, char *target_ip) {
  struct timespec start, end;
  double ttfb = 0;
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
    connection_t connection = open_connection(qs->ctx, target_ip, atoi(config->port));
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
      ttfb += (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    }
    close_stream(qs->ctx, connection, stream);
    close_connection(qs->ctx, connection);
    current = current->next;
  }
  ttfb /= NUM_REPETITIONS;
  log_info(LOGS_FORMAT, TTFB, ttfb);
}

int main(int argc, char *argv[])
{
  FILE *fp = fopen("client.log", "w+");
  log_add_fp(fp, LOG_INFO);
  // log_set_level(LOG_INFO);

  if (argc != 2)
  {
    fprintf(stderr, "Usage: run <target_ip>\n");
    exit(EXIT_FAILURE);
  }

  char *target_ip = argv[1];

  config_t *config = read_config("config.yaml");
  if (!config)
  {
    fprintf(stderr, "Error: Failed to read configuration file\n");
    exit(EXIT_FAILURE);
  }

  struct timespec start, end;
  double rtt = 0;
  context_t ctx = create_quic_context(NULL, NULL);
  fprintf(stderr, "Created context\n");
  printf("Connecting to %s:%s\n", target_ip, config->port);
  connection_t connection = open_connection(ctx, target_ip, atoi(config->port));
  fprintf(stderr, "Opened connection\n");
  stream_t stream = open_stream(ctx, connection);
  fprintf(stderr, "Opened stream\n");
  sleep(1);
  for (int i = 0; i < NUM_REPETITIONS; i++)
	{
		char *data = "Hello, server!";
    clock_gettime(CLOCK_MONOTONIC, &start);
		send_data(ctx, connection, stream, data, strlen(data));
    char response[1024];
    ssize_t len = recv_data(ctx, connection, response, 0);
    if (len > 0) {
      // Ensure the data is null-terminated
      if (len < sizeof(response)) {
        response[len] = '\0';
      } else {
        response[sizeof(response) - 1] = '\0';
      }
      fprintf(stderr, "Received data: %s\n", response);
    } else {
      fprintf(stderr, "No data received or error occurred\n");
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    rtt += (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
	}
  printf("RTT: %f\n", rtt / NUM_REPETITIONS);
  //network_experiment(config, target_ip);
  getchar();
}
