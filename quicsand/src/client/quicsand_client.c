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
    // threadpool thpool = thpool_init(50);
    context_t *ctx = create_quic_context(NULL, NULL);
    // task_open_connection_t *task = (task_open_connection_t *)malloc(sizeof(task_open_connection_t));
    // task->ctx = ctx;
    // task->ip = target_ip;
    // task->port = atoi(config->port);
    // thpool_add_work(thpool, open_connection_task, (void *)task);
    connection_t connection = open_connection(ctx, target_ip, atoi(config->port));
    stream_t stream = open_stream(ctx, connection);
    for (int i = 0; i < NUM_REPETITIONS; i++) {
      clock_gettime(CLOCK_MONOTONIC, &start);
      char *data = random_data(200);
      send_data(ctx, connection, stream, data, strlen(data));
      clock_gettime(CLOCK_MONOTONIC, &end);
      ttfb += (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    }
    ttfb /= NUM_REPETITIONS;
    close_stream(ctx, connection, stream);
    close_connection(ctx, connection);
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

  // context_t ctx = create_quic_context(QUIC_CLIENT);
  // fprintf(stderr, "Created context\n");
  // printf("Connecting to %s:%s\n", target_ip, config->port);
  // connection_t connection = open_connection(ctx, target_ip, atoi(config->port));
  // fprintf(stderr, "Opened connection\n");
  // stream_t stream = open_stream(ctx, connection);
  // fprintf(stderr, "Opened stream\n");
  // sleep(3);
  // close_stream(ctx, connection, stream);
  // fprintf(stderr, "Closed stream\n");
  network_experiment(config, target_ip);
  getchar();
}
