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

#include "quicsand_client_adapter.h"
#include "utils.h"
#include "log.h"

#define LOGS_FORMAT "[%s] %f"
#define TTFB "TTFB"
#define HANDSHAKE "HDSK"
#define CPU "CPU"
#define NUM_REPETITIONS 100

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

  Config
      *config = malloc(sizeof(Config));
  config = read_config("config.yaml");
  if (!config)
  {
    fprintf(stderr, "Error: Failed to read configuration file\n");
    exit(EXIT_FAILURE);
  }

  Client_CTX ctx;
  client_init(config, &ctx, target_ip);

  log_debug("Client configuration initialized");

  struct timespec start_cpu, end_cpu;

  clock_t start_wall = clock();
  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start_cpu);

  // open connection to the server
  log_debug("Openning connection to the server...");
  open_connection(ctx);
  log_debug("Connection opened");

  for (int i = 0; i < config->reps; i++)
  {
    log_debug("Openning stream...");
    // open stream to the server
    open_stream(ctx);
    log_debug("Stream opened");

    clock_t begin_ttfb = clock();

    clock_t start_lat = clock();

    // send content to the server
    log_debug("Sending data...");
    send_data(ctx, &config->reqsize);
    log_debug("Data sent");

    // receive content from the server
    log_debug("Receiving data...");
    receive_data(ctx);
    log_debug("Data received");

    clock_t end_lat = clock();
    clock_t end_ttfb = clock();

    // Calculate latency
    double latency = (double)(end_lat - start_lat) / CLOCKS_PER_SEC * 1000;
    log_info(LOGS_FORMAT, "LAT", latency);

    close_stream(ctx);

    // Calculate throughput
    // double throughput = (double)NUM_PACKETS * PACKET_SIZE / (double)(1024 * 1024) / ((double)(end.tv_sec - start.tv_sec) + (double)(end.tv_usec - start.tv_usec) / 1000000.0);
    // log_info(LOGS_FORMAT, "THROUGHPUT", throughput);

    // Calculate TTFB
    double ttfb = (double)(end_ttfb - begin_ttfb) / CLOCKS_PER_SEC * 1000;
    log_info(LOGS_FORMAT, TTFB, ttfb);
  }

  close_connection(ctx);

  clock_t end_wall = clock();
  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end_cpu);

  // Calculate CPU usage
  double wall_time = (double)(end_wall - start_wall) / CLOCKS_PER_SEC;
  double cpu_time = (end_cpu.tv_sec - start_cpu.tv_sec) + (end_cpu.tv_nsec - start_cpu.tv_nsec) / 1e9;
  int num_cores = sysconf(_SC_NPROCESSORS_ONLN);

  double cpu_usage = cpu_time / num_cores / wall_time * 100;
  log_info(LOGS_FORMAT, CPU, cpu_usage);

  client_shutdown(ctx);
}
