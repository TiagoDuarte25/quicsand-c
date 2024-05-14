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

int main()
{
  FILE *fp = fopen("client.log", "w+");
  log_add_fp(fp, LOG_INFO);

  Config *config = malloc(sizeof(Config));

  config = client_init();
  log_debug("Client configuration initialized");

  struct timespec start_cpu, end_cpu;

  clock_t start_wall = clock();
  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start_cpu);

  // open connection to the server
  log_debug("Openning connection to the server...");
  Connection connection = open_connection(config);
  log_debug("Connection opened");

  for (int i = 0; i < config->reps; i++)
  {
    log_debug("Openning stream...");
    // open stream to the server
    Stream stream = open_stream(connection);
    log_debug("Stream opened");

    clock_t begin_ttfb = clock();

    clock_t start_lat = clock();

    log_debug("Sending data...");
    // send content to the server
    send_data(connection, stream, &config->reqsize);
    log_debug("Data sent");

    log_debug("Receiving data...");
    // receive content from the server
    receive_data(stream);
    log_debug("Data received");

    clock_t end_lat = clock();
    clock_t end_ttfb = clock();

    // Calculate latency
    double latency = (double)(end_lat - start_lat) / CLOCKS_PER_SEC * 1000;
    log_info(LOGS_FORMAT, "LAT", latency);

    close_stream(stream);

    // Calculate throughput
    // double throughput = (double)NUM_PACKETS * PACKET_SIZE / (double)(1024 * 1024) / ((double)(end.tv_sec - start.tv_sec) + (double)(end.tv_usec - start.tv_usec) / 1000000.0);
    // log_info(LOGS_FORMAT, "THROUGHPUT", throughput);

    // Calculate TTFB
    double ttfb = (double)(end_ttfb - begin_ttfb) / CLOCKS_PER_SEC * 1000;
    log_info(LOGS_FORMAT, TTFB, ttfb);
  }

  close_connection(connection);

  clock_t end_wall = clock();
  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end_cpu);

  // Calculate CPU usage
  double wall_time = (double)(end_wall - start_wall) / CLOCKS_PER_SEC;
  double cpu_time = (end_cpu.tv_sec - start_cpu.tv_sec) + (end_cpu.tv_nsec - start_cpu.tv_nsec) / 1e9;
  int num_cores = sysconf(_SC_NPROCESSORS_ONLN);

  double cpu_usage = cpu_time / num_cores / wall_time * 100;
  log_info(LOGS_FORMAT, CPU, cpu_usage);

  client_shutdown();
}
