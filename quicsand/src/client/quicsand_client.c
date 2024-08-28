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

#include "quicsand_api.h"
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

  config_t *config = read_config("config.yaml");
  if (!config)
  {
    fprintf(stderr, "Error: Failed to read configuration file\n");
    exit(EXIT_FAILURE);
  }

  context_t ctx = create_quic_context(QUIC_CLIENT);
  fprintf(stderr, "Created context\n");
  open_connection(ctx, target_ip, atoi(config->port));
  fprintf(stderr, "Opened connection\n");
}
