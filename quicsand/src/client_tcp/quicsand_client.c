#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h> // inet_addr()
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <sys/times.h>
#include <unistd.h> // read(), write(), close()
#include <log.h>
#include <pthread.h>
#include <utils.h>
#define DEFAULT_BUFSIZE 365
#define PORT 8080
#define SA struct sockaddr
#define LOGS_FORMAT "[%s] %f"
#define TTFB "TTFB"
#define HANDSHAKE "HDSK"
#define CPU "CPU"
#define NUM_REPETITIONS 100

void send_content(int sockfd, int request_size)
{
  char content[request_size];
  memset(content, 'a', request_size - 1);
  content[request_size] = '\0'; // Null-terminate the string
  write(sockfd, content, strlen(content));
  printf("Request: %s\n", content);
}

void receive_content(int sockfd, int bufsize)
{
  char read_buff[bufsize];
  memset(read_buff, 0, sizeof(read_buff));
  read(sockfd, read_buff, sizeof(read_buff));
  printf("Reply: %s\n", read_buff);
}

void open_connection(int sockfd, struct sockaddr_in servaddr)
{
  clock_t start = clock();

  // connect the client socket to server socket
  if (connect(sockfd, (SA *)&servaddr, sizeof(servaddr)) != 0)
  {
    printf("Connection with the server failed...\n");
    exit(0);
  }
  else
  {
    printf("Connected to the server..\n");
    clock_t end = clock();
    double hdshk_time = (double)(end - start) / CLOCKS_PER_SEC * 1000;
    log_info(LOGS_FORMAT, HANDSHAKE, hdshk_time);
  }
}

int main()
{
  FILE *fp = fopen("client.log", "w+");
  Config config = read_config("config.yaml");
  printf("Repetitions: %d\n", config.reps);
  printf("Buffer size: %d\n", config.bufsize);
  printf("Request size: %d\n", config.reqsize);

  log_add_fp(fp, LOG_INFO);

  int sockfd;
  struct sockaddr_in *servaddr = malloc(sizeof(struct sockaddr_in));
  struct timespec start_cpu, end_cpu;

  clock_t start_wall = clock();
  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start_cpu);

  for (int i = 0; i < config.reps; i++)
  {
    clock_t begin_ttfb = clock();

    // socket create and verification
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
      printf("Socket creation failed...\n");
      exit(0);
    }
    else
      printf("Socket successfully created...\n");
    memset(servaddr, 0, sizeof(*servaddr));

    // assign IP, PORT
    servaddr->sin_family = AF_INET;
    servaddr->sin_addr.s_addr = inet_addr("127.0.0.1");
    servaddr->sin_port = htons(PORT);

    // open connection to the server
    open_connection(sockfd, *servaddr);

    clock_t start_lat = clock();

    // send content to the server
    send_content(sockfd, config.reqsize);

    // receive content from the server
    receive_content(sockfd, config.bufsize);

    clock_t end_lat = clock();
    clock_t end_ttfb = clock();

    // Calculate latency
    double latency = (double)(end_lat - start_lat) / CLOCKS_PER_SEC * 1000;
    log_info(LOGS_FORMAT, "LAT", latency);

    // Calculate throughput
    // double throughput = (double)NUM_PACKETS * PACKET_SIZE / (double)(1024 * 1024) / ((double)(end.tv_sec - start.tv_sec) + (double)(end.tv_usec - start.tv_usec) / 1000000.0);
    // log_info(LOGS_FORMAT, "THROUGHPUT", throughput);

    // Calculate TTFB
    double ttfb = (double)(end_ttfb - begin_ttfb) / CLOCKS_PER_SEC * 1000;
    log_info(LOGS_FORMAT, TTFB, ttfb);

    // close the socket
    close(sockfd);
  }

  clock_t end_wall = clock();
  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end_cpu);

  // Calculate CPU usage
  double wall_time = (double)(end_wall - start_wall) / CLOCKS_PER_SEC;
  double cpu_time = (end_cpu.tv_sec - start_cpu.tv_sec) + (end_cpu.tv_nsec - start_cpu.tv_nsec) / 1e9;
  int num_cores = sysconf(_SC_NPROCESSORS_ONLN);

  double cpu_usage = cpu_time / num_cores / wall_time * 100;
  log_info(LOGS_FORMAT, CPU, cpu_usage);

  free(servaddr);
}
