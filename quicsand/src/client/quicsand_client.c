#include "quicsand_api.h"
#include "log.h"

#define NUM_REPETITIONS 10
#define CHUNK_SIZE 1024

// #define LOG_USE_COLOR

void test_download_file(FILE *fp, config_t *config, char *ip_address, int port, const char *file_path) {
    log_info("testing file download");
    struct timespec start, end;
    double total_time = 0;
    context_t ctx = create_quic_context(NULL, NULL);
    log_info("context created");
    log_info("client connecting to %s:%d", ip_address, port);
    connection_t connection = open_connection(ctx, ip_address, port);
    log_info("connection opened");
    int stream_fd = open_stream(ctx, connection);
    log_info("stream opened");

    // Send control message
    const char *control_message = CONTROL_DOWNLOAD;
    write(stream_fd, control_message, strlen(control_message) + 1);
    log_info("control message sent: %s", control_message);
    char ack[256];
    int len = read(stream_fd, ack, sizeof(ack));
    log_info("ack received: %.*s", len, ack);

    // send another message with a file path request
    write(stream_fd, file_path, strlen(file_path) + 1);
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

    while ((len = read(stream_fd, buffer, sizeof(buffer))) > 0) {
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
  size_t data_size;
  double duration;
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
  int stream_fd = open_stream(ctx, connection);
  log_info("[conn] %p: stream %d opened", connection, stream_fd);

  // Send control message
  const char *control_message = CONTROL_SINGLE;
  write(stream_fd, control_message, strlen(control_message) + 1);
  log_info("[conn] %p: control message sent: %s", connection, control_message);
  char ack[256];
  int len = read(stream_fd, ack, sizeof(ack));
  log_info("[conn] %p: ack received: %.*s", connection, len, ack);

  for (int i = 0; 1; i++) {
    char *data = "Hello, server!";
    clock_gettime(CLOCK_MONOTONIC, &start);
    write(stream_fd, data, strlen(data) + 1);
    log_info("[conn] %p: data sent: %s", connection, data);
    char response[1024];
    ssize_t len;
    ssize_t total_len = 0;
    int error = 0;
    while (len = read(stream_fd, response + total_len, sizeof(response) - total_len)) {
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

  close_connection(ctx, connection);

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
    int stream_fd = open_stream(ctx, connection);
    log_info("stream opened");

    // Send control message
    const char *control_message = CONTROL_UPLOAD;
    write(stream_fd, control_message, strlen(control_message) + 1);
    log_info("control message sent: %s", control_message);
    char ack[256];
    int len = read(stream_fd, ack, sizeof(ack));
    log_info("ack received: %.*s", len, ack);

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
        write(stream_fd, buffer, bytes_read);
        clock_gettime(CLOCK_MONOTONIC, &end);
        total_time += ((end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9) * 1e3;
        total_bytes += bytes_read;
        num_chunks++;
        //clear buffer
        memset(buffer, 0, CHUNK_SIZE);
    }
    fclose(file);
    write(stream_fd, "EOF", 3);
    log_info("sending EOF");

    // close_stream(ctx, connection, stream);

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

void *test_upload_random_data(void *args) {
    struct args *arguments = (struct args *)args;
    FILE *fp = arguments->fp;
    config_t *config = arguments->config;
    char *ip_address = arguments->ip_address;
    int port = arguments->port;
    size_t data_size = arguments->data_size; // Size of random data to send
    double duration = arguments->duration; // Duration of the test in seconds
    log_info("Uploading random data of size: %zu bytes for duration: %.2f seconds", data_size, duration);
    struct timespec start, end, current, start_prog, end_prog;
    struct rusage usage_start, usage_end;
    double total_time = 0;
    double bandwidth, cpu_time, memory_usage;
    size_t total_bytes = 0;
    size_t num_chunks = 0;

    // Start time and resource usage
    clock_gettime(CLOCK_MONOTONIC, &start_prog);
    getrusage(RUSAGE_SELF, &usage_start);

    context_t ctx = create_quic_context(NULL, NULL);
    log_info("context created");
    log_info("connecting to %s:%d", ip_address, port);
    connection_t connection = open_connection(ctx, ip_address, port);
    if (!connection) {
        log_error("failed to open connection");
        return NULL;
    }
    log_info("connection opened");
    int stream_fd = open_stream(ctx, connection);
    if (!stream_fd) {
        log_error("failed to open stream");
        return NULL;
    }
    log_info("stream opened");
    // Send control message
    const char *control_message = CONTROL_UPLOAD;
    write(stream_fd, control_message, strlen(control_message) + 1);
    log_info("control message sent: %s", control_message);
    char ack[256];
    int len = read(stream_fd, ack, sizeof(ack));
    log_info("ack received: %.*s", len, ack);

    // Allocate buffer for random data
    char *buffer = malloc(data_size);
    if (!buffer) {
        log_error("failed to allocate buffer");
        return NULL;
    }

    // Seed the random number generator
    srand(time(NULL));

    // Fill buffer with random data
    for (size_t i = 0; i < data_size; i++) {
        buffer[i] = rand() % 256;
    }

    log_info("start hour: %d", start.tv_sec);

    // Send random data for the specified duration
    clock_gettime(CLOCK_MONOTONIC, &current);
    while ((current.tv_sec - start_prog.tv_sec) + (current.tv_nsec - start_prog.tv_nsec) / 1e9 < duration) {
        log_info("sending random data chunk");
        clock_gettime(CLOCK_MONOTONIC, &start);
        if (write(stream_fd, buffer, data_size) <= 0) {
            log_error("failed to write to stream");
            break;
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        total_bytes += data_size;
        num_chunks++;
        clock_gettime(CLOCK_MONOTONIC, &current);
    }

    free(buffer);
    write(stream_fd, "EOF", 3);
    log_info("sending EOF");

    close(stream_fd);

    // End time and resource usage
    clock_gettime(CLOCK_MONOTONIC, &end_prog);
    getrusage(RUSAGE_SELF, &usage_end);

    total_time = (end_prog.tv_sec - start_prog.tv_sec) + (end_prog.tv_nsec - start_prog.tv_nsec) / 1e9;

    // Calculate bandwidth in bytes per second
    bandwidth = (total_bytes / total_time);

    // Calculate CPU time in seconds
    cpu_time = (usage_end.ru_utime.tv_sec - usage_start.ru_utime.tv_sec) +
               (usage_end.ru_utime.tv_usec - usage_start.ru_utime.tv_usec) / 1e6;

    // Calculate memory usage in kilobytes
    memory_usage = usage_end.ru_maxrss - usage_start.ru_maxrss;

    // Log metrics
    log_info("upload time: %.2f ms", total_time);
    log_info("bandwidth: %.2f bytes/sec", bandwidth);
    log_info("cpu time: %.2f sec", cpu_time);
    log_info("memory usage: %.2f KB", memory_usage);
    log_info("total bytes transferred: %zu bytes", total_bytes);
    log_info("number of chunks sent: %zu", num_chunks);
    log_info("average chunk size: %.2f bytes", (double)total_bytes / num_chunks);
    log_info("random data upload completed");
    log_info("end of test");

    return NULL;
}

int main(int argc, char *argv[]) {

  char *ip_address = NULL;
  char *file_path = NULL;
  char* log_file = NULL;
  int port = 0;
  int duration = 0;
  int data_size = 0;
  int opt;

  // Parse command-line arguments
  while ((opt = getopt(argc, argv, "i:p:f:l:s:d")) != -1) {
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
            case 'l':
            log_file = strdup(optarg);
            break;
            case 's':
            data_size = atoi(optarg);
            break;
            case 'd':
            duration = atoi(optarg);
            break;
          default:
            log_info("usage: %s -i <ip_address> -p <port> [-f <file_path>]", argv[0]);
            exit(EXIT_FAILURE);
      }
  }

  // Check if required arguments are provided
  if (ip_address == NULL || port == 0) {
      log_info("usage: %s -i <ip_address> -p <port> [-f <file_path>]", argv[0]);
      return EXIT_FAILURE;
  }

  // Open the log file
  FILE *fp = fopen(log_file, "w+");
  if (!fp) {
      perror("Failed to open log file");
      return 1;
  }

  // Add file callback with LOG_TRACE level
  if (log_add_fp(fp, LOG_INFO) != 0) {
      fprintf(fp, "Failed to add file callback\n");
      return 1;
  }

  // Set global log level to LOG_TRACE
  log_set_level(LOG_INFO);
  // FILE *fp = stdout;

  log_info("ip_address: %s", ip_address);
  log_info("port: %d", port);

  log_info("client starting");
  if (file_path != NULL) {
      log_info("file_path: %s", file_path);
  } else {
      log_info("file_path: (none)");
  }

  config_t *config = NULL;

  #define NUM_THREADS 1
  pthread_t thread[NUM_THREADS];
  for (int i = 0; i < NUM_THREADS; i++) {
    struct args *arguments = (struct args *)malloc(sizeof(struct args));
    arguments->fp = fp;
    arguments->config = config;
    arguments->ip_address = ip_address;
    arguments->port = port;
    arguments->file_path = file_path;
    arguments->data_size = data_size;
    arguments->duration = duration;
    log_info("creating thread %d", i);
    pthread_create(&thread[i], NULL, test_upload_random_data, arguments);
  }
  for (int i = 0; i < NUM_THREADS; i++) {
    pthread_join(thread[i], NULL);
  }

  free(ip_address);
  free(file_path);
  getchar();
}
