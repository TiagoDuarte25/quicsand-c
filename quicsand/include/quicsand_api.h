#ifndef QUICSAN_API_H
#define QUICSAN_API_H

#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h> // inet_addr()
#include <sys/resource.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>

typedef void *context_t;
typedef void *connection_t;
typedef void *config_t;
typedef void *stream_t;

typedef struct statistics
{
    ssize_t min_rtt;
    ssize_t max_rtt;
    ssize_t avg_rtt;
    ssize_t total_sent_packets;
    ssize_t total_received_packets;
    ssize_t total_lost_packets;
    ssize_t total_retransmitted_packets;
    ssize_t total_sent_bytes;
    ssize_t total_received_bytes;
} statistics_t;

enum mode_t
{
    QUIC_CLIENT,
    QUIC_SERVER
};

// Define error codes
typedef enum {
    QUIC_SUCCESS = 0,
    QUIC_ERROR_INVALID_ARGUMENT = -1,
    QUIC_ERROR_CONNECTION_FAILED = -2,
    QUIC_ERROR_STREAM_FAILED = -3,
    QUIC_ERROR_SEND_FAILED = -4,
    QUIC_ERROR_RECV_FAILED = -5,
    QUIC_ERROR_TIMEOUT = -6,
    QUIC_ERROR_ALLOCATION_FAILED = -7,
    QUIC_ERROR_INITIALIZATION_FAILED = -8,
    QUIC_ERROR_SHUTDOWN_FAILED = -9,
    QUIC_ERROR_INVALID_STATE = -10,
    QUIC_ERROR_PROTOCOL_VIOLATION = -11,
    QUIC_ERROR_INTERNAL = -12,
    QUIC_ERROR_NETWORK_UNREACHABLE = -13,
    QUIC_ERROR_HOST_UNREACHABLE = -14,
    QUIC_ERROR_CONNECTION_REFUSED = -15,
    QUIC_ERROR_CONNECTION_RESET = -16,
    QUIC_ERROR_NO_BUFFERS = -17,
    QUIC_ERROR_NOT_SUPPORTED = -18,
    QUIC_ERROR_ADDRESS_IN_USE = -19,
    QUIC_ERROR_ADDRESS_NOT_AVAILABLE = -20,
    QUIC_ERROR_CONNECTION_ABORTED = -21,
    QUIC_ERROR_CONNECTION_CLOSED = -22,
    QUIC_ERROR_BAD_CERTIFICATE = -23,
    QUIC_ERROR_CERTIFICATE_REVOKED = -24,
    QUIC_ERROR_CERTIFICATE_EXPIRED = -25,
    QUIC_ERROR_CERTIFICATE_UNKNOWN = -26,
    QUIC_ERROR_HANDSHAKE_FAILED = -27,
    QUIC_ERROR_TLS_ERROR = -28,
    QUIC_ERROR_INVALID_IP_ADDRESS = -29,
    QUIC_ERROR_UNKNOWN = -30,
} quic_error_code_t;

extern quic_error_code_t quic_error;

#define CONTROL_UPLOAD "UPLOAD"
#define CONTROL_DOWNLOAD "DOWNLOAD"
#define CONTROL_SINGLE "SINGLE"

context_t create_quic_context(char *cert_path, char *key_path);

// client functions
connection_t open_connection(context_t context, char* ip, int port);
int close_connection(context_t context, connection_t connection);
int open_stream(context_t context, connection_t connection);
int close_stream(context_t context, connection_t connection, int stream);

// server functions
int bind_addr(context_t context, char* ip, int port);
int set_listen(context_t context);
connection_t accept_connection(context_t context, time_t timeout);
int accept_stream(context_t context, connection_t connection, time_t timeout);

// common functions
int print_context(context_t context);
char* quic_error_message(quic_error_code_t quic_error);
int get_conneciton_statistics(context_t context, connection_t connection, statistics_t *stats);

void destroy_quic_context(context_t context);

#endif 