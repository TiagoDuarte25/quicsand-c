#ifndef QUICSAN_API_H
#define QUICSAN_API_H

#include <time.h>
#include <stdio.h>
#include <stdlib.h>

typedef void *context_t;
typedef void *connection_t;
typedef void *stream_t;
typedef void *config_t;

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
int bind_addr(context_t context, char* ip, int port);

// client functions
connection_t open_connection(context_t context, char* ip, int port);
int close_connection(context_t context, connection_t connection);
stream_t open_stream(context_t context, connection_t connection);
int close_stream(context_t context, connection_t connection, stream_t stream);
int send_data(context_t context, connection_t connection, stream_t stream, void* data, int len);
ssize_t recv_data(context_t context, connection_t connection, stream_t stream, void* buf, ssize_t n_bytes, time_t timeout);

// server functions
int set_listen(context_t context);
connection_t accept_connection(context_t context, time_t timeout);
stream_t accept_stream(context_t context, connection_t connection, time_t timeout);

// common functions
int print_context(context_t context);
char* quic_error_message(quic_error_code_t quic_error);

#endif 