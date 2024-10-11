#ifndef QUICSAN_API_H
#define QUICSAN_API_H

#include <time.h>
#include <stdio.h>
#include <stdlib.h>

typedef void *context_t;
typedef void *connection_t;
typedef void *stream_t;

enum mode_t
{
    QUIC_CLIENT,
    QUIC_SERVER
};

// Define error codes
typedef enum {
    QUIC_SUCCESS,
    QUIC_ERROR_INVALID_ARGUMENT,
    QUIC_ERROR_CONNECTION_FAILED,
    QUIC_ERROR_STREAM_FAILED,
    QUIC_ERROR_SEND_FAILED,
    QUIC_ERROR_RECV_FAILED,
    QUIC_ERROR_TIMEOUT,
    QUIC_ERROR_UNKNOWN
} quic_error_code_t;

// Define error structure
typedef struct {
    quic_error_code_t code;
    const char *message;
} quic_error_t;

#define CONTROL_UPLOAD "UPLOAD"
#define CONTROL_DOWNLOAD "DOWNLOAD"
#define CONTROL_SINGLE "SINGLE"

context_t create_quic_context(char *cert_path, char *key_path);
void bind_addr(context_t context, char* ip, int port);

// client functions
connection_t open_connection(context_t context, char* ip, int port);
void close_connection(context_t context, connection_t connection);
stream_t open_stream(context_t context, connection_t connection);
void close_stream(context_t context, connection_t connection, stream_t stream);
void send_data(context_t context, connection_t connection, stream_t stream, void* data, int len);
ssize_t recv_data(context_t context, connection_t connection, stream_t stream, void* buf, ssize_t n_bytes, time_t timeout);

// server functions
void set_listen(context_t context);
connection_t accept_connection(context_t context, time_t timeout);
stream_t accept_stream(context_t context, connection_t connection, time_t timeout);

// common functions
int print_context(context_t context);

#endif 