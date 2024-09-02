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

context_t create_quic_context(mode_t mode);
void bind_addr(context_t context, char* ip, int port);

// client functions
connection_t open_connection(context_t context, char* ip, int port);
void close_connection(context_t context, connection_t connection);
stream_t open_stream(context_t context, connection_t connection);
void close_stream(context_t context, connection_t connection, stream_t stream);
void send_data(context_t context, connection_t connection, stream_t stream, char* data, int len);
char* recv_data(context_t context, connection_t connection, int buffer_size, time_t timeout);

// server functions
void set_listen(context_t context);
connection_t accept_connection(context_t context, time_t timeout);
stream_t accept_stream(context_t context, connection_t connection, time_t timeout);

#endif 