#ifndef QUICSAND_CLIENT_ADAPTER_H
#define QUICSAND_CLIENT_ADAPTER_H

#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <netinet/in.h>
#include <sys/socket.h>

typedef void *Connection;
typedef void *Stream;

Connection open_connection(Config *conf);
void close_connection(Connection conn);
Stream open_stream(Connection connection);
void close_stream(Stream stream);
void send_data(Connection connnection, Stream stream, int *reqsize);
void receive_data();
Config *client_init();
void client_shutdown();

#endif // QUICSAND_CLIENT_ADAPTER_H