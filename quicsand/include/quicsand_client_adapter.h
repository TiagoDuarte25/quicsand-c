#ifndef QUICSAND_CLIENT_ADAPTER_H
#define QUICSAND_CLIENT_ADAPTER_H

#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <netinet/in.h>
#include <sys/socket.h>

typedef void *Client_CTX;

void open_connection(Client_CTX ctx);
void close_connection(Client_CTX ctx);
void open_stream(Client_CTX ctx);
void close_stream(Client_CTX ctx);
void send_data(Client_CTX ctx, int *reqsize);
void receive_data(Client_CTX ctx);
void client_init(Config *config, Client_CTX *ctx, char *target_ip);
void client_shutdown(Client_CTX ctx);

#endif // QUICSAND_CLIENT_ADAPTER_H