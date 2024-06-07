#ifndef QUICSAND_SERVER_ADAPTER_H
#define QUICSAND_SERVER_ADAPTER_H

#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

typedef void *Server_CTX;

Server_CTX server_init(Config *config);
void server_shutdown(Server_CTX ctx);

#endif // QUICSAND_CLIENT_ADAPTER_H