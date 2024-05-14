#ifndef QUICSAND_SERVER_ADAPTER_H
#define QUICSAND_SERVER_ADAPTER_H

#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

typedef void *Connection;
typedef void *Stream;

void server_init();
void server_shutdown();

#endif // QUICSAND_CLIENT_ADAPTER_H