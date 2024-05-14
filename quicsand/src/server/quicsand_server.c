#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <log.h>
#include "quicsand_server_adapter.h"
#define DEFAULT_BUFSIZE 365
#define PORT 8080
#define SA struct sockaddr

int main()
{
	FILE *fp;
	fp = fopen("server.log", "w+");
	log_add_fp(fp, LOG_INFO);

	server_init();
	server_shutdown();
}
