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
#include "quicsand_api.h"
#include "utils.h"

int main()
{
	FILE *fp;
	fp = fopen("server.log", "w+");
	log_add_fp(fp, LOG_INFO);

	config_t *config = read_config("config.yaml");
	if (!config)
	{
		fprintf(stderr, "Error: Failed to read configuration file\n");
		exit(EXIT_FAILURE);
	}

	context_t ctx = create_quic_context();
	fprintf(stderr, "Created context\n");
	bind_addr(ctx, config->target, atoi(config->port));
}
