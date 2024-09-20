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

int main(int argc, char *argv[])
{
	char *cert_path = NULL;
    char *key_path = NULL;
	char *ip_address = NULL;
	int port = 0;
    int opt;

	FILE *fp = fopen("server.log", "w+");

    // Parse command-line arguments
    while ((opt = getopt(argc, argv, "c:k:i:p:")) != -1) {
        switch (opt) {
            case 'c':
                cert_path = strdup(optarg);
                break;
            case 'k':
                key_path = strdup(optarg);
                break;
            case 'i':
            	ip_address = strdup(optarg);
            	break;
			case 'p':
				port = atoi(optarg);
				break;
			default:
				fprintf(fp, "Usage: %s -c <cert_path> -k <key_path> -i <ip_address> -p <port>\n", argv[0]);
				exit(EXIT_FAILURE);
        }
    }

    // Print the parsed options for debugging
	fprintf(fp, "Certificate Path: %s\n", cert_path);
	fprintf(fp, "Key Path: %s\n", key_path);
	fprintf(fp, "IP Address: %s\n", ip_address);
	fprintf(fp, "Port: %d\n", port);

	// Ensure required options are provided
	if (!cert_path || !key_path || !ip_address || port == 0) {
		fprintf(fp, "Usage: %s -c <cert_path> -k <key_path> -i <ip_address> -p <port>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	log_add_fp(fp, LOG_INFO);

	config_t *config = read_config("config.yaml");
	if (!config)
	{
		fprintf(fp, "Error: Failed to read configuration file\n");
		exit(EXIT_FAILURE);
	}

	context_t ctx = create_quic_context(cert_path, key_path);
	fprintf(fp, "Created context\n");
	bind_addr(ctx, ip_address, port);
	fprintf(fp, "Bound address\n");
	set_listen(ctx);
	fprintf(fp, "Listening\n");
	connection_t connection = accept_connection(ctx, 0);
	fprintf(fp, "Accepted connection\n");
	stream_t stream = accept_stream(ctx, connection, 0);
	fprintf(fp, "Accepted stream\n");
	while(1) {
		char data[1024];
		ssize_t len = recv_data(ctx, connection, data, 0);
		if (len > 0) {
			// Ensure the data is null-terminated
			if (len < sizeof(data)) {
				data[len] = '\0';
			} else {
				data[sizeof(data) - 1] = '\0';
			}
			fprintf(fp, "Received data: %.*s\n", (int)len, data);
		} else {
			fprintf(fp, "No data received or error occurred\n");
		}
		char *response = "Hello, client!";
		send_data(ctx, connection, stream, response, strlen(response));
	}
	getchar();
}
