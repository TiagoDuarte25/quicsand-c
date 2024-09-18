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
				fprintf(stderr, "Usage: %s -c <cert_path> -k <key_path> -i <ip_address> -p <port>\n", argv[0]);
				exit(EXIT_FAILURE);
        }
    }

    // Print the parsed options for debugging
	printf("Certificate Path: %s\n", cert_path);
	printf("Key Path: %s\n", key_path);
	printf("IP Address: %s\n", ip_address);
	printf("Port: %d\n", port);

	// Ensure required options are provided
	if (!cert_path || !key_path || !ip_address || port == 0) {
		fprintf(stderr, "Usage: %s -c <cert_path> -k <key_path> -i <ip_address> -p <port>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	FILE *fp;
	fp = fopen("server.log", "w+");
	log_add_fp(fp, LOG_INFO);

	config_t *config = read_config("config.yaml");
	if (!config)
	{
		fprintf(stderr, "Error: Failed to read configuration file\n");
		exit(EXIT_FAILURE);
	}

	context_t ctx = create_quic_context(cert_path, key_path);
	fprintf(stderr, "Created context\n");
	bind_addr(ctx, ip_address, port);
	fprintf(stderr, "Bound address\n");
	set_listen(ctx);
	fprintf(stderr, "Listening\n");
	connection_t connection = accept_connection(ctx, 0);
	fprintf(stderr, "Accepted connection\n");
	stream_t stream = accept_stream(ctx, connection, 0);
	fprintf(stderr, "Accepted stream\n");
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
			fprintf(stderr, "Received data: %.*s\n", (int)len, data);
		} else {
			fprintf(stderr, "No data received or error occurred\n");
		}
		char *response = "Hello, client!";
		send_data(ctx, connection, stream, response, strlen(response));
	}
	getchar();
}
