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
#define DEFAULT_BUFSIZE 365
#define PORT 8080
#define SA struct sockaddr

void receive_content(int connfd)
{
	char read_buff[DEFAULT_BUFSIZE];
	memset(read_buff, 0, sizeof(read_buff));
	read(connfd, read_buff, sizeof(read_buff));
	printf("Request: %s\n", read_buff);
}

void write_reply(int request_size, int connfd)
{
	char content[request_size + 1];
	memset(content, 'a', request_size);
	content[request_size] = '\0'; // Null-terminate the string
	write(connfd, content, strlen(content));
	printf("Reply: %s\n", content);
}

int main()
{
	FILE *fp;
	fp = fopen("server.log", "w+");
	log_add_fp(fp, LOG_INFO);
	int sockfd, connfd;
	socklen_t len;
	struct sockaddr_in servaddr, cli;

	// socket create and verification
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1)
	{
		printf("Socket creation failed...\n");
		exit(0);
	}
	else
		printf("Socket successfully created..\n");
	memset(&servaddr, 0, sizeof(servaddr));

	// assign IP, PORT
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(PORT);

	// Binding newly created socket to given IP and verification
	if ((bind(sockfd, (SA *)&servaddr, sizeof(servaddr))) != 0)
	{
		printf("Socket bind failed...\n");
		exit(0);
	}
	else
		printf("Socket successfully binded..\n");

	// Now server is ready to listen and verification
	if ((listen(sockfd, 5)) != 0)
	{
		printf("Listen failed...\n");
		exit(0);
	}
	else
		printf("Server listening...\n");
	len = sizeof(cli);

	for (;;)
	{
		// Accept the data packet from client and verification
		connfd = accept(sockfd, (SA *)&cli, &len);
		if (connfd < 0)
		{
			printf("Server accept failed...\n");
			exit(0);
		}
		else
			printf("Server accept the client...\n");

		// Function for chatting between client and server
		receive_content(connfd);

		write_reply(20, connfd);

		close(connfd);
	}
	// After chatting close the socket
	close(sockfd);
}
