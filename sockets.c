
#include <errno.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include <fcntl.h>
#include <netinet/tcp.h>


#include "sdr_ip_gadget_types.h"
#include "sockets.h"

/* Global variables */
extern bool debug;

#define DEBUG_PRINT(...) if (debug) printf("Socket: "__VA_ARGS__)

int create_data_socket(struct sockaddr_in *peer_addr, bool use_tcp)
{
	int sock = -1;
	int optval;

	sock = socket(AF_INET, use_tcp ? SOCK_STREAM : SOCK_DGRAM, 0);
	if (sock < 0)
	{
		perror("Failed to open data socket");
		return -1;
	}
	DEBUG_PRINT("Opened data socket :-)\n");

	optval = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) == -1) {
		perror("setsockopt(SO_REUSEADDR) failed for data socket");
		close(sock);
		return -1;
	}

	if (fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) & ~O_NONBLOCK))
	{
		perror("Failed to set data socket mode to blocking mode");
		close(sock);
		return -1;
	}

	// Get the current send buffer size
	int send_size;
	socklen_t size_len = sizeof(send_size);
	if (getsockopt(sock, SOL_SOCKET, SO_SNDBUF, &send_size, &size_len) == -1)
	{
		perror("getsockopt for send buffer size");
		close(sock);
		return -1;
	}

	// Get the current receive buffer size
	int recv_size;
	size_len = sizeof(recv_size);
	if (getsockopt(sock, SOL_SOCKET, SO_RCVBUF, &recv_size, &size_len) == -1)
	{
		perror("getsockopt for receive buffer size");
		close(sock);
		return -1;
	}

	// Report current sizes
	DEBUG_PRINT("Current data socket send = %d receive = %d\n", send_size, recv_size);

	// Set the recv buffer size
	recv_size = 8*1024*1024;
	if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &recv_size, sizeof(send_size)) == -1)
	{
		perror("setsockopt for recv buffer size");
		close(sock);
		return -1;
	}
	// Get the updated recv buffer size
	size_len = sizeof(recv_size);
	if (getsockopt(sock, SOL_SOCKET, SO_RCVBUF, &recv_size, &size_len) == -1)
	{
		perror("getsockopt for recv buffer size");
		close(sock);
		return -1;
	}

	// Set the send buffer size
	send_size = 8*1024*1024;
	if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &send_size, sizeof(send_size)) == -1)
	{
		perror("setsockopt for send buffer size");
		close(sock);
		return -1;
	}
	// Get the updated send buffer size
	size_len = sizeof(send_size);
	if (getsockopt(sock, SOL_SOCKET, SO_SNDBUF, &send_size, &size_len) == -1)
	{
		perror("getsockopt for send buffer size");
		close(sock);
		return -1;
	}

	// Report updated sizes
	DEBUG_PRINT("Updated socket send = %d receive = %d\n", send_size, recv_size);

	// Set receive timeout on data socket
	struct timeval timeout;
	timeout.tv_sec = 1;
	timeout.tv_usec = 0;
	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
		perror("failed to set receive timeout");
		close(sock);
		return -1;
	}
	timeout.tv_sec = 1;
	timeout.tv_usec = 0;
	if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
		perror("failed to set send timeout");
		close(sock);
		return -1;
	}


	/* Bind to local port and connect to remote peer */
	struct sockaddr_in addr;
	memset(&addr, 0x00, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(DIRECT_IP_PORT_DATA);
	if (bind(sock, (const struct sockaddr *)&addr, sizeof(addr)))
	{
		perror("Failed to bind data socket");
		close(sock);
		return -1;
	}
	DEBUG_PRINT("Bound data socket :-)\n");

	memcpy(&addr, peer_addr, sizeof(addr));
	if (connect(sock, (struct sockaddr*)&addr, sizeof(addr))) {
		perror("failed to connect data socket");
		close(sock);
		return -1;
	}
	DEBUG_PRINT("Connected data socket :-)\n");

	/* for TCP socket enable keep-alive */
	if (use_tcp) {
		optval = 1;
		if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval)) < 0) {
			perror("failed to set TCP_NODELAY failed");
			close(sock);
			return -1;
		}

		optval = 1;
		setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval));
		optval = 1;
		setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &optval, sizeof(optval));
		optval = 1;
		setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &optval, sizeof(optval));
		optval = 5;
		setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &optval, sizeof(optval));
	}

	return sock;
}
