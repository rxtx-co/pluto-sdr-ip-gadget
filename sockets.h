#ifndef __SOCKETS_H__
#define __SOCKETS_H__

/* Standard libraries */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <netinet/in.h>

int create_data_socket(struct sockaddr_in *peer_addr, bool use_tcp);

#endif
