#ifndef __THREAD_READ_H__
#define __THREAD_READ_H__

/* Standard libraries */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <netinet/in.h>

/* Type definitions - thread args */
typedef struct
{
	/* Eventfd used to signal thread to quit */
	int quit_event_fd;

	/* Client address */
	struct sockaddr_in addr;

	/* Enabled channels */
	uint32_t iio_channels;

	/* Timestamping enabled */
	bool timestamping_enabled;

	/* Timestamp increment per buffer adjusted to timestamp clock rate */
	uint32_t timestamp_increment;

	/* Data transport tcp/udp */
	bool transport_tcp;

	/* Sample buffer size (in samples) */
	size_t buffer_size_samples;

	/* UDP packet size (in bytes) */
	size_t udp_packet_size;

} THREAD_READ_Args_t;

/* Public functions - Thread entrypoint */
void *THREAD_READ_Entrypoint(void *args);

#endif
