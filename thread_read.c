/* Use non portable functions */
#define _GNU_SOURCE

/* Public header */
#include "thread_read.h"

/* Standard / system libraries */
#include <errno.h>
#include <inttypes.h>

#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <syscall.h>
#include <time.h>
#include <unistd.h>

/* libIIO */
#include <iio.h>

/* Local modules */
#include "sdr_ip_gadget_types.h"
#include "epoll_loop.h"
#include "utils.h"
#include "sockets.h"

/* Set the following to periodically report statistics */
#ifndef GENERATE_STATS
#define GENERATE_STATS (0)
#endif

/* Set stats period */
#ifndef STATS_PERIOD_SECS
#define STATS_PERIOD_SECS (5)
#endif

/* Macros */
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define DEBUG_PRINT(...) if (debug) printf("Read: "__VA_ARGS__)

/* Type definitions */
typedef struct
{
	/* Thread args */
	THREAD_READ_Args_t *thread_args;

	/* Keep running */
	bool keep_running;

	/* epoll handler */
	int epoll_fd;

	/* socket to write to */
	int output_fd;

	/* IIO sample buffer */
	struct iio_buffer *iio_rx_buffer;

	/* Sample size (bytes) */
	size_t sample_size;

	/* Expected IIO buffer size (bytes) */
	size_t iio_buffer_size;

	size_t payload_size;
	struct {
		/* UDP packet payload size (bytes, UDP packet size with header removed) */
		size_t packet_payload_size;

		/* Number of UDP packets required to transfer buffer */
		size_t packets_per_buffer;

		/*
		** Array of message headers, io vectors and packet headers
		** Each msg has two io vectors, one for the header and one for the data
		*/
		struct mmsghdr *arr_mmsg_hdrs;
		struct iovec *arr_iovs;
		data_ip_hdr_t *arr_pkt_hdrs;
	} udp;
	struct {
		data_ip_hdr_t pkt_hdr;
	} tcp;

	/* Current sequence number / timestamp */
	uint64_t seqno;

	#if GENERATE_STATS
	int stats_timerfd;
	uint64_t stats_timer;

	uint64_t bytes_sent;
	uint32_t iio_calls;

	/* Overflow count */
	uint32_t overflows;

	/* Non sequential timestamp */
	uint32_t timestamp_misaligned;

	/* Read period timer */
	UTILS_TimeStats_t read_period;

	/* Read duration timer */
	UTILS_TimeStats_t read_dur;
	#endif

} state_t;

/* Epoll event handler */
typedef int (*epoll_event_handler)(state_t *state);

/* Global variables */
extern bool debug;
extern uint64_t start_time_usec;

/* Private functions */
static int handle_eventfd_thread(state_t *state);
static int handle_iio_buffer(state_t *state);
#if GENERATE_STATS
static int handle_stats_timer(state_t *state);
static int dump_stats(state_t *state);
#endif

static void udp_prepare(state_t *state);
static void tcp_prepare(state_t *state);
static int  udp_send(state_t *state, uint8_t *payload);
static int  tcp_send(state_t *state, uint8_t *payload);
static int  tcp_send_data(int sock, uint8_t *data, size_t size);

/* Public functions */
void *THREAD_READ_Entrypoint(void *args)
{
	THREAD_READ_Args_t *thread_args = (THREAD_READ_Args_t*)args;

	/* Enter */
	DEBUG_PRINT("Read thread enter (tid: %ld)\n", syscall(SYS_gettid));

	/* Set name, priority and CPU affinity */
	pthread_setname_np(pthread_self(), "IP_SDR_GAD_RD");
	UTILS_SetThreadRealtimePriority();
	UTILS_SetThreadAffinity(1);

	/* Reset state */
	state_t state;
	memset(&state, 0x00, sizeof(state));

	/* Store args */
	state.thread_args = thread_args;

	state.output_fd = create_data_socket(&state.thread_args->addr, state.thread_args->transport_tcp);
	if (state.output_fd < 0) {
		return NULL;
	}

	/* Create epoll instance */
	state.epoll_fd = epoll_create1(0);
	if (state.epoll_fd < 0)
	{
		perror("Failed to create epoll instance");
		return NULL;
	}
	else
	{
		DEBUG_PRINT("Opened epoll :-)\n");
	}

	struct epoll_event epoll_event;

	/* Register thread quit eventfd with epoll */
	epoll_event.events = EPOLLIN;
	epoll_event.data.ptr = handle_eventfd_thread;
	if (epoll_ctl(state.epoll_fd, EPOLL_CTL_ADD, thread_args->quit_event_fd, &epoll_event) < 0)
	{
		perror("Failed to register thread quit eventfd with epoll");
		return NULL;
	}
	else
	{
		DEBUG_PRINT("Registered thread quit eventfd with with epoll :-)\n");
	}

	/* Create IIO context */
	struct iio_context *iio_ctx = iio_create_local_context();
	if (!iio_ctx)
	{
		fprintf(stderr, "Failed to open iio\n");
		return NULL;
	}

	/* Retrieve RX streaming device */
	struct iio_device *iio_dev_rx = iio_context_find_device(iio_ctx, "cf-ad9361-lpc");
	if (!iio_dev_rx)
	{
		fprintf(stderr, "Failed to open iio rx dev\n");
		return NULL;
	}

	/* Disable all channels */
	unsigned int nb_channels = iio_device_get_channels_count(iio_dev_rx);
	DEBUG_PRINT("Found %i RX channels\n", nb_channels);
	for (unsigned int i = 0; i < nb_channels; i++)
	{
		iio_channel_disable(iio_device_get_channel(iio_dev_rx, i));
	}

	/* Enable required channels */
	int num_channels = 0;
	for (unsigned int i = 0; i < 32; i++)
	{
		/* Enable channel if required */
		if (thread_args->iio_channels & (1U << i))
		{
			/* Retrieve channel */
			struct iio_channel *channel = iio_device_get_channel(iio_dev_rx, i);
			if (!channel)
			{
				fprintf(stderr, "Failed to find iio rx chan %u\n", i);
				return false;
			}

			/* Enable channels */
			DEBUG_PRINT("Enable channel: %s, is scan element: %s\n",
						iio_channel_get_id(channel),
						iio_channel_is_scan_element(channel) ? "true" : "false");
			iio_channel_enable(channel);
			num_channels += 1;
		}
	}

	/* Create non-cyclic buffer */
	int iio_buffer_samples = thread_args->buffer_size_samples;
	if (state.thread_args->timestamping_enabled) {
		iio_buffer_samples += (num_channels == 2 ? 2 : 1);
	}

	state.iio_rx_buffer = iio_device_create_buffer(iio_dev_rx, iio_buffer_samples, false);
	if (!state.iio_rx_buffer)
	{
		fprintf(stderr, "Failed to create rx buffer for %zu samples\n", iio_buffer_samples);
		return NULL;
	}

	/* Register buffer with epoll */
	epoll_event.events = EPOLLIN;
	epoll_event.data.ptr = handle_iio_buffer;
	if (epoll_ctl(state.epoll_fd, EPOLL_CTL_ADD, iio_buffer_get_poll_fd(state.iio_rx_buffer), &epoll_event) < 0)
	{
		/* Failed to register IIO buffer with epoll */
		perror("Failed to register IIO buffer with epoll");
		return NULL;
	}
	else
	{
		DEBUG_PRINT("Registered IIO buffer with with epoll :-)\n");
	}

	/* Retrieve number of bytes between two samples of the same channel (aka size of one sample of all enabled channels) */
	state.sample_size = iio_buffer_step(state.iio_rx_buffer);

	/* Calculate expected buffer size */
	state.iio_buffer_size = state.sample_size * iio_buffer_samples;

	/* Calculate how many payload bytes are in an iio buffer */
	state.payload_size = state.iio_buffer_size;
	if (state.thread_args->timestamping_enabled)
	{
		/* Timestamp is included in IIO sample count by client library, we'll be moving it to the header, so subtract */
		state.payload_size -= sizeof(uint64_t);
	}

	/* Create and setup sendmmsg() iov vectors */
	if (state.thread_args->transport_tcp) {
		tcp_prepare(&state);
	} else {
		udp_prepare(&state);
	}

	/* Summarize info */
	DEBUG_PRINT("RX sample count: %zu, iio sample size: %zu, UDP packet size: %zu,  payload_size: %zu\n",
				thread_args->buffer_size_samples,
				state.sample_size,
				thread_args->udp_packet_size,
				state.payload_size);

	DEBUG_PRINT("Transport: %s\n", state.thread_args->transport_tcp ? "tcp" : "udp");
	DEBUG_PRINT("Timestamp increment: %u\n", state.thread_args->timestamp_increment);

	#if GENERATE_STATS
	/* Create stats reporting timer */
	state.stats_timerfd = timerfd_create(CLOCK_MONOTONIC, 0);
	if (state.stats_timerfd < 0)
	{
		perror("Failed to open timerfd");
		return NULL;
	}
	DEBUG_PRINT("Opened timerfd :-)\n");

	struct itimerspec timer_period =
	{
		.it_value = { .tv_sec = STATS_PERIOD_SECS, .tv_nsec = 0 },
		.it_interval = { .tv_sec = STATS_PERIOD_SECS, .tv_nsec = 0 }
	};
	if (timerfd_settime(state.stats_timerfd, 0, &timer_period, NULL) < 0)
	{
		perror("Failed to set timerfd");
		return NULL;
	}
	DEBUG_PRINT("Set timerfd :-)\n");

	/* Register timer with epoll */
	epoll_event.events = EPOLLIN;
	epoll_event.data.ptr = handle_stats_timer;
	if (epoll_ctl(state.epoll_fd, EPOLL_CTL_ADD, state.stats_timerfd, &epoll_event) < 0)
	{
		/* Failed to register timer with epoll */
		perror("Failed to register timer eventfd with epoll");
		return NULL;
	}
	DEBUG_PRINT("Registered timer with with epoll :-)\n");

	/* Init timer */
	UTILS_ResetTimeStats(&state.read_period);
	UTILS_ResetTimeStats(&state.read_dur);
	dump_stats(&state);	// prepare counters
	#endif

	/* Enter main loop */
	DEBUG_PRINT("Enter read loop..\n");
	state.keep_running = true;
	while (state.keep_running)
	{
		if (EPOLL_LOOP_Run(state.epoll_fd, 30000, &state) < 0)
		{
			/* Epoll failed...bail */
			break;
		}
	}
	DEBUG_PRINT("Exit read loop..\n");

	/* Close / destroy everything */
	#if GENERATE_STATS
	close(state.stats_timerfd);
	dump_stats(&state);
	#endif
	iio_buffer_destroy(state.iio_rx_buffer);
	iio_context_destroy(iio_ctx);
	close(state.epoll_fd);
	close(state.output_fd);

	/* Exit */
	DEBUG_PRINT("Read thread exit\n");

	return NULL;
}

/* Private functions */
static int handle_eventfd_thread(state_t *state)
{
	/* Quit having detected write on eventfd */
	DEBUG_PRINT("Stop request received\n");
	state->keep_running = false;

	return 0;
}

static int handle_iio_buffer(state_t *state)
{
	#if GENERATE_STATS
	/* Capture read period */
	UTILS_UpdateTimeStats(&state->read_period);

	/* Record read start time */
	UTILS_StartTimeStats(&state->read_dur);

	state->iio_calls += 1;
	#endif

	/* Refill buffer */
	ssize_t nbytes = iio_buffer_refill(state->iio_rx_buffer);
	if (nbytes != (ssize_t)state->iio_buffer_size)
	{
		fprintf(stderr, "RX buffer read failed, expected %zu, read %zd bytes\n", state->iio_buffer_size, nbytes);
		return -1;
	}

	#if GENERATE_STATS
	/* Capture read end time */
	UTILS_UpdateTimeStats(&state->read_dur);

	/* Record period start time (to subtract read time above) */
	UTILS_StartTimeStats(&state->read_period);
	#endif

	/* Retrieve buffer ptr */
	uint8_t *buffer = iio_buffer_start(state->iio_rx_buffer);
	size_t bytes_to_send = state->iio_buffer_size;

	if (state->thread_args->timestamping_enabled)
	{
		/* Update sequence number from IIO buffer, advance pointer, decrement size */
		uint64_t seqno = *((uint64_t*)buffer);
		buffer += sizeof(uint64_t);
		bytes_to_send -= sizeof(uint64_t);

		if (abs(seqno - state->seqno) > 1) {
			DEBUG_PRINT("Timestamp misaligned: expected seqno=%" PRIu64 " buffer seqno %" PRIu64 " delta %" PRId64 "\n",
					state->seqno, seqno,
					seqno - state->seqno);
			#if GENERATE_STATS
			state->timestamp_misaligned += 1;
			#endif
		}
		state->seqno = seqno;
	}

	/* Send data to the remote peer */
	int ret;
	if (state->thread_args->transport_tcp) {
		ret = tcp_send(state, buffer);
	} else {
		ret = udp_send(state, buffer);
	}
	if (ret < 0)
		return ret;

	/* Update timestamp sequence to point the end of the buffer */
	state->seqno += state->thread_args->timestamp_increment;

	#if GENERATE_STATS
	dump_stats(state);
	#endif

	return 0;
}

/*
** Handle socket operations UDP/TCP
*/
static void udp_prepare(state_t *state)
{
	/* Calculate how many payload bytes fit into a packet */
	state->udp.packet_payload_size = state->thread_args->udp_packet_size - sizeof(data_ip_hdr_t);

	/* Calculate packets required to transfer a buffer, rounding up */
	state->udp.packets_per_buffer = (state->payload_size + (state->udp.packet_payload_size - 1U)) / state->udp.packet_payload_size;

	/* Allocate multiple message header structure, which will hold pointers to individual messages and send results */
	state->udp.arr_mmsg_hdrs = calloc(state->udp.packets_per_buffer, sizeof(struct mmsghdr));

	/* For each msg we require two io vectors (one for the header and one for the data) */
	state->udp.arr_iovs = calloc(2 * state->udp.packets_per_buffer, sizeof(struct iovec));

	/* We require a fixed header for each data block */
	state->udp.arr_pkt_hdrs = calloc(state->udp.packets_per_buffer, sizeof(data_ip_hdr_t));

	/* Pre-populate fixed fields */
	for (size_t i = 0; i < state->udp.packets_per_buffer; i++)
	{
		/* Each message makes use of two IOVs (one for the header and one for the data) */
		state->udp.arr_mmsg_hdrs[i].msg_hdr.msg_iov = &state->udp.arr_iovs[2 * i];
		state->udp.arr_mmsg_hdrs[i].msg_hdr.msg_iovlen = 2;

		/* First IOV of each pair points at packet header, next will point at payload and be updated just before tranmission */
		state->udp.arr_iovs[(2 * i) + 0].iov_base = &state->udp.arr_pkt_hdrs[i];
		state->udp.arr_iovs[(2 * i) + 0].iov_len = sizeof(data_ip_hdr_t);

		if (i < (state->udp.packets_per_buffer - 1)) {
			/* Not the last packet, therefore must be full */
			state->udp.arr_iovs[(2 * i) + 1].iov_len = state->udp.packet_payload_size;
		} else {
			/* Last packet, work out how many bytes of the payload it will contain */
			state->udp.arr_iovs[(2 * i) + 1].iov_len = state->payload_size % state->udp.packet_payload_size;
		}

		/* Prepare packet headers, just need to fill in the sequence number at transmission time */
		state->udp.arr_pkt_hdrs[i].magic = SDR_IP_GADGET_MAGIC;
		state->udp.arr_pkt_hdrs[i].block_index = (uint16_t)i;
		state->udp.arr_pkt_hdrs[i].block_count = (uint16_t)state->udp.packets_per_buffer;
	}

	DEBUG_PRINT("UDP socket: UDP packet size: %zu, packet_payload_size: %u, packets_per_buffer: %u\n",
			state->thread_args->udp_packet_size,
			state->udp.packet_payload_size,
			state->udp.packets_per_buffer);
}

static void tcp_prepare(state_t *state)
{
	/* prepare packet header */
	state->tcp.pkt_hdr.magic = SDR_IP_GADGET_MAGIC;
	state->tcp.pkt_hdr.block_index = 0;
	state->tcp.pkt_hdr.block_count = 1;
}

static int udp_send(state_t *state, uint8_t *buffer)
{
	/* Prepare multi-message send structures */
	for (size_t i = 0; i < state->udp.packets_per_buffer; i++)
	{
		/* Set sequence number for packet */
		state->udp.arr_pkt_hdrs[i].seqno = state->seqno;

		/* Set data pointer for packet */
		state->udp.arr_iovs[(2 * i) + 1].iov_base = buffer;
		buffer += state->udp.packet_payload_size;
	}

	/* Send all datagrams with single system call :-) */
	int ret;
	for(;;) {
		ret = sendmmsg(state->output_fd,
						state->udp.arr_mmsg_hdrs,
						state->udp.packets_per_buffer,
						0);
		if (ret < 0 && (EWOULDBLOCK == errno) || (EAGAIN == errno))
			continue;
		break;
	}
	if (state->udp.packets_per_buffer != ret)
	{
		if (ret < 0) {
			perror("sendmmsg() failed");
			return -1;
		}
		#if GENERATE_STATS
		/* Count overflow */
		state->overflows += (state->udp.packets_per_buffer - ret);
		state->bytes_sent += ret * state->udp.packet_payload_size;
		#endif
	} else {
		#if GENERATE_STATS
		state->bytes_sent += state->payload_size;
		#endif
	}

	return 0;
}

static int tcp_send_data(int sock, uint8_t *data, size_t size)
{
	size_t offset = 0;
	while ((offset < size)) {
		int rc = sendto(sock, (const void *)&data[offset], size - offset, MSG_NOSIGNAL, NULL, 0);
		if (rc < 0) {
			if (EWOULDBLOCK == errno || EAGAIN == errno)
				continue;
			perror("TCP: Failed to send on data socket");
			return -1;
		}
		offset += rc;
	}
	return offset;
}

static int tcp_send(state_t *state, uint8_t *payload)
{
	int ret;

	state->tcp.pkt_hdr.seqno = state->seqno;

	ret = tcp_send_data(state->output_fd,
					(uint8_t *)&state->tcp.pkt_hdr, sizeof(data_ip_hdr_t));
	if (ret != sizeof(data_ip_hdr_t))
		return -1;

	ret = tcp_send_data(state->output_fd, payload, state->payload_size);
	if (ret != (int)state->payload_size)
		return -1;

	#if GENERATE_STATS
	state->bytes_sent += state->payload_size;
	#endif
	return 0;
}


#if GENERATE_STATS
static int handle_stats_timer(state_t *state)
{
	return dump_stats(state);
}

static int dump_stats(state_t *state)
{
	const uint64_t now_usec = UTILS_GetMonotonicMicros();
	if (state->stats_timer == 0)
		goto done;

	const uint64_t delta_usec = now_usec - state->stats_timer;
	if (delta_usec < (STATS_PERIOD_SECS * US_PER_SEC))
		return 0;

	const uint64_t uptime_usec = now_usec - start_time_usec;
	printf("STATS|Read: %" PRIu64 "+%" PRIu64 "\n",
			uptime_usec / US_PER_SEC,
			uptime_usec % US_PER_SEC);

	/* Report min/max/average read period */
	printf("\tperiod: min: %"PRIu64", max: %"PRIu64", avg: %"PRIu64" (uS)\n",
			state->read_period.min,
			state->read_period.max,
			UTILS_CalcAverageTimeStats(&state->read_period)
	);

	/* Report min/max/average read duration */
	printf("\tdur: min: %"PRIu64", max: %"PRIu64", avg: %"PRIu64" (uS)\n",
			state->read_dur.min,
			state->read_dur.max,
			UTILS_CalcAverageTimeStats(&state->read_dur)
	);

	printf("\tbytes=%"PRIu64" iio_calls=%"PRIu32"\n", state->bytes_sent, state->iio_calls);

	if (state->overflows) {
		printf("\toverflows=%"PRIu32"\n", state->overflows);
	}

	if (state->timestamp_misaligned) {
		printf("\ttimestamp_misaligned=%u\n", state->timestamp_misaligned);
	}

	/* Reset stats */
	UTILS_ResetTimeStats(&state->read_period);
	UTILS_ResetTimeStats(&state->read_dur);

done:
	state->stats_timer = now_usec;
	state->bytes_sent = 0;
	state->iio_calls = 0;
	state->timestamp_misaligned = 0;
	state->overflows = 0;

	return 0;
}
#endif
