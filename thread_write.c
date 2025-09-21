/* Use non portable functions */
#define _GNU_SOURCE

/* Public header */
#include "thread_write.h"

/* Standard / system libraries */
#include <assert.h>
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
#define DEBUG_PRINT(...) if (debug) printf("Write: "__VA_ARGS__)

/* Type definitions */
typedef struct
{
	/* Thread args */
	THREAD_WRITE_Args_t *thread_args;

	/* epoll handler */
	int epoll_fd;

	/* socket to read from */
	int input_fd;

	/* iio_buffer file descriptor for epoll */
	int iio_buf_fd;

	/* Keep running */
	bool keep_running;

	/* IIO sample buffer */
	struct iio_buffer *iio_tx_buffer;
	uint8_t *buffer;

	/* Sample size */
	size_t sample_size;

	/* Expected IIO buffer size (bytes) with timestamp */
	size_t iio_buffer_size;

	/* Current block index / count */
	uint16_t block_index;
	uint16_t block_count;

	/* Current sequence number / timestamp */
	uint64_t seqno;

	/* Current amount of IIO buffer space used (bytes) */
	size_t iio_buffer_used;

	/* UDP recvmsg() struct */
	struct {
		struct msghdr msg;
		struct iovec iov[2];
	} udp;

	#if GENERATE_STATS
	uint64_t stats_timer;

	uint64_t socket_recv;
	uint64_t iio_bytes;
	uint32_t iio_calls;

	/* Count time wraps */
	uint32_t time_wraps;
	uint32_t time_gaps;

	/* Drop count (due to bad index) */
	uint32_t dropped_index;

	/* Partial buffer pushes (due to out of order seq no) */
	uint32_t out_of_order;

	/* Overflow count */
	uint32_t overflows;

	/* Write period timer */
	UTILS_TimeStats_t write_period;

	/* Write duration timer */
	UTILS_TimeStats_t write_dur;
	#endif

} state_t;

/* Epoll event handler */
typedef int (*epoll_event_handler)(state_t *state);

/* Global variables */
extern bool debug;
extern uint64_t start_time_usec;

/* Private functions */
static int handle_eventfd_thread(state_t *state);
static int handle_socket(state_t *state);
static int handle_iio_push(state_t *state);
#if GENERATE_STATS
static int dump_stats(state_t *state);
#endif

static int update_state(state_t *state, data_ip_hdr_t *hdr);

static int udp_recv(state_t *state, data_ip_hdr_t *hdr, uint8_t *buffer, size_t buffer_offset);
static int tcp_recv(state_t *state, data_ip_hdr_t *hdr, uint8_t *buffer, size_t buffer_offset);

static void epoll_enable_socket(state_t *state);
static void epoll_disable_socket(state_t *state);
static void epoll_enable_iio(state_t *state);

/* Public functions */
void *THREAD_WRITE_Entrypoint(void *args)
{
	THREAD_WRITE_Args_t *thread_args = (THREAD_WRITE_Args_t*)args;

	/* Enter */
	DEBUG_PRINT("Write thread enter (tid: %ld)\n", syscall(SYS_gettid));

	/* Set name, priority and CPU affinity */
	pthread_setname_np(pthread_self(), "IP_SDR_GAD_WR");
	UTILS_SetThreadRealtimePriority();
	UTILS_SetThreadAffinity(1);

	/* Reset state */
	state_t state;
	memset(&state, 0x00, sizeof(state));

	/* Store args */
	state.thread_args = thread_args;

	state.input_fd = create_data_socket(&state.thread_args->addr, state.thread_args->transport_tcp);
	if (state.input_fd < 0) {
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

	/* Retrieve TX streaming device */
	struct iio_device *iio_dev_tx = iio_context_find_device(iio_ctx, "cf-ad9361-dds-core-lpc");
	if (!iio_dev_tx)
	{
		fprintf(stderr, "Failed to open iio tx dev\n");
		return NULL;
	}

	/* Disable all channels */
	unsigned int nb_channels = iio_device_get_channels_count(iio_dev_tx);
	DEBUG_PRINT("Found %i TX channels\n", nb_channels);
	for (unsigned int i = 0; i < nb_channels; i++)
	{
		iio_channel_disable(iio_device_get_channel(iio_dev_tx, i));
	}

	/* Enable required channels */
	int num_channels = 0;
	for (unsigned int i = 0; i < 32; i++)
	{
		/* Enable channel if required */
		if (thread_args->iio_channels & (1U << i))
		{
			/* Retrieve channel */
			struct iio_channel *channel = iio_device_get_channel(iio_dev_tx, i);
			if (!channel)
			{
				fprintf(stderr, "Failed to find iio rx chan %u\n", i);
				return NULL;
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

	state.iio_tx_buffer = iio_device_create_buffer(iio_dev_tx, iio_buffer_samples, false);
	if (!state.iio_tx_buffer)
	{
		fprintf(stderr, "Failed to create tx buffer for %zu samples\n", iio_buffer_samples);
		return NULL;
	}

	/* Retrieve number of bytes between two samples of the same channel (aka size of one sample of all enabled channels) */
	state.sample_size = iio_buffer_step(state.iio_tx_buffer);

	/* Calculate expected buffer size */
	state.iio_buffer_size = state.sample_size * iio_buffer_samples;

	/* Summarize info */
	DEBUG_PRINT("TX sample count: %zu, iio sample size: %zu\n",
				iio_buffer_samples,
				state.sample_size);

	DEBUG_PRINT("Transport: %s\n", state.thread_args->transport_tcp ? "tcp" : "udp");
	DEBUG_PRINT("Timestamp increment: %zu\n", state.thread_args->timestamp_increment);

	/* Prepare scatter/gather structures */
	memset(&state.udp.msg, 0, sizeof(state.udp.msg));
	state.udp.msg.msg_iov = state.udp.iov;
	state.udp.msg.msg_iovlen = 2;

	/* Register data socket with epoll */
	epoll_event.events = EPOLLIN;
	epoll_event.data.ptr = handle_socket;
	if (epoll_ctl(state.epoll_fd, EPOLL_CTL_ADD, state.input_fd, &epoll_event) < 0)
	{
		perror("Failed to register data socket readable with epoll");
		return NULL;
	}
	else
	{
		DEBUG_PRINT("Registered data socket readable with epoll :-)\n");
	}

	/* Register buffer with epoll */
	state.iio_buf_fd = iio_buffer_get_poll_fd(state.iio_tx_buffer);
	epoll_event.events = 0; // will be enabled with epoll_enable_iio(); (EPOLLOUT | EPOLLONESHOT)
	epoll_event.data.ptr = handle_iio_push;
	if (epoll_ctl(state.epoll_fd, EPOLL_CTL_ADD, state.iio_buf_fd, &epoll_event) < 0)
	{
		/* Failed to register IIO buffer with epoll */
		perror("Failed to register IIO buffer with epoll");
		return NULL;
	}
	else
	{
		DEBUG_PRINT("Registered IIO buffer with with epoll :-)\n");
	}

	#if GENERATE_STATS
	/* Init timers */
	UTILS_ResetTimeStats(&state.write_period);
	UTILS_ResetTimeStats(&state.write_dur);
	dump_stats(&state);
	#endif

	/* Enter main loop */
	DEBUG_PRINT("Enter write loop..\n");
	state.keep_running = true;
	while (state.keep_running)
	{
		if (EPOLL_LOOP_Run(state.epoll_fd, 30000, &state) < 0)
		{
			/* Epoll failed...bail */
			break;
		}
	}
	DEBUG_PRINT("Exit write loop..\n");

	/* Close / destroy everything */
	close(state.input_fd);
	close(state.epoll_fd);
	iio_buffer_destroy(state.iio_tx_buffer);
	iio_context_destroy(iio_ctx);

	/* Exit */
	DEBUG_PRINT("Write thread exit\n");

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

static int handle_socket(state_t *state)
{
	/* Is buffer full? */
	if (state->iio_buffer_size <= state->iio_buffer_used) {
		state->buffer = NULL;
		epoll_disable_socket(state);
		epoll_enable_iio(state);
		return 0;
	}

	/* Retrieve buffer address */
	if (state->buffer == NULL) {
		state->buffer = iio_buffer_start(state->iio_tx_buffer);
		state->iio_buffer_used = 0;
	}

	uint8_t *buffer = state->buffer;
	size_t buffer_offset = state->iio_buffer_used;
	size_t buffer_size = state->iio_buffer_size - buffer_offset;

	const bool prepend_timestamp = (0 == state->iio_buffer_used)		// first block
									&& (state->thread_args->timestamping_enabled);

	/* Reserve space at head of buffer for timestamp */
	if (prepend_timestamp) {
		buffer_size -= sizeof(uint64_t);
		buffer_offset += sizeof(uint64_t);
	}

	/* Prepare data packet header */
	data_ip_hdr_t pkt_hdr;

	int rc;
	if (state->thread_args->transport_tcp) {
		rc = tcp_recv(state, &pkt_hdr, &buffer[buffer_offset], buffer_size);
	} else {
		rc = udp_recv(state, &pkt_hdr, &buffer[buffer_offset], buffer_size);
	}
	if (rc <= 0)
		return rc;

	#if GENERATE_STATS
	state->socket_recv += rc;
	#endif

	if (update_state(state, &pkt_hdr) < 0)
		return 0;

	/* Update buffer used */
	state->iio_buffer_used += (size_t)rc;

	if (prepend_timestamp)
	{
		*((uint64_t*)buffer) = pkt_hdr.seqno;
		state->iio_buffer_used += sizeof(uint64_t);
	}

	/* Is buffer full? */
	if (state->iio_buffer_size <= state->iio_buffer_used)
	{
		assert(state->iio_buffer_size == state->iio_buffer_used);
		state->buffer = NULL;

		epoll_disable_socket(state);
		epoll_enable_iio(state);

		//usleep(16400);
		//state->seqno += state->thread_args->timestamp_increment;
		//state->iio_buffer_used = 0;
	}

	#if GENERATE_STATS
	dump_stats(state);
	#endif
	return 0;
}

static int handle_iio_push(state_t *state)
{
	if (state->iio_buffer_size > state->iio_buffer_used) {
		epoll_enable_socket(state);
		return 0;
	}
	assert(state->iio_buffer_size == state->iio_buffer_used);

	/* Yep, get ready to send it */
	#if GENERATE_STATS
	/* Capture write period */
	UTILS_UpdateTimeStats(&state->write_period);

	/* Record write start time */
	UTILS_StartTimeStats(&state->write_dur);
	#endif

	/* Perform blocking write */
	ssize_t nbytes = iio_buffer_push(state->iio_tx_buffer);
	if (nbytes != (ssize_t)state->iio_buffer_size)
	{
		DEBUG_PRINT("IIO: iio_buffer_push failed, nbytes=%d\n", nbytes);

		#if GENERATE_STATS
		/* Count overflow */
		state->overflows++;
		#endif

		if (nbytes <= 0) {
			perror("iio_buffer_push() failed");
			epoll_disable_socket(state);
			epoll_enable_iio(state);
			return 0;
		}
	}

	#if GENERATE_STATS
	state->iio_bytes += nbytes;
	state->iio_calls += 1;

	/* Capture write end time */
	UTILS_UpdateTimeStats(&state->write_dur);

	/* Record period start time (to subtract write time above) */
	UTILS_StartTimeStats(&state->write_period);
	#endif

	/* Reset buffer used */
	state->iio_buffer_used = 0;

	/* Advance sequence number */
	state->seqno += state->thread_args->timestamp_increment;

	epoll_enable_socket(state);

	#if GENERATE_STATS
	dump_stats(state);
	#endif
	return 0;
}

static int update_state(state_t *state, data_ip_hdr_t *hdr)
{
	// fprintf(stderr, "PKT: last.seqno=%" PRIu64 " seqno=%" PRIu64 " block_index=%u block_count=%u\n", 
	// 				state->seqno,
	// 				hdr->seqno,
	// 				hdr->block_index,
	// 				hdr->block_count);

	/*
	** Check packet sequence number / timestamp, discarding any out of order packets
	** Note this is fragile against time warps
	*/
	if (0 == state->iio_buffer_used)
	{
		/* Check packet starts sequence */
		if (0 != hdr->block_index)
		{
			#if GENERATE_STATS
			/* Count dropped datagram */
			state->dropped_index++;
			#endif

			/* Drop packet, waiting for sequence start */
			return -1;
		}

		/* check seqno */
		if (hdr->seqno < state->seqno) {
			#if GENERATE_STATS
			state->time_wraps++;
			#endif
			DEBUG_PRINT("time wraps: last seqno=%" PRIu64 " hdr.seqno=%" PRIu64 " delta=%" PRId64 "\n",
				state->seqno,
				hdr->seqno,
				(state->seqno - hdr->seqno));
		} else
		if (hdr->seqno != state->seqno) {
			#if GENERATE_STATS
			state->time_gaps++;
			#endif
			DEBUG_PRINT("time gap: last seqno=%" PRIu64 " hdr.seqno=%" PRIu64 " delta=%" PRId64 "\n",
				state->seqno,
				hdr->seqno,
				(hdr->seqno - state->seqno));
		}

		/* First block: update the state */
		state->block_index = 0;
		state->block_count = hdr->block_count;
		state->seqno = hdr->seqno;
	}
	else
	{
		/* Check index, total and timestamp match */
		if (((state->block_index + 1) != hdr->block_index)
			|| (state->block_count != hdr->block_count)
			|| (state->seqno != hdr->seqno))
		{
			/* Either an out of order, or duplicate block */
			#if GENERATE_STATS
			/* Count out-of-order datagram */
			state->out_of_order++;
			#endif

			/* Reset buffer */
			state->iio_buffer_used = 0;

			/* Drop packet */
			return -1;
		}

		state->block_index = hdr->block_index;
	}

	return 0;
}

/*
** Handle socket receive UDP/TCP
*/
static int udp_recv(state_t *state, data_ip_hdr_t *hdr, uint8_t *payload, size_t payload_size)
{
	state->udp.iov[0].iov_base = hdr;
	state->udp.iov[0].iov_len = sizeof(data_ip_hdr_t);

	/* Prepare buffer pointer */
	state->udp.iov[1].iov_base = payload;
	state->udp.iov[1].iov_len = payload_size; /* udp_packet_size - sizeof(data_ip_hdr_t) */

	/* Receive into buffers */
	int rc = recvmsg(state->input_fd, &state->udp.msg, 0);
	if (rc <= 0)
	{
		/* Receive failed, check for EAGAIN, which is fine, we ran out of data */
		if ((rc < 0) && (EWOULDBLOCK != errno) && (EAGAIN != errno))
		{
			/* Oh dear, a "bad" error */
			fprintf(stderr, "Receive failed: %s (%d)\n", strerror(errno), errno);
			fprintf(stderr, "--> payload_size=%d\n", payload_size);
			fprintf(stderr, "--> block_index=%d block_count=%d\n",
					state->block_index, state->block_count);
			fprintf(stderr, "--> buffer_used=%d buffer_size=%d\n",
					state->iio_buffer_used, state->iio_buffer_size);
			return -1;
		}
		return 0;
	}

	/* Receive succeeded, what did we win? Check magic */
	if (((size_t)rc < sizeof(data_ip_hdr_t)) || (SDR_IP_GADGET_MAGIC != hdr->magic))
	{
		/* Wrong header size or bad magic, possibly a naughty network application or an honest mistake */
		fprintf(stderr, "Dropped wrong header udp datagram "
				" hdr_size=%" PRIu64
				" recv_size=%" PRIu64
				" magic=%" PRIu64
				" recv_magic=%" PRIu64 "\n",
				sizeof(data_ip_hdr_t), rc, SDR_IP_GADGET_MAGIC, hdr->magic);
		return 0;
	}

	return rc - sizeof(data_ip_hdr_t);
}

static int tcp_recv_data(int sock, uint8_t *buffer, size_t size)
{
	size_t offset = 0;
	while (offset < size) {
		int rc = recv(sock, &buffer[offset], size - offset, MSG_WAITALL);
		if (rc <= 0) {
			if ((EWOULDBLOCK == errno) || (EAGAIN == errno))
				continue;
			if (rc == 0) {
				fprintf(stderr, "tcp_recv_data :: Connection is closed by the peer\n");
				return -1;
			}
			perror("tcp_recv_data :: Failed to receive buffer on tcp data socket");
			return -1;
		}
		offset += rc;
	}
	return offset;
}

static int tcp_stream_resync(int sock, data_ip_hdr_t *hdr, uint8_t *buffer, size_t buffer_size, size_t search_limit)
{
	size_t processed_bytes = 0;
	int buf_offset = 0;

	while(processed_bytes < search_limit) {
		int recv_bytes = recv(sock, &buffer[buf_offset], buffer_size - buf_offset, 0);
		if (recv_bytes <= 0) {
			if ((EWOULDBLOCK == errno) || (EAGAIN == errno))
				continue;
			if (recv_bytes == 0) {
				fprintf(stderr, "tcp_stream_resync :: Connection is closed by the peer\n");
				return -1;
			}
			perror("tcp_stream_resync :: Failed to receive buffer on tcp data socket");
			return -1;
		}

		uint8_t *p = buffer;
		uint8_t *p_end = p + recv_bytes + buf_offset;
		for(; p < p_end; p++) {
			data_ip_hdr_t *h = (data_ip_hdr_t *)p;
			if (h->magic != SDR_IP_GADGET_MAGIC)
				continue;
			break;
		}
		if (p == p_end) {
			/* SDR_IP_GADGET_MAGIC not found */
			processed_bytes += recv_bytes;
			memcpy(buffer, p_end - sizeof(data_ip_hdr_t), sizeof(data_ip_hdr_t));
			buf_offset = sizeof(data_ip_hdr_t);
			continue;
		}

		processed_bytes += p - buffer;
		size_t left_bytes = p_end - p;
		DEBUG_PRINT("tcp_stream_resync :: Synchronized: skipped=%u left=%u\n",
					processed_bytes,
					left_bytes);

		if (left_bytes < sizeof(data_ip_hdr_t)) {
			if (tcp_recv_data(sock, p_end, sizeof(data_ip_hdr_t) - left_bytes) < 0)
				return -1;
			left_bytes = sizeof(data_ip_hdr_t);
		}

		// copy header from buffer into hdr struct
		memcpy((uint8_t *)hdr, p, sizeof(data_ip_hdr_t));
		left_bytes -= sizeof(data_ip_hdr_t);
		p += sizeof(data_ip_hdr_t);

		// move what is left into the begining of the buffer
		if (left_bytes > 0) {
			memcpy((uint8_t *)buffer, p, left_bytes);
		}
		return left_bytes;
	}

	fprintf(stderr, "tcp_stream_resync :: Failed to resynchronize :: search limit reached\n");
	return -1;
}

static int tcp_recv(state_t *state, data_ip_hdr_t *hdr, uint8_t *payload, size_t payload_size)
{
	int rc = tcp_recv_data(state->input_fd, (uint8_t *)hdr, sizeof(data_ip_hdr_t));
	if (rc < 0) {
		fprintf(stderr, "Failed to receive header on tcp data socket\n");
		return -1;
	}

	int payload_offset = 0;

	/* Receive succeeded, what did we win? Check magic */
	if ((SDR_IP_GADGET_MAGIC != hdr->magic)) {
		/* Wrong header size or bad magic, possibly a naughty network application or an honest mistake */
		fprintf(stderr, "Dropped wrong header tcp datagram. Try to resynchronize ::"
						" hdr_size=%d"
						" recv_size=%d"
						" magic=%u"
						" recv_magic=%u"
						" payload_size=%u"
						" iio_buffer_used=%u\n",
						sizeof(data_ip_hdr_t), rc,
						SDR_IP_GADGET_MAGIC, hdr->magic,
						payload_size,
						state->iio_buffer_used);

		/* Try to resynchronize */
		int search_buf_size = payload_size;
		if (search_buf_size > 4096)
			search_buf_size = 4096;

		int rc = tcp_stream_resync(state->input_fd, hdr, payload, search_buf_size, state->iio_buffer_size * 2);
		if (rc < 0) {
			fprintf(stderr, "Failed to resynchronize\n");
			return -1;
		}
		payload_offset += rc;
		if (payload_offset == payload_size)
			return sizeof(data_ip_hdr_t);
	}

	rc = tcp_recv_data(state->input_fd, &payload[payload_offset], (payload_size - payload_offset));
	if (rc < 0) {
		fprintf(stderr, "Failed to receive buffer on tcp data socket\n");
		return -1;
	}

	return payload_size;
}

static void epoll_enable_socket(state_t *state)
{
	struct epoll_event epoll_event;
	epoll_event.events = EPOLLIN;
	epoll_event.data.ptr = handle_socket;
	if (epoll_ctl(state->epoll_fd, EPOLL_CTL_MOD, state->input_fd, &epoll_event) < 0)
	{
		perror("epoll: failed to enable data socket");
	}
}

static void epoll_disable_socket(state_t *state)
{
	struct epoll_event epoll_event;
	epoll_event.events = 0;
	if (epoll_ctl(state->epoll_fd, EPOLL_CTL_MOD, state->input_fd, &epoll_event) < 0)
	{
		perror("epoll: failed to disable data socket");
	}
}

static void epoll_enable_iio(state_t *state)
{
	struct epoll_event epoll_event;
	epoll_event.events = EPOLLOUT | EPOLLONESHOT;
	epoll_event.data.ptr = handle_iio_push;
	if (epoll_ctl(state->epoll_fd, EPOLL_CTL_MOD, state->iio_buf_fd, &epoll_event) < 0)
	{
		perror("epoll: failed to enable (one-shot) iio socket");
	}
}


#if GENERATE_STATS
static int dump_stats(state_t *state)
{
	const uint64_t now_usec = UTILS_GetMonotonicMicros();
	if (state->stats_timer == 0)
		goto done;

	const uint64_t delta_usec = now_usec - state->stats_timer;
	if (delta_usec < (STATS_PERIOD_SECS * US_PER_SEC))
		return 0;

	const uint64_t uptime_usec = now_usec - start_time_usec;
	printf("STATS|Write: %" PRIu64 "+%" PRIu64 "\n",
		uptime_usec / US_PER_SEC,
		uptime_usec % US_PER_SEC);

	/* Report min/max/average write period */
	printf("\tperiod: min: %"PRIu64", max: %"PRIu64", avg: %"PRIu64" (uS)\n",
		   state->write_period.min,
		   state->write_period.max,
		   UTILS_CalcAverageTimeStats(&state->write_period)
	);

	/* Report min/max/average write duration */
	printf("\tdur: min: %"PRIu64", max: %"PRIu64", avg: %"PRIu64" (uS)\n",
		   state->write_dur.min,
		   state->write_dur.max,
		   UTILS_CalcAverageTimeStats(&state->write_dur)
	);

	/* Report received bytes and iio calls */
	printf("\tiio bytes %" PRIu64 " iio calls %" PRIu64 " sock bytes %" PRIu64 "\n",
		   state->iio_bytes,
		   state->iio_calls,
		   state->socket_recv
	);

	/* Check for overflows */
	if (state->overflows > 0)
	{
		printf("\toverflows: %u\n",
			state->overflows,
			STATS_PERIOD_SECS);
	}

	/* Time wraps : new seqno is smaller than previous */
	if (state->time_wraps > 0)
	{
		printf("\ttime wraps: %u\n",
			state->time_wraps,
			STATS_PERIOD_SECS);
	}

	/* Time gaps: new seqno is larger that timestamp_increment than the last one */
	if (state->time_gaps > 0)
	{
		printf("\ttime gaps: %u\n",
			state->time_gaps,
			STATS_PERIOD_SECS);
	}

	/* Check for dropped due to index */
	if (state->dropped_index > 0)
	{
		printf("\tdropped_index: %u\n",
			state->dropped_index,
			STATS_PERIOD_SECS);
	}

	/* Check for out of order */
	if (state->out_of_order > 0)
	{
		printf("\tout_of_order: %u\n",
			state->out_of_order,
			STATS_PERIOD_SECS);
	}

	/* Reset stats */
	UTILS_ResetTimeStats(&state->write_period);
	UTILS_ResetTimeStats(&state->write_dur);

done:
	state->stats_timer = now_usec;
	state->socket_recv = 0;
	state->iio_bytes = 0;
	state->iio_calls = 0;
	state->overflows = 0;
	state->time_wraps = 0;
	state->time_gaps = 0;
	state->dropped_index = 0;
	state->out_of_order = 0;

	return 0;
}
#endif