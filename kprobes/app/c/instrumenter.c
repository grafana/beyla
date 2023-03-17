#include "bpf/libbpf.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include "instrumenter.h"
#include "instrumenter.skel.h"
#include "g_hashmap.h"

// global data
static struct instrumenter_bpf *skel;
static struct ring_buffer *ring_buf = NULL;
static struct hashmap *map;
static struct hashmap *thread_fd_map;
// for debugging
static __u8 print = 0;

struct http_record
{
	unsigned long fd;
	char read_buf[MAX_MSG_SIZE];
	unsigned int read_len;
	__u64 read_ts;
	__u16 peer_port;
	char peer_ip[INET6_ADDRSTRLEN];
};

struct thread_fd_record
{
	unsigned long id;
	unsigned long fd;
};

static int thread_fd_record_compare(const void *a, const void *b, void *udata)
{
	const struct thread_fd_record *ra = a;
	const struct thread_fd_record *rb = b;
	return ra->id - rb->id;
}

uint64_t thread_fd_record_hash(const void *item, uint64_t seed0, uint64_t seed1)
{
	const struct thread_fd_record *r = item;
	return r->id;
}

static int http_record_compare(const void *a, const void *b, void *udata)
{
	const struct http_record *ra = a;
	const struct http_record *rb = b;
	return ra->fd - rb->fd;
}

uint64_t http_record_hash(const void *item, uint64_t seed0, uint64_t seed1)
{
	const struct http_record *r = item;
	return r->fd;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static char *strnchr(char *s, int c, size_t n)
{
	for (char *p = s; (p - s) < n; p++)
	{
		if (*p == c)
		{
			return p;
		}
		if (!*p)
		{
			break;
		}
	}
	return NULL;
}

/* Receive events from the ring buffer. */
static int event_handler(void *_ctx, void *data, size_t size)
{
	struct syscall_write_event_t *event = data;

	switch (event->attr.event_type)
	{
	case kEventTypeSyscallAddrEvent:
	{
		// delete in case the request failed to close
		g_hashmap_delete(map, &(struct http_record){.fd = event->attr.fd});
		struct http_record r = {.fd = event->attr.fd};

		// overriden for inet type
		if (event->attr.msg_size_or_type > 0)
		{
			r.peer_port = ntohs(event->attr.bytes);
			inet_ntop(event->attr.msg_size_or_type, event->msg, r.peer_ip, INET6_ADDRSTRLEN);
		}
		g_hashmap_set(map, &r);
		g_hashmap_set(thread_fd_map, &(struct thread_fd_record){.id = event->attr.ssl_corr_id, .fd = event->attr.fd});
		break;
	}
	case kEventTypeSyscallPeerNameEvent:
	{
		if (event->attr.msg_size_or_type > 0)
		{
			struct http_record *r = g_hashmap_get(map, &(struct http_record){.fd = event->attr.fd});
			if (!r)
			{
				r = &(struct http_record){.fd = event->attr.fd};
			}

			r->peer_port = ntohs(event->attr.bytes);
			inet_ntop(event->attr.msg_size_or_type, event->msg, r->peer_ip, INET6_ADDRSTRLEN);
			g_hashmap_set(map, r);
			g_hashmap_set(thread_fd_map, &(struct thread_fd_record){.id = event->attr.ssl_corr_id, .fd = event->attr.fd});
		}
		break;
	}
	case kEventTypeSyscallCloseEvent:
		g_hashmap_delete(map, &(struct http_record){.fd = event->attr.fd});
		g_hashmap_delete(thread_fd_map, &(struct thread_fd_record){.id = event->attr.ssl_corr_id});
		break;
	case kEventTypeSyscallWriteEvent:
	{
		struct http_record *r = g_hashmap_get(map, &(struct http_record){.fd = event->attr.fd});
		if (r)
		{
			char *space = strnchr(event->msg, ' ', MAX_MSG_SIZE);
			if (space)
			{
				space++;
				char *next_space = strnchr(space, ' ', MAX_MSG_SIZE - (space - event->msg));
				if (next_space)
				{
					char return_code[32];
					strncpy(return_code, space, next_space - space);
					return_code[next_space - space] = '\0';

					char *peer_ip = r->peer_ip;
					__u16 peer_port = r->peer_port;

					// this might be ssl, let's see if we have a correlated record from the original fd
					if (peer_port == 0)
					{
						struct thread_fd_record *tr = g_hashmap_get(thread_fd_map, &(struct thread_fd_record){.id = event->attr.ssl_corr_id});
						if (tr)
						{
							struct http_record * or = g_hashmap_get(map, &(struct http_record){.fd = tr->fd});
							if (or)
							{
								peer_ip = or->peer_ip;
								peer_port = or->peer_port;
								// this is ssl write end when we couldn't map ssl to fd, close will be on the original fd
								g_hashmap_delete(map, &(struct http_record){.fd = event->attr.ssl_corr_id});
							}
						}
					}

					if (print)
					{
						fprintf(stderr, "result=%s, elapsed=%lldns, [%s]:[%d]\n", return_code, event->attr.ts - r->read_ts, peer_ip, peer_port);
					}
				}
			}
		}

		break;
	}
	case kEventTypeSyscallReadAndInitEvent:
	{
		struct http_record *r = g_hashmap_get(map, &(struct http_record){.fd = event->attr.fd});
		if (!r)
		{
			g_hashmap_set(map, &(struct http_record){.fd = event->attr.fd});
		}
		// fall through
	}
	case kEventTypeSyscallReadEvent:
	{
		struct http_record *r = g_hashmap_get(map, &(struct http_record){.fd = event->attr.fd});
		if (r)
		{
			memcpy(r->read_buf, event->msg, MAX_MSG_SIZE * sizeof(char));
			r->read_len = event->attr.bytes;
			r->read_ts = event->attr.ts;
			r->read_buf[r->read_len] = '\0';
			char method[32], url[256];

			char *space = strnchr(r->read_buf, ' ', r->read_len);
			if (space)
			{
				int method_size = space - r->read_buf;
				strncpy(method, r->read_buf, method_size);
				method[method_size] = '\0';
				space++;

				char *next_space = strnchr(space, ' ', r->read_len - method_size);
				if (next_space)
				{
					int url_size = next_space - space;
					strncpy(url, space, next_space - space);
					url[url_size] = '\0';
				}

				if (print)
				{
					fprintf(stderr, "#### - ####: method: %s, url=%s, ", method, url);
				}
			}
		}
		break;
	}
	}

	return 0;
}

void cleanup()
{
	g_hashmap_free(map);
	ring_buffer__free(ring_buf);
	instrumenter_bpf__destroy(skel);
}

void cleanup_and_exit(int sig)
{
	cleanup();
	exit(sig);
}

int main(int argc, char **argv)
{
	int err, active_pid;

	if (argc < 2)
	{
		fprintf(stderr, "Please specify the PID to track as first argument\n");
		return 1;
	}

	if (argc > 2 && !strncmp(argv[2], "print", 5))
	{
		print = 1;
	}

	signal(SIGINT, cleanup_and_exit);
	signal(SIGTERM, cleanup_and_exit);

	map = g_hashmap_new(sizeof(struct http_record), 0, 0, 0,
						http_record_hash, http_record_compare, NULL, NULL);

	thread_fd_map = g_hashmap_new(sizeof(struct thread_fd_record), 0, 0, 0,
								  thread_fd_record_hash, thread_fd_record_compare, NULL, NULL);

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	skel = instrumenter_bpf__open();

	if (!skel)
	{
		fprintf(stderr, "Failed to open BPF skeleton\n");
		cleanup();
		return 1;
	}

	active_pid = atoi(argv[1]);

	if (active_pid <= 0)
	{
		fprintf(stderr, "The specified PID must be > 0, you supplied %d\n", active_pid);
		cleanup();
		return 1;
	}

	fprintf(stderr, "Active pid %d\n", active_pid);
	skel->rodata->active_pid = active_pid;

	/* Open load and verify BPF application */
	err = instrumenter_bpf__load(skel);
	if (err)
	{
		fprintf(stderr, "Failed to load BPF skeleton\n");
		cleanup();
		return -err;
	}

	/* Prepare ring buffer to receive events from the BPF program. */
	ring_buf = ring_buffer__new(bpf_map__fd(skel->maps.events), event_handler, NULL, NULL);
	if (!ring_buf)
	{
		fprintf(stderr, "Failed to allocate new ring buffer\n");
		cleanup();
		return 1;
	}

	/* Attach tracepoint handler */
	err = instrumenter_bpf__attach(skel);
	if (err)
	{
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		cleanup();
		return 1;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
		   "to see output of the BPF programs.\n");

	// Wait and receive events
	while (ring_buffer__poll(ring_buf, -1) >= 0)
	{
	}

	cleanup();
	return 0;
}