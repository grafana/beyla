---
title: "http tracer in Beyla"
description: "How Beyla traces your HTTP requests"
---

There are two major sections when it comes to working with HTTP tracers in Beyla.
i.e. What happens when an HTTP packet leaves (egress) a service and what happens
when it receives (ingress) a packet.

When a service A sends an HTTP (HTTP relies on TCP for Networking Layer) packet to
another service B, there are some modifications made to the packet at the **traffic
control** layer, which is present between layer 3 and layer 2 in the network stack.

## Goal

Add additional information in each HTTP packet being sent from the service, to
maintain context information of an HTTP request. While doing this, we have to
make sure the connection doesn't fail and all the used/required network
protocols function as it is.

This involves making sure:

- Additional information being added to the packet doesn't bloat it in extensively
  dense systems (many services).
- TCP still works, i.e. checksum and sequencing both should work as usual.
- Working as close to the network layer as possible, that allows us to directly
  work with `sk_buff` which is the in-memory representation of a network packet
  in the Linux kernel.

## Computer Networking Primer

We know that TCP is connection oriented and reliable, that means both side of
the connections keep track of data being sent back and forth. This is done using
`sequence` numbers and a cycle of `send` and `acknowledge` steps.

Therefore we have an internal map on every service that holds state for each
packet being sent and how it was modified so that the acknowledgement can be
adjusted on being received.

### Sequence numbers and Acknowledgement

TCP uses sequence numbers to track the order of bytes sent and acknowledgement
numbers confirm what has been received. Here is how it all works.

Let's say there are two services, A and B communicating with each other over TCP.
During the handshake they both decide their own Initial Sequence Numbers (ISN) that
is going to keep track of how much data has been sent from one service to the other.

- Initial Setup:

  - A sends to B with an initial sequence number of 1000.
  - B sends to A with its own ISN of 5000 (each direction has its own sequence space).

- A Sends Data:

  - Packet 1: `seq=1000`, 100 bytes of data. Expected acknowledgement number
    `1000 + 100 = 1100`.
  - Packet 2: `seq=1100`, 50 bytes of data. Expected acknowledgement number
    `1100 + 50 = 1150`.

- B Acknowledges:
  - B receives packet 1, sends `ack_seq = 1100` saying "I've got everything up to
    1100".
  - Similarly, B receives packet 2, sends `ack_seq = 1150`.

It was important to understand how this works because if the sending and acknowledging
sequence numbers do not match, the system goes out of sync and might even result
in terminated connection.

### Anatomy of a TCP header

A TCP header typically contains 4 major sections, Ethernet Header, IP header
, TCP Header and finally, the HTTP Request Payload. There are more things,
but for the sake of simplicity, we only care about these.

```md
+-----------------+-------------+------------+----------------------+
| Ethernet Header | IP Header | TCP Header | HTTP Request Payload |
| (14 bytes) | (20 bytes) | (20 bytes) | (100 bytes) |
+-----------------+-------------+------------+----------------------+
```

An example Request Payload might look like this:

```text
GET / HTTP/1.1\r\n
Host: example.com\r\n
\r\n
```

**Layer Details**:

- **Ethernet Header**: Source/Destination MAC addresses.
- **IP Header**: Source/Destination IP addresses.
- **TCP Header**: Source/Destination sequence numbers, acknowledgement numbers,
  checksum.

Now, we need to attach additional information in this request payload so that it
contains trace related information (context) while moving through multiple services.
For which we will use a web standard named **trace context** as defined in the
[official W3C docs](https://www.w3.org/TR/trace-context/).

This is the header spec:

- **Version** : Represents the W3C version of the trace context spec.
- **Trace Id**: A 16 byte array of characters (32 characters in hexadecimal,
  e.g., `1234567890abcdef1234567890abcdef`). This is the unique id of the
  entire trace. It does not change.
- **Parent Id**: An 8 byte array of characters representing the unique id of the
  sender service's id. This keeps changing on every hop.
- **Trace Flags**: An 8 bit flag, that contain flags such as sampling, trace
  level, etc.

Example:

```c
"Traceparent: 00-<trace-id>-<span-id>-<flags>\r\n"
```

- `Traceparent`: (12 bytes)
- `00`: (version, 3 bytes)
- `<trace-id>`: (32 hex chars = 16 bytes)
- `-`: (1 byte)
- `<span-id>` (16 hex chars = 8 bytes)
- `-`:(1 byte)
- `<flags>`: (2 hex chars = 1 byte)
- `\r\n`: (2 bytes)

**Trace Id** remains unique throughout the request, and the **Parent Id** keeps
changing service to service. For a packet going from service A to B, the
parent Id section will contain 8 byte character from the parent service (A).
Which will be replaced with B's id when going from B to C and so on.

This makes sure the packet doesn't bloat and is fixed to 64 bytes all the time.

Now the entire process of modification can be divided into following steps:

## Solution

### Egress

1. **Identify the packet**

Since we are working with Traffic Control, we get access to
`struct __sk_buff *ctx` which is a kernel socket buffer representing the packet.
We skip the Ethernet and IP Headers to get to the TCP header (if exists).

If it is does not have a TCP header, we let the packet pass unchanged.

2. **Connection Context**

Now, We are going to modify the packet payload, to keep track of the request
using the traceparent header which will change the size of the entire packet,
but as mentioned earlier, we have to maintain the sequence number.

For that, we are going to keep a data structure (an eBPF hash map
`tc_http_ctx_map`) to keep track of the size of additional data we added
to the packet payload. Here, the hashmap key has to be something unique
for each TCP connection, so we can use the source port for it.

The value of the hashmap will be a `struct tc_http_ctx` holding `xtra_bytes`
along with the state of the connections. Below is how these data structures look
in the Beyla codebase.

```c
struct tc_http_ctx {
    u32 xtra_bytes;
    u8 state;
} __attribute__((packed));

struct tc_http_ctx_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct tc_http_ctx);
    __uint(max_entries, 10240);
} tc_http_ctx_map SEC(".maps");

```

> [!NOTE]
> You can read more about the TCP state status [here](<https://www.googlecloudcommunity.com/gc/Cloud-Product-Articles/TCP-states-explained/ta-p/78462>.

The `get_extra_xmited_bytes` function is handling this process, checking the
state of connection. It initialises an entry if its a new connection (SYN flag)
and delete the entry if its an RST flag (reset).

```c
static __always_inline void
get_extra_xmited_bytes(u32 key, u32 *extra_bytes, struct tc_http_ctx **http_ctx) {
    struct tc_http_ctx *ctx = bpf_map_lookup_elem(&tc_http_ctx_map, &key);

    if (ctx) {
        *extra_bytes = ctx->xtra_bytes;
        *http_ctx = ctx;
    } else {
        *extra_bytes = 0;
        *http_ctx = NULL;
    }
}
```

3. **Adjusting sequence number**:

- Now we get to the actual part of adding extra bytes in the packets. We can
  get the `extra_bytes` from the map (cumulative extra bytes added so far) and call
  the `update_tcp_seq`, which performs a simple operation like `tcp->seq += extra_bytes`.

```c
static __always_inline void update_tcp_seq(struct __sk_buff *ctx, u32 extra_bytes) {
    if (extra_bytes == 0) {
        return;
    }

    struct tcphdr *tcp = tcp_header(ctx);

    if (!tcp) {
        return;
    }

    u32 seq = bpf_ntohl(tcp->seq);
    seq += extra_bytes;

    tcp->seq = bpf_htonl(seq);
}
```

4. **Adding the traceparent header**

- Find the Insertion point: Above there is an example HTTP Payload, we can enter
  our header just below the first line. This can be done by finding the first line
  break through `\n`. Inserting our traceparent header just after this makes it the
  first one (HTTP headers are order-agnostic).

- Make space: As mentioned above, traceparent header size is fixed i.e 64 bytes,
  this makes our work easier, as we have to shift the entire payload data by 64 bytes
  and put our header over there. Function `bpf_skb_change_tail` does this through
  a simple `ctx->len + EXTEND_SIZE`, where EXTEND_SIZE is the header size.

  ```c
  const char TP[] = "Traceparent: 00-00000000000000000000000000000000-0000000000000000-01\r\n";
  const u32 EXTEND_SIZE = sizeof(TP) - 1;

  ```

- Insert Header: `make_tp_string_skb` writes the `traceparent` string into the
  gap we created, using the trace and spen IDs from `tp_info_t`. We are doing
  some tail call magic here (which I need to learn).

  ```c
  typedef struct tc_l7_args {
    tp_info_t tp;
    u32 extra_bytes;
    u32 key;
  } tc_l7_args_t;

  struct {
  **uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  **type(key, int);
  **type(value, tc_l7_args_t);
  **uint(max_entries, 1);
  } tc_l7_args_mem SEC(".maps");
  ```

- Update Packet Metadata:

  - IP header: Increase the total length of the packet by `EXTEND_SIZE` and we also
    fix the checksum through `bpf_13_csum_replace`.

  - TCP Header: Recalculate the checksum over the pseudo-header (IP addresses,
    protocol, TCP length) and new payload with `update_tcp_csum`.

### Ingress

TBD.
