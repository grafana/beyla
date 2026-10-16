# Chapter 14. Identity in the Traceparent

*An extract in the style of an O’Reilly book for kernel engineers.*
*POC: `poc/traceparent-encode` on linux/arm64. Measured figures from that run.*

---

Grafana Beyla is a distribution of OpenTelemetry eBPF Instrumentation (OBI). On Kubernetes it solves a problem that looks like magic and is, in fact, an API server: a DaemonSet watches pods, a metadata cache maps `IP → (service.name, service.namespace)`, and `survey_info` publishes what was found. Off-cluster — a rack of EC2 instances, ansible-built VMs, no `kube-apiserver` — the cache has nothing to watch. The W3C `traceparent` still crosses the wire. This chapter is about loading *identity* into that header without adding a header, a TCP option, or a single extra byte on the wire.

The proof of concept does not change Beyla’s injector. It specifies a codec that produces a *legal* 55-character version-00 `traceparent`, and it states what `survey_info` must carry so a receiver can name the bytes.

## 14.1 Two planes

Call the packet path the *data plane* and the discovery path the *control plane*.

```
  control plane (slow, local, lossy-OK)          data plane (per request, lossy-not-OK)
 ┌─────────────────────────────────────┐        ┌──────────────────────────────────────┐
 │  process walk / ansible inventory   │        │  HTTP/1  Traceparent: 55 chars       │
 │  comm, OTEL_SERVICE_NAME, cgroup    │        │  HTTP/2  HPACK val_len == 55         │
 │           │                         │        │  TCP     option kind 25, 26 bytes    │
 │           ▼                         │        │           │                          │
 │  survey_info{service_name,          │  join  │           ▼                          │
 │              service_namespace,     │◄───────│  SHA-256 prefix in trace-id/span-id  │
 │              service_origin_key,    │        │  (this POC)                          │
 │              service_caller_key}    │        └──────────────────────────────────────┘
 └─────────────────────────────────────┘
```

**Figure 14-1.** *The hash is not a name. `survey_info` is the name. The header only carries a key.*

On Kubernetes the join key is a pod IP. On EC2 the join key is a 56-bit origin prefix and a 32-bit caller prefix of

```
SHA-256("beyla.tpenc.v1" || 0x00 || lowercase(namespace) || 0x00 || lowercase(name))
```

`survey_info` already exists. It is a Beyla-only up/down counter (Prometheus gauge) with the same attribute set as `target_info`. Survey mode discovers processes and does not instrument them. The POC assumes discovery is “nailed down”: every Beyla on the fleet already knows its local `(service_name, service_namespace)` and publishes them. What it did not have, off-cluster, is a way to *propagate* those two strings to the other end of a TCP connection.

## 14.2 What the POC can and cannot do

It can:

- Produce a version-00 `traceparent` that `go.opentelemetry.io/otel/propagation.TraceContext` Extract accepts.
- Carry *origin* identity in the left 8 bytes of `trace-id` (56-bit digest prefix) and *caller* identity in `span-id` (32-bit prefix of the same digest).
- Survive HTTP/1, HTTP/2 (literal 55-byte value), and Beyla’s existing TCP option kind 25, because it never grows the 24 ID bytes.
- Leave W3C uniqueness and head-based sampling intact (right 8 bytes of `trace-id` stay random).
- Round-trip any name length, any alphabet: the strings never enter the header.
- Adopt an incoming header if one is already present; never inject a second.

It cannot:

- Name a peer that is not in the catalog (hash without `survey_info` is an anonymous node).
- Survive an SDK that rewrites `span-id` and still name that hop’s caller.
- Fit more TCP options than Beyla already fails to fit (26-byte option vs. 40-byte options region).
- Compute SHA-256 in PromQL; the keys must be *labels* on `survey_info` or the join happens out of band.

## 14.3 The 24-byte invariant

A version-00 value is exactly 55 ASCII characters:

```
  0         1         2         3         4         5
  0123456789012345678901234567890123456789012345678901234
  00-0123456789abcdef0123456789abcdef-0123456789abcdef-01
     |--------- 16 bytes ---------|  |--- 8 bytes ---|
     trace-id                         parent-id / span-id
```

**Figure 14-2.** *W3C v00 layout. Beyla hard-codes this length: `TP_MAX_VAL_LENGTH = 55`, `k_hpack_value_len_tp = 55`, `TRACE_PARENT_HEADER_LEN = 68` (name + value, no CRLF).*

Those 24 binary bytes are the *only* payload common to every channel tpinjector already uses. HTTP/2 adopts a field only when `val_len == 55`. gRPC Go metadata is checked for `val_len == W3C_VAL_LENGTH`. The TCP option is:

```
struct tp_option {          /* 26 bytes, IANA kind 25 (unassigned) */
    u8  kind;               /* 25 */
    u8  len;                /* 26 */
    u8  trace_id[16];
    u8  span_id[8];
};
```

The TCP options region is 40 bytes. A typical SYN already carries MSS + window scale + SACK-permitted + timestamps ≈ 20 bytes. `26 + 20 > 40`. Growing the option is not a research question; it is already a production loss. The codec must live *inside* the 24 bytes Beyla already stores in `tp_info_t`.

W3C itself splits the 16-byte `trace-id`:

```
 trace-id
┌──────────────────┬──────────────────┐
│ left 8 bytes     │ right 8 bytes    │
│ vendor structure │ uniqueness +     │
│ (X-Ray time,     │ sampling         │
│  this POC hash)  │ (64-bit systems  │
│                  │  use only these) │
└──────────────────┴──────────────────┘
 span-id / parent-id   rewritten every hop
┌─────────────────────────────────────┐
│ this POC: caller key, 32 bits       │
│ mixed with 32 bits of random        │
└─────────────────────────────────────┘
```

**Figure 14-3.** *Where structure is legal. Randomness is SHOULD, not MUST. All-zero is the only forbidden ID. The processing model requires a participant to update `parent-id` and forbids any other mutation of `traceparent` except a deliberate restart.*

An extra ASCII suffix (`…-01-more-info`) is not a common channel. OTel Extract *rejects* a v00 header with leftover fields (the trace restarts). Extract *accepts* a v01 suffix and then Inject downgrades to a clean v00 and strips the extra. HPACK and the TCP option cannot carry it at all.

## 14.4 Hijacking the header without corrupting it

“Hijack” here means: the bytes that W3C, OTel, Envoy, and Beyla already treat as an opaque identifier are *also* a keyed encoding. A compliant parser that does not know the scheme still sees a valid id. A Beyla that does know the scheme recovers two catalog keys.

### Layout

```
digest = SHA-256("beyla.tpenc.v1" || 0x00 || ns || 0x00 || name)

plain_left[8]
┌────────┬──────────────────────────────────────┐
│ 0xB1   │ digest[0..6]          56-bit origin  │
└────────┴──────────────────────────────────────┘

wire_trace_id[16]
┌────────────────────────────┬──────────────────┐
│ plain_left XOR kdf8(R)     │ R = 8 random B   │
└────────────────────────────┴──────────────────┘

wire_span_id[8]
┌──────────────────┬──────────────────┐
│ digest[0..3] XOR S│ S = 4 random B  │
└──────────────────┴──────────────────┘
```

**Figure 14-4.** *The only identity scheme. `0xB1` is the loaded-v1 magic. `kdf8` is two FNV-1a 32-bit folds of `R` and `R⊕0x5a`, not a cryptographic KDF. Inverse is the same XOR. Anyone who knows the scheme can unmix; that is intentional.*

On the wire a `prod/api` origin with a fixed nonce is:

```
00-429c4fa371e4e8240123456789abcdef-7df3987bdeadbeef-01
   ^^^^^^^^^^^^^^^^                ^^^^^^^^^^^^^^^^
   mixed 0xB1||digest[0:7]         R (uniqueness)
                                   ^^^^^^^^ ^^^^^^^^
                                   key XOR S    S
```

Go and gcc on `aarch64` emit that exact vector. `TraceContext.Extract` returns valid. Beyla’s HTTP/1 matcher only checks the name prefix `traceparent: ` and then reads 32+16 hex at fixed dashes; it does not care that the hex is structured. `make_tp_string` will later rewrite version `00` and flags `01` from `tp_info_t` — the IDs it writes are the IDs it stored, which are these.

### Why this is not corruption

A parser corrupts a header when it writes bytes that another parser will reject, or when it changes the *meaning* of `trace-id` for everyone else.

| Check | Result |
|---|---|
| Length 55, lowercase hex, dashes at 2/35/52 | Pass |
| Version `00`, flags `01` (sampled, not “random”) | Pass; flags `> 3` would fail OTel v00 |
| `trace-id` / `span-id` not all-zero | Pass (retry the nonce if they are) |
| OTel Extract | Accepts |
| OTel Inject | Emits the same `trace-id`, new `span-id`, version forced to `00` |
| Beyla HPACK `val_len == 55` | Matches |
| 64-bit systems using the right 8 bytes | See only `R`; sampling unbiased |
| Second `traceparent` on the same request | Never written |

The mix exists so that two requests from `prod/api` do not share a visible `trace-id` prefix. The right 8 bytes are the W3C uniqueness field. Put the hash on the *right* and a 10% head-sampler (last 32 bits) keeps 0% or 100% of that service; measured 0.0% versus 10.1% with the hash on the left.

Kernel-shaped implementation: userspace computes the digest once per `(pid, service)` when discovery assigns the name — the same moment `survey_info` is created. BPF copies 7 bytes into a new `trace-id` and 4 bytes into a new `span-id`. No SHA-256 in the verifier’s face. `new_trace_id()` already fills 16 `urand` bytes; the change is “overwrite the left 8 after mix,” not a new map.

```
  userspace (discovery)                    BPF (sk_msg / sock_ops / uprobe)
 ┌─────────────────────────┐              ┌──────────────────────────────┐
 │  SHA-256 → origin[7],   │  pid map     │  if creating trace-id:       │
 │  caller[4]              │─────────────►│    left = (0xB1||o[7])⊕kdf(R)│
 │  survey_info series = 1 │              │    right = R                 │
 └─────────────────────────┘              │  if creating span-id:        │
                                          │    sid = c[4]⊕S || S         │
                                          │  if adopting existing TP:    │
                                          │    parse; do not recreate    │
                                          └──────────────────────────────┘
```

**Figure 14-5.** *Hash once, memcpy many. The codec is a userspace contract plus a few stores next to `urand_bytes`.*

## 14.5 `survey_info` labelling requirements

`survey_info` is created from process events (`ProcessEventCreated` / `Terminated`). The Prometheus exporter is a `GaugeVec` named `survey_info`, help text *“attributes associated to a given surveyed entity”*. Label names are the same set as `target_info` (see `labelNamesTargetInfo` in `pkg/export/prom/prom.go`):

```
host_id, host_name, service_name, service_namespace,
instance, job, telemetry_sdk_language, telemetry_sdk_name,
source, os_type
```

plus Kubernetes or Docker names when those informers are on, plus `extra_resource_labels`.

`job` is `namespace/name`, or just `name` if namespace is empty. `source` and `telemetry_sdk_name` are `"beyla"`. `os_type` is `"linux"`. The gauge is `1` while the UID is alive and is deleted on last-PID termination.

### What must be true for the join

PromQL cannot evaluate SHA-256. Therefore a Prometheus-native join **requires the digest prefixes as labels**. Computing them only in the collector is allowed; leaving them implicit is not, if the consumer is PromQL.

**R1.** Every series that a peer might need to resolve MUST have non-empty `service_name`. `service_namespace` may be empty (Beyla already allows that); the digest uses an empty string, not the word `"default"`.

**R2.** The strings hashed at encode time MUST be exactly `ToLower(TrimSpace(service_name))` and the same for namespace. If survey later “improves” a name (PID grew metadata, `OTEL_SERVICE_NAME` appeared), the series is deleted and recreated — today’s code already does that. The new keys must follow the new name or in-flight headers become anonymous.

**R3.** Emit two additional labels on every `survey_info` series (POC contract; not in tree today):

| Label | Value | Width |
|---|---|---|
| `service_origin_key` | `hex(digest[0:7])` | 14 hex chars |
| `service_caller_key` | `hex(digest[0:4])` | 8 hex chars |

`service_caller_key` is a prefix of `service_origin_key`. That is deliberate: a 32-bit hit can be confirmed against a 56-bit origin when both are on the same request.

**R4.** Do **not** put `host_id` or `instance` into the digest. The header names a *service*, not a replica. Instance fan-out is a join onto `survey_info` via the key, then a group-by on `host_id` if you need it. Putting instance into the hash would make every replica a different graph node and would explode caller collisions.

**R5.** One series per `svc.UID` (`name, namespace, instance`). Cardinality is the number of surveyed processes, not the number of requests. That is the point of survey mode.

**R6.** The same domain string (`beyla.tpenc.v1`) and magic (`0xB1`) on every host. A fleet with two digest versions cannot join.

**R7.** Off-cluster, do not rely on `k8s_*` labels. They will be absent. `host_id` / `host_name` are the placement labels (EC2 instance id, private DNS).

### Example series — EC2, no Kubernetes

Two instances, three processes. Hashes are illustrative except `prod/api`, which is the locked ARM vector.

```
# HELP survey_info attributes associated to a given surveyed entity
# TYPE survey_info gauge

survey_info{
  host_id="i-0a1b2c3d4e5f",
  host_name="ip-10-1-2-14.ec2.internal",
  service_name="api",
  service_namespace="prod",
  instance="i-0a1b2c3d4e5f:prod/api",
  job="prod/api",
  telemetry_sdk_language="go",
  telemetry_sdk_name="beyla",
  source="beyla",
  os_type="linux",
  service_origin_key="a35e269406e3ab",
  service_caller_key="a35e2694"
} 1

survey_info{
  host_id="i-0a1b2c3d4e5f",
  host_name="ip-10-1-2-14.ec2.internal",
  service_name="nginx",
  service_namespace="",
  instance="i-0a1b2c3d4e5f:nginx",
  job="nginx",
  telemetry_sdk_language="generic",
  telemetry_sdk_name="beyla",
  source="beyla",
  os_type="linux",
  service_origin_key="32c1557a244347",
  service_caller_key="32c1557a"
} 1

survey_info{
  host_id="i-09f8e7d6c5b4",
  host_name="ip-10-1-2-77.ec2.internal",
  service_name="worker",
  service_namespace="prod",
  instance="i-09f8e7d6c5b4:prod/worker",
  job="prod/worker",
  telemetry_sdk_language="python",
  telemetry_sdk_name="beyla",
  source="beyla",
  os_type="linux",
  service_origin_key="b7e10000000000",
  service_caller_key="b7e10000"
} 1
```

**Figure 14-6.** *Control-plane scrape. A receiver that decoded `caller=a35e2694` from a `span-id` joins:*

```
survey_info{service_caller_key="a35e2694"}
```

*and reads `service_name="api"`, `service_namespace="prod"`. Two replicas of `api` share the same keys and differ on `host_id` / `instance`.*

A recording rule that builds the service graph from spans (pseudo-PromQL, assuming the span metrics pipeline already copied the decoded keys onto the client span) looks like:

```
# peer is the caller key on the incoming parent-id
sum by (server_service, server_ns, client_service, client_ns) (
  http_server_request_duration_seconds_count
  * on (service_origin_key) group_left (server_service, server_ns)
    label_replace(survey_info, "server_service", "$1", "service_name", "(.*)")
)
```

The exact metric name depends on the span-metrics view. The *join key* does not: it is `service_origin_key` / `service_caller_key`.

If you refuse to add those labels, the join must happen in the collector (or in Beyla userspace at decode time, writing `service.name` onto the span the way the k8s cache already does). That is the better product shape: decode in Beyla, emit ordinary OTel resource attributes, leave `survey_info` as the fleet directory rather than a PromQL hash table.

## 14.6 Collision rate

Let *n* be the number of distinct `(namespace, name)` pairs in the catalog, not the number of PIDs or hosts. Approximate

```
P(at least one colliding pair) ≈ 1 − exp( − n(n−1) / 2^{b+1} )
```

| *n* | 24-bit (rejected layout) | 32-bit caller | 56-bit origin |
|---:|---:|---:|---:|
| 1 000 | 2.9% | 0.012% | ~0 |
| 10 000 | 95% | 1.2% | ~0 |
| 100 000 | 100% | 69% | 7×10⁻⁸ |
| 1 000 000 | 100% | 100% | 7×10⁻⁶ |

**Figure 14-7.** *Birthday bound. The discarded 24-bit caller+crc8 tag was already a coin flip at 10k services. Origin at 56 bits is not a fleet-scale problem. Caller at 32 bits is the remaining budget after leaving 32 bits of span-id random.*

Handling is not “pick one.”

- Origin lookup is 56-bit exact. Miss → anonymous `hash:a35e269406e3ab` until survey binds.
- Caller lookup is 32-bit and must be *unique* in the catalog. Zero hits: no caller (SDK rewrite, or a peer you have not surveyed). Two hits: refuse; drop the edge. Do not guess.
- A random SDK `span-id` names a catalogued service with probability *n / 2³²* per request. Measured: 0/50 000 with a one-entry catalog.
- A random `trace-id` unmixes to magic `0xB1` about 1/256 of the time (measured 802/200 000). Without a catalog hit it is an anonymous hash, not a wrong name.

SHA-256 vs FNV at the same width: same birthday arithmetic, better distribution, domain-separated so a future `beyla.tpenc.v2` cannot collide with v1 on the wire (magic would also change).

Trace-id uniqueness is independent: 2⁶⁴ on the right. Birthday ~ 4×10⁹ traces. If a nonce ever yields an all-zero id, encode retries.

## 14.7 Existing `traceparent` headers

Beyla’s rule, already tested in `TestHTTP1ClientTraceparentNotDuplicated` and encoded in `h2_inject_verdict`: **one field, never two**. A second `traceparent` is not “more context”; it is an invalid request.

```
                    incoming request
                           │
                           ▼
                 ┌─────────────────────┐
                 │ traceparent present?│
                 └─────────┬───────────┘
                     no    │    yes
                      │    │     │
                      ▼    │     ▼
              new_trace_id │  parse 55-char v00
              (POC: hash   │  adopt trace-id
               this        │  incoming span-id → parent
               service)    │  new local span-id
                      │    │     │
                      │    │     ├─ magic 0xB1 after unmix?
                      │    │     │    yes: catalog lookup (origin, caller)
                      │    │     │    no:  ordinary W3C, no names from header
                      │    │     │
                      ▼    ▼     ▼
                   same rule on the way out:
                   if the app already wrote one, skip inject
                   (HTTP/1 is_traceparent; H2 k_h2_skip_app_propagates)
```

**Figure 14-8.** *Adopt, then optionally decode. Never overwrite an upstream `trace-id`. That would restart the trace.*

Special case, already in `apply_parent_tp`: a proxy that is forwarding a header *this* Beyla wrote. Same `trace-id`, span-id still equal to the parent — rewrite the on-wire span-id so the child is distinct. The POC would restamp that new span-id with the *local* caller key.

HTTP/2 Huffman or indexed-name fields are *present but not adoptable*. The injector skips. You cannot read the ids from that encoding on egress, and you must not add a second field. Ingress kprobes can still decode some of those shapes; that path is unchanged.

An incoming *random* SDK header is case “magic fail.” Keep the ids. If this service later creates a child, keep the upstream `trace-id` and write a new span-id (optionally loaded). The next Beyla can name *this* hop and cannot name the origin. Mixed traces are correct.

A v00 header with an extra suffix is rejected by OTel Extract; the SDK restarts. The POC never emits that shape.

## 14.8 A request across an EC2 fleet

Three instances, ansible-installed Beyla, no Kubernetes, context propagation `headers,tcp`. Discovery has already published the series in Figure 14-6.

```
   i-0a1b  (10.1.2.14)              i-09f8  (10.1.2.77)              i-0cc0  (10.1.2.90)
   Beyla + nginx + api              Beyla + worker                   Beyla + postgres
        │                                │                                │
        │  GET /orders                   │                                │
        │  Traceparent: 00-429c…-7df3…-01│                                │
        │  origin=a35e269406e3ab (api)   │                                │
        │  caller=a35e2694       (api)   │                                │
        ├───────────────────────────────►│                                │
        │                                │  decode: catalog hit           │
        │                                │  server span parent = 7df3…    │
        │                                │  new span-id = worker key⊕S    │
        │                                │                                │
        │                                │  POST /commit                  │
        │                                │  00-429c…-b7e1…-01             │
        │                                │  same trace-id (origin lives)  │
        │                                ├───────────────────────────────►│
        │                                │                                │ decode: origin=api
        │                                │                                │ caller=worker
```

**Figure 14-9.** *EC2 east-west. The `trace-id` never changes. Each Beyla restamps `span-id`. `survey_info` on the receiver is a local table; it does not RPC to the sender.*

Timeline for the engineer who will attach `bpftrace`:

1. **Host A, userspace.** Survey sees `api` in `prod`, writes `survey_info=1` with `service_origin_key=a35e269406e3ab`, stores the 7+4 bytes in the pid map.
2. **Host A, `sk_msg`.** No existing header. `create_tp` / `new_trace_id`: 8 bytes of `get_prandom_u32` on the right, left = `(0xB1||key56) ⊕ kdf(R)`, span-id = `key32 ⊕ S || S`. `make_tp_string` writes 55 chars. Optionally `bpf_reserve_hdr_opt` + `bpf_store_hdr_opt` for kind 25 (same 24 bytes).
3. **Host B, ingress.** HTTP parse or `bpf_load_hdr_opt`. IDs land in `tp_info_t`. Userspace unmixes, magic matches, catalog hit on both keys. Server span: `trace-id` unchanged, `parent-id` = A’s span-id, new local span-id. Resource attributes on the span can now include `service.name=worker` (local) and a peer attribute from the catalog (`prod/api`).
4. **Host B, egress to C.** App did not write a header. Injector writes the *same* `trace-id` and a new span-id carrying worker’s key.
5. **Host C.** Same adopt. Graph edge `api → worker → postgres`, labelled from three local scrapes of `survey_info`, not from the k8s cache.

If the `api` process already had an OTel SDK header, step 2 is skipped. B adopts a random `trace-id`. Origin lookup fails. Caller lookup fails unless the SDK span-id accidentally hits the catalog (*n/2³²*). B still knows *itself*. The east-west edge from an SDK-owned hop is missing a name. That is §14.9.

Same-node black-box context (two processes on `i-0a1b`, no header because of UDS or an old kernel) is unchanged: `trace_map` keyed by connection, not by this codec. The codec is for the hop that *leaves* the box.

## 14.9 Use cases that remain unsolved

**The other end is not Beyla.** A public ALB, a Lambda, a customer laptop. They will propagate a valid `trace-id` and a random `span-id`. You get correlation, not identity. Do not hash-overwrite their `trace-id`.

**The process already propagates.** Go `net/http` with the OTel SDK, gRPC with a Huffman `traceparent`, any library that wrote the field first. Beyla will not add a second field. Ingress may still *read* some encodings; egress will not *rewrite* span-id into a caller key. The SDK’s span-id is not your catalog key.

**Survey-only hosts.** Survey mode emits `survey_info` and does not attach tpinjector. A fleet that surveys on a sidecar and instruments on another must share the catalog (the scrape) but only the instrumented host writes loaded ids.

**Instance-level graphs.** Two `api` replicas share keys. You can say “`api` called `worker`.” You cannot say which EC2 of `api` without joining span `host_id` (local) to the *caller’s* `host_id` — and the caller’s host is not in the header. That is what the k8s pod IP used to give you for free. Solving it means more bits (instance in the span-id) or a side channel.

**Caller cardinality above tens of thousands of distinct names.** 32-bit birthday is 1.2% at 10k and likely at 100k. The fix is a dense catalog index (16-bit unique IDs, zero hash collisions to 65k), not a tighter compressor. Origin at 56 bits is not this problem.

**TCP option loss on option-heavy SYNs.** Pre-existing. The codec does not make it worse and does not make it better. Headers remain the reliable HTTP path; non-HTTP still depends on 14 leftover option bytes that often do not exist.

**TLS to a peer whose plaintext you cannot see, and the option did not fit.** No header, no option, no identity. Same as today’s context-propagation miss.

**Non-HTTP protocols with incomplete metadata** (MQTT, Kafka, raw TCP). Beyla already carries a partial blob. The codec applies wherever `tp_info_t` is filled. It does not invent a mapping for protocols that never called `init_new_trace`.

**Trust-boundary restarts.** W3C allows a front door to regenerate `trace-id` to stop identifier abuse. Your origin key dies there. That is spec-compliant hostility, not a bug.

**Arbitrary attributes.** Only `(service_namespace, service_name)`. Not `deployment.environment`, not `cloud.availability_zone`, not a user id (and the spec forbids PII in `traceparent` anyway). More attributes are more bits or a return to `tracestate` (HTTP-only, 512-character soft limit, truncated by vendors).

**PromQL-only shops that will not add labels.** They cannot join. Decode in Beyla and export `service.name` on the span, or add the two keys to `survey_info`. There is no third way.

**Algorithm agility.** Magic is one byte (`0xB1`). A digest change is a fleet flag day. Mixed versions during a rollout produce anonymous nodes, not corrupt traces.

---

The kernel-shaped moral is the same one as `skb_cb` and `sk_storage`: you do not get new fields; you get a contract about bits that were already reserved as “opaque.” W3C reserved the left half of `trace-id` for structure and required `parent-id` to be rewritten every hop. The POC takes both at face value, spends the bits on a hash wide enough to join `survey_info`, and leaves the right half alone so the rest of the tracing world still sees a random number.
