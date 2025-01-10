
## EBPF tracer

YAML section `ebpf`.

| YAML         | Environment variable   | Type   | Default |
| ------------ | ---------------------- | ------ | ------- |
| `wakeup_len` | `BEYLA_BPF_WAKEUP_LEN` | string | (unset) |

Specifies how many messages need to be accumulated in the eBPF ringbuffer
before sending a wake-up request to the user space code.

In high-load services (in terms of requests/second), tuning this option to higher values
can help with reducing the CPU overhead of Beyla.

In low-load services (in terms of requests/second), high values of `wakeup_len` could
add a noticeable delay in the time the metrics are submitted and become externally visible.

| YAML                      | Environment variable              | Type    | Default |
| ------------------------- | --------------------------------- | ------- | ------- |
| `traffic_control_backend` | `BEYLA_BPF_TC_BACKEND`            | string  |  `tc`   |

Chooses which backend to use for the attachment of traffic control probes.
Linux 6.6 has added support for a file-descriptor based traffic control
attachment called TCX, providing a more robust way of attaching traffic
control probes (it does not require explicit qdisc management, and provides a
deterministic way to chain probes). We recommend the usage of the `tcx`
backend for kernels >= 6.6 for this reason.

The accepted backends are `tc` and `tcx`. An empty or unset value defaults to
`tc`.

| YAML                    | Environment variable               | Type    | Default |
| ----------------------- | ---------------------------------- | ------- | ------- |
| `http_request_timeout`  | `BEYLA_BPF_HTTP_REQUEST_TIMEOUT`   | string  | (30s)   |

Configures the time interval after which an HTTP request is considered as a timeout.
This option allows Beyla to report HTTP transactions which timeout and never return.
To disable the automatic HTTP request timeout feature, set this option to zero,
that is "0ms".

| YAML                    | Environment variable               | Type     | Default |
| ----------------------- | ---------------------------------- | -------- | ------- |
| `high_request_volume`   | `BEYLA_BPF_HIGH_REQUEST_VOLUME`    | boolean  | (false) |

Configures the HTTP tracer heuristic to send telemetry events as soon as a response is detected.
Setting this option reduces the accuracy of timings for requests with large responses, however,
in high request volume scenarios this option will reduce the number of dropped trace events.
