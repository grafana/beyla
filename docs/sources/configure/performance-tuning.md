
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

| YAML                    | Environment variable              | Type    | Default |
| ----------------------- | --------------------------------- | ------- | ------- |
| `track_request_headers` | `BEYLA_BPF_TRACK_REQUEST_HEADERS` | boolean | (false) |

Enables tracking of request headers for the purposes of processing any incoming 'Traceparent'
header values. If this option is enabled, when Beyla encounters an incoming server request with
a 'Traceparent' header value, it will use the provided 'trace id' to create its own trace spans.

This option does not have an effect on Go applications, where the 'Traceparent' field is always
processed, without additional tracking of the request headers.

Enabling this option may increase the performance overhead in high request volume scenarios.
This option is only useful when generating Beyla traces, it does not affect
generation of Beyla metrics.

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

| YAML                    | Environment variable               | Type     | Default |
| ----------------------- | ---------------------------------- | -------- | ------- |
| `heuristic_sql_detect`   | `BEYLA_HEURISTIC_SQL_DETECT`      | boolean  | (false) |

By default, Beyla detects various SQL client requests through detection of their
particular binary protocol format. However, oftentimes SQL database clients send their
queries in a format where Beyla can detect the query statement without knowing
the exact binary protocol. If you are using a database technology not directly supported
by Beyla, you can enable this option to get database client telemetry. The option is
not enabled by default, because it can create false positives, for example, an application
sending SQL text for logging purposes through a TCP connection. Currently supported
protocols where this option isn't needed are the Postgres and MySQL binary protocols.
