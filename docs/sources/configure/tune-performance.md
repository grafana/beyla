---
title: Configure Beyla performance
menuTitle: Tune performance
description: Configure how the eBPF tracer component instruments HTTP and GRPC services of external processes and creates traces to forward to the next stage of the pipeline.
weight: 90
keywords:
  - Beyla
  - eBPF
---

# Configure Beyla performance

You can use the eBPF tracer to fine-tune Beyla performance.

You can configure the component under the `ebpf` section of your YAML configuration or via environment variables.

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
| `traffic_control_backend` | `BEYLA_BPF_TC_BACKEND`            | string  |  `auto`   |

Chooses which backend to use for the attachment of traffic control probes.
Linux 6.6 has added support for a file-descriptor based traffic control
attachment called TCX, providing a more robust way of attaching traffic
control probes (it does not require explicit qdisc management, and provides a
deterministic way to chain probes).
We recommend the usage of the `tcx` backend for kernels >= 6.6 for this reason.
When set to `auto`, Beyla picks the most suitable backend based on the underlying kernel.

The accepted backends are `tc`, `tcx`, and `auto.
An empty or unset value defaults to `auto`.

| YAML                    | Environment variable               | Type    | Default |
| ----------------------- | ---------------------------------- | ------- | ------- |
| `http_request_timeout`  | `BEYLA_BPF_HTTP_REQUEST_TIMEOUT`   | string  | (0ms)   |

Configures the time interval after which an HTTP request is considered as a timeout.
This option allows Beyla to report HTTP transactions which timeout and never return.
To enable the automatic HTTP request timeout feature, set this option to a non-zero
value. When a request is automatically timed out, Beyla reports the HTTP status
code of 408. Disconnects can be misinterpreted as timeouts, therefore, setting this
value may incorrectly increase your request averages.

| YAML                    | Environment variable               | Type     | Default |
| ----------------------- | ---------------------------------- | -------- | ------- |
| `high_request_volume`   | `BEYLA_BPF_HIGH_REQUEST_VOLUME`    | boolean  | (false) |

Configures the HTTP tracer heuristic to send telemetry events as soon as a response is detected.
Setting this option reduces the accuracy of timings for requests with large responses, however,
in high request volume scenarios this option will reduce the number of dropped trace events.
