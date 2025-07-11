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

YAML section: `grafana.otlp`

You can use the eBPF tracer to fine-tune Beyla performance.

You can configure the component under the `ebpf` section of your YAML configuration or with environment variables.

| YAML<p>environment variable</p>                               | Description                                                                                                                                                   | Type    | Default |
| ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- | ------- |
| `wakeup_len`<p>`BEYLA_BPF_WAKEUP_LEN`</p>                     | Sets how many messages Beyla accumulates in the eBPF ring buffer before sending a wake-up request to user space. Refer to [wake up length](#wake-up-length).  | string  | (unset) |
| `traffic_control_backend`<p>`BEYLA_BPF_TC_BACKEND`</p>        | Selects the backend for attaching traffic control probes. Refer to the [traffic control backend](#traffic-control-backend) section for details.               | string  | `auto`  |
| `http_request_timeout`<p>`BEYLA_BPF_HTTP_REQUEST_TIMEOUT`</p> | Sets the time interval after which Beyla considers an HTTP request a timeout. Refer to the [HTTP request timeout](#http-request-timeout) section for details. | string  | (0ms)   |
| `high_request_volume`<p>`BEYLA_BPF_HIGH_REQUEST_VOLUME`</p>   | Sends telemetry events as soon as Beyla detects a response. Refer to the [high request volume](#high-request-volume) section for details.                     | boolean | (false) |

## Wake up length

Beyla accumulates messages in the eBPF ringbuffer and sends a wake-up request to user space when it reaches this value.

For high-load services, set this option higher to reduce CPU overhead.

For low-load services, high values can delay when Beyla submits metrics and when they become visible.

## Traffic control backend

This option selects the backend for attaching traffic control probes.
Linux 6.6 adds support for TCX, a file-descriptor based traffic control attachment. TCX is more robust, doesn't require explicit qdisc management, and chains probes deterministically.
We recommend the `tcx` backend for kernels >= 6.6.
When set to `auto`, Beyla chooses the best backend for your kernel.

Accepted backends: `tc`, `tcx`, and `auto`.
If you leave this value empty or unset, Beyla uses `auto`.

## HTTP request timeout

This option sets how long Beyla waits before considering an HTTP request a timeout.
Beyla can report HTTP transactions that time out and never return.
Set this option to a non-zero value to enable automatic HTTP request timeouts. When a request times out, Beyla reports HTTP status code 408. Disconnects can look like timeouts, so setting this value may increase your request averages.

## High request volume

This option makes Beyla send telemetry events as soon as it detects a response.
It reduces timing accuracy for requests with large responses, but in high-volume scenarios, it helps reduce dropped trace events.
