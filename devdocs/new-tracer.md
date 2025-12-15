# Add new TCP based BPF tracer

This documents the steps required to add a new TCP protocol based BPF tracer to Beyla.

## Investigate the protocol

First, you need to understand the protocol used by the application you want to trace. Beyla captures TCP packets and you need to add the logic to identify the packets that belong to the protocol you want to trace. The are basically two cases:

- The package comes in plain text, like SQL. In this case, you can just search for the SQL keywords in the packets.
- The package comes in binary format, like Kafka. In this case, you need to figure out how to identify the start and end of the packets and where the relevant information is.


## Add the new protocol to the BPF program

In [pkg/internal/ebpf/common/tcp_detect_transform.go](https://github.com/grafana/beyla/blob/main/pkg/internal/ebpf/common/tcp_detect_transform.go) any TCP packet captured from BPF passes through the `ReadTCPRequestIntoSpan` function, and depending what's in the bytes, you can identify if the packet is SQL, Redis, etc. You need to add a new case to this function to identify the new protocol.

Once you have this done (the hard part!), you have to create a new `EventType` in [pkg/internal/request/span.go](https://github.com/grafana/beyla/blob/main/pkg/internal/request/span.go#L4). Look how other `EventTypes` are handled, and you probably need to edit every single file where the data is flowing. For example, to add a new OTEL trace you have to edit `traceAttributes` in [pkg/export/otel/traces.go](https://github.com/grafana/beyla/blob/main/pkg/export/otel/traces.go#L4)

Take a look at this PR for an example of how to add a new Kafka protocol: https://github.com/grafana/beyla/pull/890

## Other considerations

- Add always definitions for Prometheus metrics and OpenTelemetry traces and metrics.
- Look for already defined semantic conventions defined in OpenTelemetry spec for those attributes.
   - If there's nothing defined, you can create your own attributes, and if they are useful, propose them to the OpenTelemetry community.
- Add always tests, both unit and OATS integration tests.
- Add always documentation of the newly introduced metrics and traces for this protocol.