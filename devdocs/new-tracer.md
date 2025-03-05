# Add new TCP based BPF tracer

This document the steps required to add a new TCP protocol based BPF tracer to Beyla.

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

## Example: Adding JSON-RPC Protocol Support

Here's a practical example of how we implemented JSON-RPC protocol support in Beyla:

### 1. Create a dedicated protocol detector file

We created a specific file for JSON-RPC detection and transformation at `pkg/internal/ebpf/common/jsonrpc_detect_transform.go`:

```go
// JSON-RPC detection and packet transformation
package ebpfcommon

import (
    "encoding/json"
    "errors"
    "strings"
    "unsafe"

    trace2 "go.opentelemetry.io/otel/trace"

    "github.com/grafana/beyla/v2/pkg/internal/request"
)

// JSONRPCInfo contains information about a JSON-RPC request or response
type JSONRPCInfo struct {
    Method string
    ID     string
    Params json.RawMessage
}

const (
    JSONRPCMinLength = 10 // Minimal length for a valid JSON-RPC message
    JSONRPCMaxLength = 1024 * 1024 // 1MB max payload size
)

// ProcessPossibleJSONRPCEvent processes a TCP packet and returns error if the packet is not a valid JSON-RPC request.
// Otherwise, return JSONRPCInfo with the processed data.
func ProcessPossibleJSONRPCEvent(event *TCPRequestInfo, pkt []byte, rpkt []byte) (*JSONRPCInfo, error) {
    info, err := ProcessJSONRPCRequest(pkt)
    if err != nil {
        // If we are getting the information in the response buffer, the event
        // must be reversed and that's how we captured it.
        info, err = ProcessJSONRPCRequest(rpkt)
        if err == nil {
            reverseTCPEvent(event)
        }
    }
    return info, err
}

// ProcessJSONRPCRequest processes a packet and returns JSONRPCInfo if it's a valid JSON-RPC message
func ProcessJSONRPCRequest(pkt []byte) (*JSONRPCInfo, error) {
    // Validation logic for JSON-RPC packet
    // ...implementation details
}

// TCPToJSONRPCToSpan transforms TCP request info and JSON-RPC info into a generic span
func TCPToJSONRPCToSpan(trace *TCPRequestInfo, data *JSONRPCInfo) request.Span {
    // Transform to span object
    // ...implementation details
}
```

### 2. Update the event types

We added new event types in `pkg/internal/request/span.go` to represent JSON-RPC client and server events:

```go
const (
    // ...existing EventTypes...
    EventTypeJSONRPCClient
    EventTypeJSONRPCServer
)
```

### 3. Integrate with TCP detection

We modified the `ReadTCPRequestIntoSpan` function in `tcp_detect_transform.go` to check for JSON-RPC messages:

```go
func ReadTCPRequestIntoSpan(cfg *config.EBPFTracer, record *ringbuf.Record, filter ServiceFilter) (request.Span, bool, error) {
    // ...existing code...
    
    // Check if we have a JSON-RPC message
    jsonrpc, err := ProcessPossibleJSONRPCEvent(&event, b, event.Rbuf[:rl])
    if err == nil {
        return TCPToJSONRPCToSpan(&event, jsonrpc), false, nil
    }
    
    // Try other protocols...
    // ...existing code...
}
```

### 4. Add OpenTelemetry export support

Finally, we added JSON-RPC specific attributes to the OpenTelemetry traces export in `traces.go`:

```go
func traceAttributes(span *request.Span, optionalAttrs map[attr.Name]struct{}) []attribute.KeyValue {
    var attrs []attribute.KeyValue
    switch span.Type {
    // ...existing protocols...
    
    case request.EventTypeJSONRPCClient, request.EventTypeJSONRPCServer:
        attrs = []attribute.KeyValue{
            request.ServerAddr(request.HostAsServer(span)),
            request.ServerPort(span.HostPort),
            semconv.RPCSystem("jsonrpc"),
            semconv.RPCMethod(span.Method),
        }
        if span.Statement != "" {
            attrs = append(attrs, attribute.String("jsonrpc.request.id", span.Statement))
        }
    }
    
    // ...existing code...
}

func (tr *tracesOTELReceiver) acceptSpan(span *request.Span) bool {
    switch span.Type {
    // ...existing cases...
    
    case request.EventTypeJSONRPCClient, request.EventTypeJSONRPCServer:
        return tr.is.HTTPEnabled() // Use HTTP instrumentation flag for JSON-RPC
    }
    return false
}
```

### 5. Adding span kind handling

We updated the `spanKind` function to properly categorize JSON-RPC spans:

```go
func spanKind(span *request.Span) trace2.SpanKind {
    switch span.Type {
    case request.EventTypeHTTP, request.EventTypeGRPC, request.EventTypeRedisServer, request.EventTypeKafkaServer, request.EventTypeJSONRPCServer:
        return trace2.SpanKindServer
    case request.EventTypeHTTPClient, request.EventTypeGRPCClient, request.EventTypeSQLClient, request.EventTypeRedisClient, request.EventTypeJSONRPCClient:
        return trace2.SpanKindClient
    // ...existing code...
    }
    return trace2.SpanKindInternal
}
```
