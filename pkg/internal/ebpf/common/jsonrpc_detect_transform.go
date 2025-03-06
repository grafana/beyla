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
	JSONRPCMinLength = 10          // Minimal length for a valid JSON-RPC message
	JSONRPCMaxLength = 1024 * 1024 // 1MB max payload size
)

// ProcessPossibleJSONRPCEvent processes a TCP packet and returns error if the packet is not a valid JSON-RPC request.
// Otherwise, return JSONRPCInfo with the processed data.
func ProcessPossibleJSONRPCEvent(event *TCPRequestInfo, pkt []byte, rpkt []byte) (*JSONRPCInfo, error) {
	// debug
	log.Debug("[debuger:at:ProcessPossibleJSONRPCEvent>>>>]", event, pkt, rpkt)
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
	if len(pkt) < JSONRPCMinLength {
		return nil, errors.New("packet too short")
	}

	if len(pkt) > JSONRPCMaxLength {
		return nil, errors.New("packet too large")
	}

	// Check if the packet starts with '{'
	if pkt[0] != '{' {
		return nil, errors.New("not a JSON message")
	}

	// Try to find a JSON-RPC characteristic pattern
	content := string(pkt)
	if !strings.Contains(content, "\"jsonrpc\"") {
		return nil, errors.New("not a JSON-RPC message")
	}

	// Parse the JSON
	var jsonRPCMap map[string]json.RawMessage
	if err := json.Unmarshal(pkt, &jsonRPCMap); err != nil {
		return nil, errors.New("invalid JSON format")
	}

	// Validate it's a JSON-RPC by checking required fields
	version, ok := jsonRPCMap["jsonrpc"]
	if !ok {
		return nil, errors.New("missing jsonrpc field")
	}

	var versionStr string
	if err := json.Unmarshal(version, &versionStr); err != nil {
		return nil, errors.New("invalid jsonrpc version format")
	}

	if versionStr != "2.0" {
		return nil, errors.New("unsupported JSON-RPC version")
	}

	// Extract the method and id
	info := &JSONRPCInfo{}

	// Method is required in requests but not in responses
	if method, ok := jsonRPCMap["method"]; ok {
		if err := json.Unmarshal(method, &info.Method); err != nil {
			return nil, errors.New("invalid method format")
		}
	}

	// ID can be string, number or null
	if id, ok := jsonRPCMap["id"]; ok {
		var idValue interface{}
		if err := json.Unmarshal(id, &idValue); err != nil {
			return nil, errors.New("invalid id format")
		}

		switch v := idValue.(type) {
		case string:
			info.ID = v
		case float64:
			info.ID = string(id)
		case nil:
			// Notification, no ID
			info.ID = ""
		default:
			info.ID = string(id)
		}
	}

	// Store params if available
	if params, ok := jsonRPCMap["params"]; ok {
		info.Params = params
	}

	return info, nil
}

// TCPToJSONRPCToSpan transforms TCP request info and JSON-RPC info into a generic span
func TCPToJSONRPCToSpan(trace *TCPRequestInfo, data *JSONRPCInfo) request.Span {
	peer := ""
	hostname := ""
	hostPort := 0

	if trace.ConnInfo.S_port != 0 || trace.ConnInfo.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(unsafe.Pointer(&trace.ConnInfo)).reqHostInfo()
		hostPort = int(trace.ConnInfo.D_port)
	}

	reqType := request.EventTypeJSONRPCClient
	if trace.Direction == 0 {
		reqType = request.EventTypeJSONRPCServer
	}

	return request.Span{
		Type:          reqType,
		Method:        data.Method,
		Statement:     data.ID,
		Path:          "", // No specific path in JSON-RPC
		Peer:          peer,
		PeerPort:      int(trace.ConnInfo.S_port),
		Host:          hostname,
		HostPort:      hostPort,
		ContentLength: 0,
		RequestStart:  int64(trace.StartMonotimeNs),
		Start:         int64(trace.StartMonotimeNs),
		End:           int64(trace.EndMonotimeNs),
		Status:        0,
		TraceID:       trace2.TraceID(trace.Tp.TraceId),
		SpanID:        trace2.SpanID(trace.Tp.SpanId),
		ParentSpanID:  trace2.SpanID(trace.Tp.ParentId),
		Flags:         trace.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   trace.Pid.HostPid,
			UserPID:   trace.Pid.UserPid,
			Namespace: trace.Pid.Ns,
		},
	}
}
