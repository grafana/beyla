package ebpfcommon

import (
	"bytes"
	"log/slog"
	"net"
	"strconv"
	"strings"

	"github.com/grafana/beyla/pkg/internal/request"
)

var log = slog.With("component", "goexec.spanner")

func HTTPRequestTraceToSpan(trace *HTTPRequestTrace) request.Span {
	// From C, assuming 0-ended strings
	methodLen := bytes.IndexByte(trace.Method[:], 0)
	if methodLen < 0 {
		methodLen = len(trace.Method)
	}
	method := string(trace.Method[:methodLen])
	pathLen := bytes.IndexByte(trace.Path[:], 0)
	if pathLen < 0 {
		pathLen = len(trace.Path)
	}
	path := string(trace.Path[:pathLen])

	peer := ""
	hostname := ""
	hostPort := 0
	traceparent := extractTraceparent(trace.Traceparent)

	switch request.EventType(trace.Type) {
	case request.EventTypeHTTPClient, request.EventTypeHTTP:
		peer, _ = extractHostPort(trace.RemoteAddr[:])
		hostname, hostPort = extractHostPort(trace.Host[:])
	case request.EventTypeGRPC:
		hostPort = int(trace.HostPort)
		peer = extractIP(trace.RemoteAddr[:], int(trace.RemoteAddrLen))
		hostname = extractIP(trace.Host[:], int(trace.HostLen))
	case request.EventTypeGRPCClient:
		hostname, hostPort = extractHostPort(trace.Host[:])
	case request.EventTypeSQLClient:
		trace.GoStartMonotimeNs = trace.StartMonotimeNs
		method, path = getSQLOperationAndTable(path)
	default:
		log.Warn("unknown trace type", "type", trace.Type)
	}

	return request.Span{
		Type:          request.EventType(trace.Type),
		ID:            trace.Id,
		Method:        method,
		Path:          path,
		Peer:          peer,
		Host:          hostname,
		HostPort:      hostPort,
		ContentLength: trace.ContentLength,
		RequestStart:  int64(trace.GoStartMonotimeNs),
		Start:         int64(trace.StartMonotimeNs),
		End:           int64(trace.EndMonotimeNs),
		Status:        int(trace.Status),
		Traceparent:   traceparent,
	}
}

func extractHostPort(b []uint8) (string, int) {
	addrLen := bytes.IndexByte(b, 0)
	if addrLen < 0 {
		addrLen = len(b)
	}

	peer := ""
	peerPort := 0

	if addrLen > 0 {
		addr := string(b[:addrLen])
		ip, port, err := net.SplitHostPort(addr)
		if err != nil {
			peer = addr
		} else {
			peer = ip
			peerPort, _ = strconv.Atoi(port)
		}
	}

	return peer, peerPort
}

func extractIP(b []uint8, size int) string {
	if size > len(b) {
		size = len(b)
	}
	return net.IP(b[:size]).String()
}

func extractTraceparent(traceparent [55]byte) string {
	// If traceparent was not set, array should be all zeroes.
	if traceparent[0] == 0 {
		return ""
	}
	return string(traceparent[:])
}

func getSQLOperationAndTable(queryString string) (string, string) {
	fields := strings.Fields(queryString)
	if len(fields) == 0 {
		return "", ""
	}
	operation := strings.ToUpper(fields[0])
	if len(fields) < 2 {
		return operation, ""
	}
	table := ""
	if operation == "UPDATE" {
		return operation, fields[1]
	}
	if len(fields) < 3 {
		return operation, ""
	}
	switch operation {
	case "ALTER", "CREATE", "DROP", "TRUNCATE":
		if strings.ToUpper(fields[1]) == "TABLE" {
			// TODO: Handle "If exists" -- cyclomatic complexity is too great here to pass linter
			//if len(fields) < 5 {
			return operation, fields[2]
			//} else if strings.ToUpper(fields[2]) == "IF" &&
			//	strings.ToUpper(fields[3]) == "EXISTS" {
			//	return operation, fields[4]
			//}
		}
	}
	for i, f := range fields {
		word := strings.ToUpper(f)
		switch word {
		case "FROM", "INTO", "ON":
			next := i + 1
			if next < len(fields) {
				table = fields[next]
			}
			return operation, table
		}
	}
	return operation, table
}
