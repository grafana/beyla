package ebpfcommon

import (
	"bytes"
	"net"
	"strconv"

	"golang.org/x/exp/slog"

	"github.com/grafana/beyla/pkg/internal/request"
)

var log = slog.With("component", "goexec.spanner")

func HTTPRequestTraceToSpan(trace *HTTPRequestTrace) request.Span {
	// From C, assuming 0-ended strings
	methodLen := bytes.IndexByte(trace.Method[:], 0)
	if methodLen < 0 {
		methodLen = len(trace.Method)
	}
	pathLen := bytes.IndexByte(trace.Path[:], 0)
	if pathLen < 0 {
		pathLen = len(trace.Path)
	}

	peer := ""
	hostname := ""
	hostPort := 0

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
	default:
		log.Warn("unknown trace type %d", trace.Type)
	}

	return request.Span{
		Type:          request.EventType(trace.Type),
		ID:            trace.Id,
		Method:        string(trace.Method[:methodLen]),
		Path:          string(trace.Path[:pathLen]),
		Peer:          peer,
		Host:          hostname,
		HostPort:      hostPort,
		ContentLength: trace.ContentLength,
		RequestStart:  int64(trace.GoStartMonotimeNs),
		Start:         int64(trace.StartMonotimeNs),
		End:           int64(trace.EndMonotimeNs),
		Status:        int(trace.Status),
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
