package httpfltr

import (
	"strings"

	"github.com/grafana/beyla/pkg/internal/request"
	"go.opentelemetry.io/otel/trace"
)

func httpInfoToSpan(info *HTTPInfo) request.Span {
	return request.Span{
		Type:          request.EventType(info.Type),
		ID:            0,
		Method:        info.Method,
		Path:          removeQuery(info.URL),
		Peer:          info.Peer,
		Host:          info.Host,
		HostPort:      int(info.ConnInfo.D_port),
		ContentLength: int64(info.Len),
		RequestStart:  int64(info.StartMonotimeNs),
		Start:         int64(info.StartMonotimeNs),
		End:           int64(info.EndMonotimeNs),
		Status:        int(info.Status),
		ServiceID:     info.Service,
		TraceID:       trace.TraceID(info.Tp.TraceId),
		SpanID:        trace.SpanID(info.Tp.SpanId),
		ParentSpanID:  trace.SpanID(info.Tp.ParentId),
		Pid: request.PidInfo{
			HostPID:   info.Pid.HostPid,
			UserPID:   info.Pid.UserPid,
			Namespace: info.Pid.Namespace,
		},
	}
}

func removeQuery(url string) string {
	idx := strings.IndexByte(url, '?')
	if idx > 0 {
		return url[:idx]
	}
	return url
}
