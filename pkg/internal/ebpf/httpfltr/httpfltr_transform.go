package httpfltr

import (
	"strings"

	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/svc"
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
		ServiceID:     svc.ID{Name: info.Comm},
		Traceparent:   info.Traceparent,
	}
}

func removeQuery(url string) string {
	idx := strings.IndexByte(url, '?')
	if idx > 0 {
		return url[:idx]
	}
	return url
}
