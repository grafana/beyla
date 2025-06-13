//go:build !linux

package ebpf

import (
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/ebpf/ringbuf"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/netolly/ebpf"
)

type SockFlowFetcher struct{}

func (s *SockFlowFetcher) Close() error {
	panic("this is never going to be executed")
}

func (s *SockFlowFetcher) LookupAndDeleteMap() map[ebpf.NetFlowId][]ebpf.NetFlowMetrics {
	panic("this is never going to be executed")
}

func (s *SockFlowFetcher) ReadRingBuf() (ringbuf.Record, error) {
	panic("this is never going to be executed")
}

func NewSockFlowFetcher(_, _ int) (*SockFlowFetcher, error) {
	return nil, nil
}
