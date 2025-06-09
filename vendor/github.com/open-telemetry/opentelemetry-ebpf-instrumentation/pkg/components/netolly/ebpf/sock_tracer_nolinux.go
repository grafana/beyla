//go:build !linux

package ebpf

import (
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/ebpf/ringbuf"
)

type SockFlowFetcher struct{}

func (s *SockFlowFetcher) Close() error {
	panic("this is never going to be executed")
}

func (s *SockFlowFetcher) LookupAndDeleteMap() map[NetFlowId][]NetFlowMetrics {
	panic("this is never going to be executed")
}

func (s *SockFlowFetcher) ReadRingBuf() (ringbuf.Record, error) {
	panic("this is never going to be executed")
}

func NewSockFlowFetcher(_, _ int) (*SockFlowFetcher, error) {
	return nil, nil
}
