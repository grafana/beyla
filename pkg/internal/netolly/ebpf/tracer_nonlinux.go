//go:build !linux

package ebpf

import (
	"github.com/cilium/ebpf/ringbuf"

	"github.com/grafana/beyla/pkg/internal/netolly/ifaces"
)

type FlowFetcher struct {
}

func NewFlowFetcher(_, _ int, _, _ bool) (*FlowFetcher, error) {
	return nil, nil
}

func (m *FlowFetcher) Close() error {
	return nil
}

func (m *FlowFetcher) ReadRingBuf() (ringbuf.Record, error) {
	return ringbuf.Record{}, nil
}

func (m *FlowFetcher) LookupAndDeleteMap() map[NetFlowId][]NetFlowMetrics {
	return nil
}
