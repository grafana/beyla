//go:build !linux

package ebpf

import (
	"github.com/cilium/ebpf/ringbuf"

	"github.com/grafana/beyla/pkg/internal/ebpf/tcmanager"
)

type FlowFetcher struct {
}

func NewFlowFetcher(_, _ int, _, _ bool, _ tcmanager.TCManager) (*FlowFetcher, error) {
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
