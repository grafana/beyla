package flow

import (
	"fmt"

	"github.com/mariomac/pipes/pipe"

	"github.com/grafana/beyla/pkg/internal/netolly/ebpf"
	"github.com/grafana/beyla/pkg/internal/netolly/flow/transport"
)

// ProtocolFilterProvider allows selecting which protocols are going to be instrumented.
// It drops any flow not appearing in the "allowed" list.
// If the Allowed list is empty, it drops any flow appearing in the "excluded" list.
func ProtocolFilterProvider(allowed, excluded []string) pipe.MiddleProvider[[]*ebpf.Record, []*ebpf.Record] {
	return func() (pipe.MiddleFunc[[]*ebpf.Record, []*ebpf.Record], error) {
		if len(allowed) == 0 && len(excluded) == 0 {
			// user did not configure any filter. Ignore this node
			return pipe.Bypass[[]*ebpf.Record](), nil
		}
		pf, err := newFilter(allowed, excluded)
		if err != nil {
			return nil, err
		}
		return pf.nodeLoop, nil
	}
}

type protocolFilter struct {
	allowed  map[transport.Protocol]struct{}
	excluded map[transport.Protocol]struct{}
}

func newFilter(allowed, excluded []string) (*protocolFilter, error) {
	pf := protocolFilter{
		allowed:  map[transport.Protocol]struct{}{},
		excluded: map[transport.Protocol]struct{}{},
	}
	for _, aStr := range allowed {
		if atp, err := transport.ParseProtocol(aStr); err == nil {
			pf.allowed[atp] = struct{}{}
		} else {
			return nil, fmt.Errorf("in network protocols: %w", err)
		}
	}
	for _, eStr := range excluded {
		if etp, err := transport.ParseProtocol(eStr); err == nil {
			pf.excluded[etp] = struct{}{}
		} else {
			return nil, fmt.Errorf("in network excluded protocols: %w", err)
		}
	}
	return &pf, nil
}

func (pf *protocolFilter) nodeLoop(in <-chan []*ebpf.Record, out chan<- []*ebpf.Record) {
	for records := range in {
		if filtered := pf.filter(records); len(filtered) > 0 {
			out <- filtered
		}
	}
}

func (pf *protocolFilter) filter(input []*ebpf.Record) []*ebpf.Record {
	writeIdx := 0
	for readIdx := range input {
		if pf.isAllowed(input[readIdx]) {
			input[writeIdx] = input[readIdx]
			writeIdx++
		}
	}
	return input[:writeIdx]
}

func (pf *protocolFilter) isAllowed(r *ebpf.Record) bool {
	// if the allowed list is empty, any interface is allowed except if it matches the exclusion list
	if len(pf.allowed) == 0 {
		_, excluded := pf.excluded[transport.Protocol(r.Id.TransportProtocol)]
		return !excluded
	}
	_, ok := pf.allowed[transport.Protocol(r.Id.TransportProtocol)]
	return ok
}
