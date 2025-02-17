package flow

import (
	"fmt"

	"github.com/mariomac/pipes/pipe"

	"github.com/grafana/beyla/v2/pkg/internal/netolly/ebpf"
	"github.com/grafana/beyla/v2/pkg/internal/netolly/flow/transport"
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
	isAllowed func(r *ebpf.Record) bool
}

func newFilter(allowed, excluded []string) (*protocolFilter, error) {
	// if the allowed list has items, only interfaces in that list are allowed
	if len(allowed) > 0 {
		allow, err := allower(allowed)
		if err != nil {
			return nil, err
		}
		return &protocolFilter{isAllowed: allow}, nil
	}
	// if the allowed list is empty, any interface is allowed except if it matches the exclusion list
	exclude, err := excluder(excluded)
	if err != nil {
		return nil, err
	}
	return &protocolFilter{isAllowed: exclude}, nil
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

func allower(allowed []string) (func(r *ebpf.Record) bool, error) {
	allow, err := protocolsMap(allowed)
	if err != nil {
		return nil, fmt.Errorf("in network protocols: %w", err)
	}
	return func(r *ebpf.Record) bool {
		_, ok := allow[transport.Protocol(r.Id.TransportProtocol)]
		return ok
	}, nil
}

func excluder(excluded []string) (func(r *ebpf.Record) bool, error) {
	exclude, err := protocolsMap(excluded)
	if err != nil {
		return nil, fmt.Errorf("in network excluded protocols: %w", err)
	}
	return func(r *ebpf.Record) bool {
		_, excluded := exclude[transport.Protocol(r.Id.TransportProtocol)]
		return !excluded
	}, nil
}

func protocolsMap(entries []string) (map[transport.Protocol]struct{}, error) {
	protoMap := map[transport.Protocol]struct{}{}
	for _, aStr := range entries {
		if atp, err := transport.ParseProtocol(aStr); err == nil {
			protoMap[atp] = struct{}{}
		} else {
			return nil, err
		}
	}
	return protoMap, nil
}
