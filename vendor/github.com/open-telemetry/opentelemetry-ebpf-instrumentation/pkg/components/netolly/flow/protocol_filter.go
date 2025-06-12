package flow

import (
	"context"
	"fmt"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/netolly/ebpf"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/netolly/flow/transport"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/msg"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/swarm"
)

// ProtocolFilterProvider allows selecting which protocols are going to be instrumented.
// It drops any flow not appearing in the "allowed" list.
// If the Allowed list is empty, it drops any flow appearing in the "excluded" list.
func ProtocolFilterProvider(
	allowed, excluded []string,
	input, output *msg.Queue[[]*ebpf.Record],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if len(allowed) == 0 && len(excluded) == 0 {
			// user did not configure any filter. Ignore this node
			return swarm.Bypass(input, output)
		}
		pf, err := newFilter(allowed, excluded, input, output)
		if err != nil {
			return nil, err
		}
		return pf.nodeLoop, nil
	}
}

type protocolFilter struct {
	isAllowed func(r *ebpf.Record) bool
	input     <-chan []*ebpf.Record
	output    *msg.Queue[[]*ebpf.Record]
}

func newFilter(allowed, excluded []string, input, output *msg.Queue[[]*ebpf.Record]) (*protocolFilter, error) {
	// if the allowed list has items, only interfaces in that list are allowed
	if len(allowed) > 0 {
		allow, err := allower(allowed)
		if err != nil {
			return nil, err
		}
		return &protocolFilter{isAllowed: allow, input: input.Subscribe(), output: output}, nil
	}
	// if the allowed list is empty, any interface is allowed except if it matches the exclusion list
	exclude, err := excluder(excluded)
	if err != nil {
		return nil, err
	}
	return &protocolFilter{isAllowed: exclude, input: input.Subscribe(), output: output}, nil
}

func (pf *protocolFilter) nodeLoop(_ context.Context) {
	defer pf.output.Close()
	for records := range pf.input {
		if filtered := pf.filter(records); len(filtered) > 0 {
			pf.output.Send(filtered)
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
		atp, err := transport.ParseProtocol(aStr)
		if err != nil {
			return nil, err
		}
		protoMap[atp] = struct{}{}
	}
	return protoMap, nil
}
