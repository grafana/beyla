package flow

import (
	"testing"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/netolly/ebpf"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/testutil"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/msg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/v2/pkg/internal/netolly/flow/transport"
)

var tcp1 = &ebpf.Record{NetFlowRecordT: ebpf.NetFlowRecordT{Id: ebpf.NetFlowId{SrcPort: 1, TransportProtocol: uint8(transport.TCP)}}}
var tcp2 = &ebpf.Record{NetFlowRecordT: ebpf.NetFlowRecordT{Id: ebpf.NetFlowId{SrcPort: 2, TransportProtocol: uint8(transport.TCP)}}}
var tcp3 = &ebpf.Record{NetFlowRecordT: ebpf.NetFlowRecordT{Id: ebpf.NetFlowId{SrcPort: 3, TransportProtocol: uint8(transport.TCP)}}}
var udp1 = &ebpf.Record{NetFlowRecordT: ebpf.NetFlowRecordT{Id: ebpf.NetFlowId{SrcPort: 4, TransportProtocol: uint8(transport.UDP)}}}
var udp2 = &ebpf.Record{NetFlowRecordT: ebpf.NetFlowRecordT{Id: ebpf.NetFlowId{SrcPort: 5, TransportProtocol: uint8(transport.UDP)}}}
var icmp1 = &ebpf.Record{NetFlowRecordT: ebpf.NetFlowRecordT{Id: ebpf.NetFlowId{SrcPort: 7, TransportProtocol: uint8(transport.ICMP)}}}
var icmp2 = &ebpf.Record{NetFlowRecordT: ebpf.NetFlowRecordT{Id: ebpf.NetFlowId{SrcPort: 8, TransportProtocol: uint8(transport.ICMP)}}}
var icmp3 = &ebpf.Record{NetFlowRecordT: ebpf.NetFlowRecordT{Id: ebpf.NetFlowId{SrcPort: 9, TransportProtocol: uint8(transport.ICMP)}}}

func TestProtocolFilter_Allow(t *testing.T) {
	input := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(100))
	defer input.Close()
	outputQu := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(100))
	output := outputQu.Subscribe()
	protocolFilter, err := ProtocolFilterProvider([]string{"TCP"}, nil, input, outputQu)(t.Context())
	require.NoError(t, err)
	go protocolFilter(t.Context())

	input.Send([]*ebpf.Record{})
	input.Send([]*ebpf.Record{tcp1, tcp2, tcp3})
	input.Send([]*ebpf.Record{icmp2, udp1, icmp1, udp2, icmp3})
	input.Send([]*ebpf.Record{icmp2, tcp1, udp1, icmp1, tcp2, udp2, tcp3, icmp3})

	filtered := testutil.ReadChannel(t, output, timeout)
	assert.Equal(t, []*ebpf.Record{tcp1, tcp2, tcp3}, filtered)
	filtered = testutil.ReadChannel(t, output, timeout)
	assert.Equal(t, []*ebpf.Record{tcp1, tcp2, tcp3}, filtered)
	// no more slices are sent (the second was completely filtered)
	select {
	case o := <-output:
		require.Failf(t, "unexpected flows!", "%v", o)
	default:
		// ok!!
	}
}

func TestProtocolFilter_Exclude(t *testing.T) {
	input := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(100))
	defer input.Close()
	outputQu := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(100))
	output := outputQu.Subscribe()
	protocolFilter, err := ProtocolFilterProvider(nil, []string{"TCP"}, input, outputQu)(t.Context())
	require.NoError(t, err)
	go protocolFilter(t.Context())

	input.Send([]*ebpf.Record{tcp1, tcp2, tcp3})
	input.Send([]*ebpf.Record{icmp2, udp1, icmp1, udp2, icmp3})
	input.Send([]*ebpf.Record{})
	input.Send([]*ebpf.Record{icmp2, tcp1, udp1, icmp1, tcp2, udp2, tcp3, icmp3})

	filtered := testutil.ReadChannel(t, output, timeout)
	assert.Equal(t, []*ebpf.Record{icmp2, udp1, icmp1, udp2, icmp3}, filtered)
	filtered = testutil.ReadChannel(t, output, timeout)
	assert.Equal(t, []*ebpf.Record{icmp2, udp1, icmp1, udp2, icmp3}, filtered)
	// no more slices are sent (the first was completely filtered)
	select {
	case o := <-output:
		require.Failf(t, "unexpected flows!", "%v", o)
	default:
		// ok!!
	}
}
func TestProtocolFilter_ParsingErrors(t *testing.T) {
	_, err := ProtocolFilterProvider([]string{"TCP", "tralara"}, nil, nil, nil)(t.Context())
	assert.Error(t, err)
	_, err = ProtocolFilterProvider([]string{"TCP", "tralara"}, []string{"UDP"}, nil, nil)(t.Context())
	assert.Error(t, err)
	_, err = ProtocolFilterProvider(nil, []string{"TCP", "tralara"}, nil, nil)(t.Context())
	assert.Error(t, err)
}
