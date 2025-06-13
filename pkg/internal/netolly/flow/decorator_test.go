package flow

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/netolly/ebpf"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/testutil"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/msg"
)

const timeout = 5 * time.Second

func TestDecoration(t *testing.T) {
	srcIP := [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 1, 2, 3, 4}
	dstIP := [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 4, 3, 2, 1}

	// Given a flow Decorator node
	in := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(10))
	out := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(10))
	go Decorate(net.IPv4(3, 3, 3, 3), func(n int) string {
		return fmt.Sprintf("eth%d", n)
	}, in, out)(t.Context())

	// When it receives flows
	f1 := &ebpf.Record{NetFlowRecordT: ebpf.NetFlowRecordT{
		Id: ebpf.NetFlowId{IfIndex: 1},
	}, Attrs: ebpf.RecordAttrs{SrcName: "source"}}
	f1.Id.SrcIp.In6U.U6Addr8 = srcIP
	f1.Id.DstIp.In6U.U6Addr8 = dstIP

	f2 := &ebpf.Record{NetFlowRecordT: ebpf.NetFlowRecordT{
		Id: ebpf.NetFlowId{IfIndex: 2},
	}, Attrs: ebpf.RecordAttrs{DstName: "destination"}}
	f2.Id.SrcIp.In6U.U6Addr8 = srcIP
	f2.Id.DstIp.In6U.U6Addr8 = dstIP

	in.Send([]*ebpf.Record{f1, f2})

	// THEN it decorates them, by adding IPs to source/destination
	// names only when they were missing
	decorated := testutil.ReadChannel(t, out.Subscribe(), timeout)
	require.Len(t, decorated, 2)

	assert.Equal(t, "eth1", decorated[0].Attrs.Interface)
	assert.Equal(t, "3.3.3.3", decorated[0].Attrs.BeylaIP)
	assert.Equal(t, "source", decorated[0].Attrs.SrcName)
	assert.Equal(t, "4.3.2.1", decorated[0].Attrs.DstName)

	assert.Equal(t, "eth2", decorated[1].Attrs.Interface)
	assert.Equal(t, "3.3.3.3", decorated[1].Attrs.BeylaIP)
	assert.Equal(t, "1.2.3.4", decorated[1].Attrs.SrcName)
	assert.Equal(t, "destination", decorated[1].Attrs.DstName)
}
