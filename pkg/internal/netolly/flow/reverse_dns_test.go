package flow

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/v2/pkg/internal/netolly/ebpf"
	"github.com/grafana/beyla/v2/pkg/internal/testutil"
	"github.com/grafana/beyla/v2/pkg/pipe/msg"
)

var srcIP = [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 140, 82, 121, 4}
var dstIP = [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 127, 0, 0, 1}

func TestReverseDNS(t *testing.T) {
	netLookupAddr = func(addr string) (names []string, err error) {
		if addr == "140.82.121.4" {
			return []string{"foo.github.com"}, nil
		} else if addr == "127.0.0.1" {
			return []string{"localhost.localdomain"}, nil
		}
		return []string{"unknown"}, nil
	}
	// Given a Reverse DNS node
	in := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(10))
	out := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(10))
	outCh := out.Subscribe()
	reverseDNS, err := ReverseDNSProvider(&ReverseDNS{Type: ReverseDNSLocalLookup, CacheLen: 255, CacheTTL: time.Minute}, in, out)(t.Context())
	require.NoError(t, err)
	go reverseDNS(t.Context())

	// When it receives flows without source nor destination name
	f1 := &ebpf.Record{NetFlowRecordT: ebpf.NetFlowRecordT{
		Id: ebpf.NetFlowId{IfIndex: 1},
	}}
	f1.Id.SrcIp.In6U.U6Addr8 = srcIP
	f1.Id.DstIp.In6U.U6Addr8 = dstIP

	in.Send([]*ebpf.Record{f1})

	// THEN it decorates them with the looked up source/destination names
	decorated := testutil.ReadChannel(t, outCh, timeout)
	require.Len(t, decorated, 1)

	assert.Contains(t, decorated[0].Attrs.SrcName, "github")
	assert.Contains(t, decorated[0].Attrs.DstName, "local")
}

func TestReverseDNS_AlreadyProvidedNames(t *testing.T) {
	netLookupAddr = func(addr string) ([]string, error) {
		require.Fail(t, "network lookup shouldn't be invoked!", "Got:", addr)
		return nil, errors.New("boom")
	}
	// Given a Reverse DNS node
	in := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(10))
	out := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(10))
	outCh := out.Subscribe()
	reverseDNS, err := ReverseDNSProvider(&ReverseDNS{Type: ReverseDNSLocalLookup, CacheLen: 255, CacheTTL: time.Minute}, in, out)(t.Context())
	require.NoError(t, err)
	go reverseDNS(t.Context())

	// When it receives flows with source and destination names
	f1 := &ebpf.Record{
		NetFlowRecordT: ebpf.NetFlowRecordT{Id: ebpf.NetFlowId{IfIndex: 1}},
		Attrs:          ebpf.RecordAttrs{SrcName: "src", DstName: "dst"},
	}
	f1.Id.SrcIp.In6U.U6Addr8 = srcIP
	f1.Id.DstIp.In6U.U6Addr8 = dstIP

	in.Send([]*ebpf.Record{f1})

	// THEN it does not cange the decoration
	decorated := testutil.ReadChannel(t, outCh, timeout)
	require.Len(t, decorated, 1)

	assert.Contains(t, decorated[0].Attrs.SrcName, "src")
	assert.Contains(t, decorated[0].Attrs.DstName, "dst")
}

func TestReverseDNS_Cache(t *testing.T) {
	lookups := 0
	netLookupAddr = func(_ string) (_ []string, _ error) {
		require.Zero(t, lookups, "address lookup should only happen once", lookups)
		lookups++
		return []string{"amazon"}, nil
	}
	// Given a Reverse DNS node
	in := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(10))
	out := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(10))
	outCh := out.Subscribe()
	reverseDNS, err := ReverseDNSProvider(&ReverseDNS{Type: ReverseDNSLocalLookup, CacheLen: 255, CacheTTL: time.Minute}, in, out)(t.Context())
	require.NoError(t, err)
	go reverseDNS(t.Context())

	// When it receives a flow with an unknown destination for the first time
	f1 := &ebpf.Record{
		NetFlowRecordT: ebpf.NetFlowRecordT{Id: ebpf.NetFlowId{IfIndex: 1}},
		Attrs:          ebpf.RecordAttrs{SrcName: "src"},
	}
	f1.Id.SrcIp.In6U.U6Addr8 = srcIP
	f1.Id.DstIp.In6U.U6Addr8 = dstIP

	in.Send([]*ebpf.Record{f1})

	// THEN it decorates it
	decorated := testutil.ReadChannel(t, outCh, timeout)
	require.Len(t, decorated, 1)
	assert.Contains(t, decorated[0].Attrs.DstName, "amazon")

	// AND when it receives the same flow again
	f1.Attrs.DstName = ""
	in.Send([]*ebpf.Record{f1})

	// THEN it decorates it from the cached copy (otherwise the fake netLookupAddr would crash)
	decorated = testutil.ReadChannel(t, outCh, timeout)
	require.Len(t, decorated, 1)
	assert.Contains(t, decorated[0].Attrs.DstName, "amazon")
}
