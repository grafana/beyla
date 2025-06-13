package cidr

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/netolly/ebpf"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/testutil"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/msg"
)

const testTimeout = 5 * time.Second

func TestCIDRDecorator(t *testing.T) {
	input := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(100))
	defer input.Close()
	outputQu := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(100))
	outCh := outputQu.Subscribe()
	grouper, err := DecoratorProvider([]string{
		"10.0.0.0/8",
		"10.1.2.0/24",
		"140.130.22.0/24",
		"2001:db8:3c4d:15::/64",
		"2001::/16",
	}, input, outputQu)(t.Context())
	require.NoError(t, err)
	go grouper(t.Context())
	input.Send([]*ebpf.Record{
		flow("10.3.4.5", "10.1.2.3"),
		flow("2001:db8:3c4d:15:3210::", "2001:3333:3333::"),
		flow("140.130.22.11", "140.130.23.11"),
		flow("180.130.22.11", "10.1.2.4"),
	})
	decorated := testutil.ReadChannel(t, outCh, testTimeout)
	require.Len(t, decorated, 4)
	assert.Equal(t, "10.0.0.0/8", decorated[0].Attrs.Metadata["src.cidr"])
	assert.Equal(t, "10.1.2.0/24", decorated[0].Attrs.Metadata["dst.cidr"])
	assert.Equal(t, "2001:db8:3c4d:15::/64", decorated[1].Attrs.Metadata["src.cidr"])
	assert.Equal(t, "2001::/16", decorated[1].Attrs.Metadata["dst.cidr"])
	assert.Equal(t, "140.130.22.0/24", decorated[2].Attrs.Metadata["src.cidr"])
	assert.Empty(t, decorated[2].Attrs.Metadata["dst.cidr"])
	assert.Empty(t, decorated[3].Attrs.Metadata["src.cidr"])
	assert.Equal(t, "10.1.2.0/24", decorated[3].Attrs.Metadata["dst.cidr"])
}

func TestCIDRDecorator_GroupAllUnknownTraffic(t *testing.T) {
	input := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(100))
	defer input.Close()
	outputQu := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(100))
	outCh := outputQu.Subscribe()
	grouper, err := DecoratorProvider([]string{
		"10.0.0.0/8",
		"10.1.2.0/24",
		"0.0.0.0/0", // this entry will capture all the unknown traffic
		"140.130.22.0/24",
		"2001:db8:3c4d:15::/64",
		"2001::/16",
	}, input, outputQu)(t.Context())
	require.NoError(t, err)
	go grouper(t.Context())
	input.Send([]*ebpf.Record{
		flow("10.3.4.5", "10.1.2.3"),
		flow("2001:db8:3c4d:15:3210::", "2001:3333:3333::"),
		flow("140.130.22.11", "140.130.23.11"),
		flow("180.130.22.11", "10.1.2.4"),
	})
	decorated := testutil.ReadChannel(t, outCh, testTimeout)
	require.Len(t, decorated, 4)
	assert.Equal(t, "10.0.0.0/8", decorated[0].Attrs.Metadata["src.cidr"])
	assert.Equal(t, "10.1.2.0/24", decorated[0].Attrs.Metadata["dst.cidr"])
	assert.Equal(t, "2001:db8:3c4d:15::/64", decorated[1].Attrs.Metadata["src.cidr"])
	assert.Equal(t, "2001::/16", decorated[1].Attrs.Metadata["dst.cidr"])
	assert.Equal(t, "140.130.22.0/24", decorated[2].Attrs.Metadata["src.cidr"])
	assert.Equal(t, "0.0.0.0/0", decorated[2].Attrs.Metadata["dst.cidr"])
	assert.Equal(t, "0.0.0.0/0", decorated[3].Attrs.Metadata["src.cidr"])
	assert.Equal(t, "10.1.2.0/24", decorated[3].Attrs.Metadata["dst.cidr"])
}

func flow(srcIP, dstIP string) *ebpf.Record {
	er := ebpf.Record{}
	copy(er.Id.SrcIp.In6U.U6Addr8[:], net.ParseIP(srcIP).To16())
	copy(er.Id.DstIp.In6U.U6Addr8[:], net.ParseIP(dstIP).To16())
	return &er
}
