package filter

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	attr "github.com/grafana/beyla/v2/pkg/export/attributes/names"
	"github.com/grafana/beyla/v2/pkg/internal/netolly/ebpf"
	"github.com/grafana/beyla/v2/pkg/internal/request"
	"github.com/grafana/beyla/v2/pkg/internal/testutil"
	"github.com/grafana/beyla/v2/pkg/pipe/msg"
)

const timeout = 5 * time.Second

func TestAttributeFilter(t *testing.T) {
	input := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(10))
	output := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(10))

	filterFunc, err := ByAttribute[*ebpf.Record](AttributeFamilyConfig{
		"beyla.ip":          MatchDefinition{Match: "148.*"},
		"k8s.src.namespace": MatchDefinition{NotMatch: "debug"},
	}, ebpf.RecordStringGetters, input, output)(context.Background())
	require.NoError(t, err)

	out := output.Subscribe()
	go filterFunc(context.Background())

	// records not matching both the ip and src namespace will be dropped
	input.Send([]*ebpf.Record{
		{Attrs: ebpf.RecordAttrs{BeylaIP: "148.132.1.1",
			Metadata: map[attr.Name]string{"k8s.src.namespace": "debug"}}},
		{Attrs: ebpf.RecordAttrs{BeylaIP: "128.132.1.1",
			Metadata: map[attr.Name]string{"k8s.src.namespace": "foo"}}},
		{Attrs: ebpf.RecordAttrs{BeylaIP: "148.132.1.1",
			Metadata: map[attr.Name]string{"k8s.src.namespace": "foo"}}},
		{Attrs: ebpf.RecordAttrs{BeylaIP: "148.133.2.1",
			Metadata: map[attr.Name]string{"k8s.src.namespace": "tralar"}}},
		{Attrs: ebpf.RecordAttrs{BeylaIP: "141.132.1.1",
			Metadata: map[attr.Name]string{"k8s.src.namespace": "tralari"}}},
	})

	// the whole batch will be dropped (won't go to the out channel)
	input.Send([]*ebpf.Record{
		{Attrs: ebpf.RecordAttrs{BeylaIP: "128.132.1.1",
			Metadata: map[attr.Name]string{"k8s.src.namespace": "foo"}}},
		{Attrs: ebpf.RecordAttrs{BeylaIP: "141.132.1.1",
			Metadata: map[attr.Name]string{"k8s.src.namespace": "tralari"}}},
	})

	// no record will be dropped
	input.Send([]*ebpf.Record{
		{Attrs: ebpf.RecordAttrs{BeylaIP: "148.132.1.1",
			Metadata: map[attr.Name]string{"k8s.src.namespace": "foo"}}},
		{Attrs: ebpf.RecordAttrs{BeylaIP: "148.133.2.1",
			Metadata: map[attr.Name]string{"k8s.src.namespace": "tralar"}}},
	})

	filtered := testutil.ReadChannel(t, out, timeout)
	assert.Equal(t, []*ebpf.Record{
		{Attrs: ebpf.RecordAttrs{BeylaIP: "148.132.1.1",
			Metadata: map[attr.Name]string{"k8s.src.namespace": "foo"}}},
		{Attrs: ebpf.RecordAttrs{BeylaIP: "148.133.2.1",
			Metadata: map[attr.Name]string{"k8s.src.namespace": "tralar"}}},
	}, filtered)

	filtered = testutil.ReadChannel(t, out, timeout)
	assert.Equal(t, []*ebpf.Record{
		{Attrs: ebpf.RecordAttrs{BeylaIP: "148.132.1.1",
			Metadata: map[attr.Name]string{"k8s.src.namespace": "foo"}}},
		{Attrs: ebpf.RecordAttrs{BeylaIP: "148.133.2.1",
			Metadata: map[attr.Name]string{"k8s.src.namespace": "tralar"}}},
	}, filtered)

	select {
	case batch := <-out:
		assert.Failf(t, "not expecting more output batches", "%#v", batch)
	default:
		// ok!!
	}

}

func TestAttributeFilter_VerificationError(t *testing.T) {
	testCases := []AttributeFamilyConfig{
		// non-existing attribute
		{"super-attribute": MatchDefinition{Match: "foo"}},
		// valid attribute without match definition
		{"beyla.ip": MatchDefinition{}},
		// valid attribute with double match definition
		{"beyla.ip": MatchDefinition{Match: "foo", NotMatch: "foo"}},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%v", tc), func(t *testing.T) {
			input := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(10))
			output := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(10))
			_, err := ByAttribute[*ebpf.Record](tc, ebpf.RecordStringGetters, input, output)(context.Background())
			assert.Error(t, err)
		})
	}
}

func TestAttributeFilter_SpanMetrics(t *testing.T) {
	// if the attributes are not existing, we should just ignore them
	input := msg.NewQueue[[]*request.Span](msg.ChannelBufferLen(10))
	output := msg.NewQueue[[]*request.Span](msg.ChannelBufferLen(10))
	filterFunc, err := ByAttribute[*request.Span](AttributeFamilyConfig{
		"client": MatchDefinition{NotMatch: "filtered"},
		"server": MatchDefinition{NotMatch: "filtered"},
	}, request.SpanPromGetters, input, output)(context.Background())
	require.NoError(t, err)

	out := output.Subscribe()
	go filterFunc(context.Background())

	// will drop filtered events
	input.Send([]*request.Span{
		{Type: request.EventTypeHTTP, PeerName: "someclient", Host: "filtered"},
		{Type: request.EventTypeHTTPClient, PeerName: "filtered", Host: "someserver"},
		{Type: request.EventTypeHTTPClient, PeerName: "aserver", Host: "aclient"},
	})

	// no record will be dropped
	input.Send([]*request.Span{
		{Type: request.EventTypeHTTP, PeerName: "client", Host: "server"},
		{Type: request.EventTypeHTTPClient, PeerName: "server", Host: "client"},
	})

	filtered := testutil.ReadChannel(t, out, timeout)
	assert.Equal(t, []*request.Span{
		{Type: request.EventTypeHTTPClient, PeerName: "aserver", Host: "aclient"},
	}, filtered)

	filtered = testutil.ReadChannel(t, out, timeout)
	assert.Equal(t, []*request.Span{
		{Type: request.EventTypeHTTP, PeerName: "client", Host: "server"},
		{Type: request.EventTypeHTTPClient, PeerName: "server", Host: "client"},
	}, filtered)

	select {
	case batch := <-out:
		assert.Failf(t, "not expecting more output batches", "%#v", batch)
	default:
		// ok!!
	}

}
