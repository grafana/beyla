package filter

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/netolly/ebpf"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/msg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	attr "github.com/grafana/beyla/v2/pkg/export/attributes/names"
	"github.com/grafana/beyla/v2/pkg/internal/request"
	"github.com/grafana/beyla/v2/pkg/internal/testutil"
)

const timeout = 5 * time.Second

func TestAttributeFilter(t *testing.T) {
	input := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(10))
	output := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(10))

	filterFunc, err := ByAttribute[*ebpf.Record](AttributeFamilyConfig{
		"beyla.ip":          MatchDefinition{Match: "148.*"},
		"k8s.src.namespace": MatchDefinition{NotMatch: "debug"},
		"k8s.app.version":   MatchDefinition{Match: "*"},
	}, map[string][]attr.Name{
		"k8s_app_meta": {"k8s.app.version"},
	}, ebpf.RecordStringGetters, input, output)(context.Background())
	require.NoError(t, err)

	out := output.Subscribe()
	go filterFunc(context.Background())

	// records not matching both the ip and src namespace will be dropped
	input.Send([]*ebpf.Record{
		{
			Attrs: ebpf.RecordAttrs{BeylaIP: "148.132.1.1",
				Metadata: map[attr.Name]string{
					"k8s.src.namespace": "debug",
					"k8s.app.version":   "v0.0.1",
				}},
		},
		{
			Attrs: ebpf.RecordAttrs{BeylaIP: "128.132.1.1",
				Metadata: map[attr.Name]string{
					"k8s.src.namespace": "foo",
					"k8s.app.version":   "v0.0.1",
				}},
		},
		{
			Attrs: ebpf.RecordAttrs{BeylaIP: "148.132.1.1",
				Metadata: map[attr.Name]string{
					"k8s.src.namespace": "foo",
					"k8s.app.version":   "v0.0.1",
				}},
		},
		{
			Attrs: ebpf.RecordAttrs{BeylaIP: "148.133.2.1",
				Metadata: map[attr.Name]string{
					"k8s.src.namespace": "tralar",
					"k8s.app.version":   "v0.0.1",
				}},
		},
		{
			Attrs: ebpf.RecordAttrs{BeylaIP: "141.132.1.1",
				Metadata: map[attr.Name]string{
					"k8s.src.namespace": "tralari",
					"k8s.app.version":   "v0.0.1",
				}},
		},
	})

	// the whole batch will be dropped (won't go to the out channel)
	input.Send([]*ebpf.Record{
		{
			Attrs: ebpf.RecordAttrs{BeylaIP: "128.132.1.1",
				Metadata: map[attr.Name]string{
					"k8s.src.namespace": "foo",
					"k8s.app.version":   "v0.0.1",
				}},
		},
		{
			Attrs: ebpf.RecordAttrs{BeylaIP: "141.132.1.1",
				Metadata: map[attr.Name]string{
					"k8s.src.namespace": "tralari",
					"k8s.app.version":   "v0.0.1",
				}},
		},
	})

	// no record will be dropped
	input.Send([]*ebpf.Record{
		{
			Attrs: ebpf.RecordAttrs{BeylaIP: "148.132.1.1",
				Metadata: map[attr.Name]string{
					"k8s.src.namespace": "foo",
					"k8s.app.version":   "v0.0.1",
				}},
		},
		{
			Attrs: ebpf.RecordAttrs{BeylaIP: "148.133.2.1",
				Metadata: map[attr.Name]string{
					"k8s.src.namespace": "tralar",
					"k8s.app.version":   "v0.0.1",
				}},
		},
	})

	filtered := testutil.ReadChannel(t, out, timeout)
	assert.Equal(t, []*ebpf.Record{
		{
			Attrs: ebpf.RecordAttrs{BeylaIP: "148.132.1.1",
				Metadata: map[attr.Name]string{
					"k8s.src.namespace": "foo",
					"k8s.app.version":   "v0.0.1",
				}},
		},
		{
			Attrs: ebpf.RecordAttrs{BeylaIP: "148.133.2.1",
				Metadata: map[attr.Name]string{
					"k8s.src.namespace": "tralar",
					"k8s.app.version":   "v0.0.1",
				}},
		},
	}, filtered)

	filtered = testutil.ReadChannel(t, out, timeout)
	assert.Equal(t, []*ebpf.Record{
		{
			Attrs: ebpf.RecordAttrs{BeylaIP: "148.132.1.1",
				Metadata: map[attr.Name]string{
					"k8s.src.namespace": "foo",
					"k8s.app.version":   "v0.0.1",
				}},
		},
		{
			Attrs: ebpf.RecordAttrs{BeylaIP: "148.133.2.1",
				Metadata: map[attr.Name]string{
					"k8s.src.namespace": "tralar",
					"k8s.app.version":   "v0.0.1",
				}},
		},
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
			_, err := ByAttribute[*ebpf.Record](tc, map[string][]attr.Name{}, ebpf.RecordStringGetters, input, output)(context.Background())
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
	}, map[string][]attr.Name{}, request.SpanPromGetters, input, output)(context.Background())
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
