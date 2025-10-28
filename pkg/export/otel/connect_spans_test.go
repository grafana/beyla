package otel

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"

	"github.com/grafana/beyla/v2/pkg/internal/testutil"
	"github.com/grafana/beyla/v2/pkg/test/collector"
)

func TestConnection_Spans(t *testing.T) {
	otlp, err := collector.Start(t.Context())
	require.NoError(t, err)
	traces := otlp.TraceRecords()

	input := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
	cse, err := ConnectionSpansExport(
		&global.ContextInfo{HostID: "the-host"},
		&otelcfg.TracesConfig{
			TracesEndpoint: otlp.ServerEndpoint + "/v1/traces",
			TracesProtocol: otelcfg.ProtocolHTTPJSON,
			Instrumentations: []string{
				instrumentations.InstrumentationALL,
			},
			SamplerConfig: services.SamplerConfig{Name: "always_on"},
			MaxQueueSize:  4096,
			BatchTimeout:  10 * time.Millisecond,
		},
		request.UnresolvedNames{},
		input,
	)(t.Context())
	require.NoError(t, err)
	go cse(t.Context())
	testutil.ChannelEmpty(t, traces, 10*time.Millisecond)

	input.Send([]request.Span{{
		Type:     request.EventTypeHTTP,
		Method:   "GET",
		Route:    "/foo",
		Start:    123,
		End:      456,
		Service:  svc.Attrs{UID: svc.UID{Name: "foo"}},
		Host:     "1.2.3.4",
		HostName: "foo.com",
		Peer:     "4.2.3.1",
		PeerName: "4.2.3.1",
		SpanID:   [8]byte{2},
	}, {
		Type:     request.EventTypeHTTPClient,
		Method:   "POST",
		Route:    "/bar",
		Start:    321,
		End:      654,
		Service:  svc.Attrs{UID: svc.UID{Name: "foo"}},
		Host:     "1.2.3.4",
		HostName: "foo.com",
		Peer:     "3.3.2.6",
		PeerName: "3.3.2.6",
		SpanID:   [8]byte{1},
	}})

	trace := testutil.ReadChannel(t, traces, 5*time.Second)
	assert.Equal(t, "GET /foo", trace.Name)
	assert.Equal(t, map[string]string{
		"client":         "4.2.3.1",
		"client.address": "4.2.3.1",
		"server":         "foo.com",
		"server.address": "foo.com",
		"beyla.topology": "external",
		"parent_span_id": "",
		"span_id":        "0200000000000000",
	}, trace.Attributes)

	trace = testutil.ReadChannel(t, traces, 5*time.Second)
	assert.Equal(t, "POST /bar", trace.Name)
	assert.Equal(t, map[string]string{
		"server":         "foo.com",
		"server.address": "foo.com",
		"client":         "3.3.2.6",
		"client.address": "3.3.2.6",
		"beyla.topology": "external",
		"parent_span_id": "",
		"span_id":        "0100000000000000",
	}, trace.Attributes)
}
