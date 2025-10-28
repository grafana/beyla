package traces

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/pipe/msg"

	"github.com/grafana/beyla/v2/pkg/internal/testutil"
)

func TestSelectExternal(t *testing.T) {
	in := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
	outQ := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
	out := outQ.Subscribe()
	var isClusterIP = func(ip string) bool {
		return ip == "10.0.0.1"
	}
	se, err := SelectExternal(isClusterIP, in, outQ)(t.Context())
	require.NoError(t, err)
	go se(t.Context())
	in.Send([]request.Span{{
		Type: request.EventTypeHTTP, Method: "GET", Route: "/foo",
		Peer: "1.2.3.4", Host: "10.0.0.1",
		TraceID: [16]byte{1},
	}, {
		Type: request.EventTypeHTTPClient, Method: "POST", Route: "/bar",
		Peer: "10.0.0.1", Host: "1.2.3.4",
		TraceID: [16]byte{2},
	}, { // TO BE EXCLUDED (client is cluster-internal)
		Type: request.EventTypeHTTP, Method: "GET", Route: "/baz",
		Peer: "10.0.0.1", Host: "1.2.3.4",
		TraceID: [16]byte{3},
	}, { // TO BE EXCLUDED (server is cluster-internal)
		Type: request.EventTypeHTTPClient, Method: "POST", Route: "/bae",
		Peer: "1.2.3.4", Host: "10.0.0.1",
		TraceID: [16]byte{4},
	}, { // TO BE EXCLUDED (Trace ID is not valid)
		Type: request.EventTypeHTTP, Method: "GET", Route: "/foo",
		Peer: "1.2.3.4", Host: "10.0.0.1",
	}})

	external := testutil.ReadChannel(t, out, 5*time.Second)
	assert.Equal(t, []request.Span{{
		Type: request.EventTypeHTTP, Method: "GET", Route: "/foo",
		Peer: "1.2.3.4", Host: "10.0.0.1",
		TraceID: [16]byte{1},
	}, {
		Type: request.EventTypeHTTPClient, Method: "POST", Route: "/bar",
		Peer: "10.0.0.1", Host: "1.2.3.4",
		TraceID: [16]byte{2},
	}}, external)
}
