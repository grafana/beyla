package traces

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/app/request"
	"go.opentelemetry.io/obi/pkg/components/testutil"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func TestSelectExternal(t *testing.T) {
	in := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
	outQ := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
	out := outQ.Subscribe()
	se, err := SelectExternal(in, outQ)(t.Context())
	require.NoError(t, err)
	go se(t.Context())
	in.Send([]request.Span{{
		Type: request.EventTypeHTTP, Method: "GET", Route: "/foo",
		PeerName: "1.2.3.4", HostName: "foo.com",
		TraceID: [16]byte{1},
	}, {
		Type: request.EventTypeHTTPClient, Method: "POST", Route: "/bar",
		PeerName: "foo.com", HostName: "1.2.3.4",
		TraceID: [16]byte{2},
	}, { // TO BE EXCLUDED (client is known in an HTTP service)
		Type: request.EventTypeHTTP, Method: "GET", Route: "/baz",
		PeerName: "foo.com", HostName: "1.2.3.4",
		TraceID: [16]byte{3},
	}, { // TO BE EXCLUDED (server is known in an HTTP client)
		Type: request.EventTypeHTTPClient, Method: "POST", Route: "/bae",
		PeerName: "1.2.3.4", HostName: "foo.com",
		TraceID: [16]byte{4},
	}, { // TO BE EXCLUDED (Trace ID is not valid)
		Type: request.EventTypeHTTP, Method: "GET", Route: "/foo",
		PeerName: "1.2.3.4", HostName: "foo.com",
	}})

	external := testutil.ReadChannel(t, out, 5*time.Second)
	assert.Equal(t, []request.Span{{
		Type: request.EventTypeHTTP, Method: "GET", Route: "/foo",
		PeerName: "1.2.3.4", HostName: "foo.com",
		TraceID: [16]byte{1},
	}, {
		Type: request.EventTypeHTTPClient, Method: "POST", Route: "/bar",
		PeerName: "foo.com", HostName: "1.2.3.4",
		TraceID: [16]byte{2},
	}}, external)
}
