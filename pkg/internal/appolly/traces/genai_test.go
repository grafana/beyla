package traces

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/pipe/msg"

	"github.com/grafana/beyla/v3/pkg/internal/testutil"
)

func TestSelectGenAI(t *testing.T) {
	in := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
	outQ := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
	out := outQ.Subscribe()

	sg, err := SelectGenAI(in, outQ)(t.Context())
	require.NoError(t, err)
	go sg(t.Context())

	in.Send([]request.Span{{
		Type: request.EventTypeHTTPClient, SubType: request.HTTPSubtypeOpenAI,
		Method: "POST", Route: "/v1/chat/completions",
	}, { // TO BE EXCLUDED (not a GenAI subtype)
		Type: request.EventTypeHTTP, SubType: request.HTTPSubtypeNone,
		Method: "GET", Route: "/foo",
	}, {
		Type: request.EventTypeHTTPClient, SubType: request.HTTPSubtypeAnthropic,
		Method: "POST", Route: "/v1/messages",
	}, { // TO BE EXCLUDED (plain HTTP client, no GenAI subtype)
		Type: request.EventTypeHTTPClient, SubType: request.HTTPSubtypeNone,
		Method: "GET", Route: "/bar",
	}})

	genAI := testutil.ReadChannel(t, out, 5*time.Second)
	assert.Equal(t, []request.Span{{
		Type: request.EventTypeHTTPClient, SubType: request.HTTPSubtypeOpenAI,
		Method: "POST", Route: "/v1/chat/completions",
	}, {
		Type: request.EventTypeHTTPClient, SubType: request.HTTPSubtypeAnthropic,
		Method: "POST", Route: "/v1/messages",
	}}, genAI)
}

// TestSelectGenAI_NonExportable verifies spans whose service blocks trace export are
// dropped even when they carry a GenAI subtype.
func TestSelectGenAI_NonExportable(t *testing.T) {
	blocked := request.Span{
		Type: request.EventTypeHTTPClient, SubType: request.HTTPSubtypeOpenAI,
		Method: "POST", Route: "/v1/chat/completions",
	}
	blocked.Service.ExportModes = services.NewExportModes() // blocks all signals

	out := filterGenAI([]request.Span{blocked})
	assert.Empty(t, out)
}
