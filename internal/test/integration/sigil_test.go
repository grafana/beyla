//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ti "go.opentelemetry.io/obi/pkg/test/integration"

	"github.com/grafana/beyla/v3/internal/test/tools/docker"
	"github.com/grafana/beyla/v3/internal/test/tools/jaeger"
)

const jaegerQueryURL = "http://localhost:16686/api/traces"

func TestSigilSpans(t *testing.T) {
	compose, err := docker.ComposeSuite("compose/docker-compose-sigil.yml", path.Join(pathOutput, "test-suite-sigil-traces.log"))
	require.NoError(t, err)
	require.NoError(t, compose.Up())

	t.Run("sigil traces export", func(t *testing.T) {
		testSigilTraces(t)
	})

	require.NoError(t, compose.Close())
}

func testSigilTraces(t *testing.T) {
	var trace jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		ti.DoHTTPGet(t, "http://localhost:8080/chat", 200)
		resp, err := http.Get(jaegerQueryURL + "?service=testserver&operation=chat%20%gpt-4o-mini")
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "openai.api.type", Type: "string", Value: "chat_completions"})
		require.GreaterOrEqual(ct, len(traces), 1)
		trace = traces[0]

		res := trace.FindByOperationName("chat gpt-4o-mini", "client")
		require.Len(ct, res, 1)
		span := res[0]

		sigilId, ok := jaeger.FindIn(span.Tags, "sigil.generation.id")

		require.Truef(ct, ok, "sigil.generation.id not found in tags: %v", span.Tags)
		assert.NotEmpty(ct, sigilId.Value)

		conversationId, ok := jaeger.FindIn(span.Tags, "gen_ai.conversation.id")

		require.Truef(ct, ok, "gen_ai.conversation.id not found in tags: %v", span.Tags)
		assert.NotEmpty(ct, conversationId.Value)
	}, testTimeout, 1*time.Second)
}
