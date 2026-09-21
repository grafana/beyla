package traces

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/pipe/msg"

	"github.com/grafana/beyla/v3/pkg/export/extraattributes/names"
	"github.com/grafana/beyla/v3/pkg/internal/testutil"
)

func TestDecorateHostID(t *testing.T) {
	in := msg.NewQueue[[]request.Span]()
	outQueue := msg.NewQueue[[]request.Span]()
	out := outQueue.Subscribe()
	run, err := DecorateHostID("resolved-host", in, outQueue)(t.Context())
	require.NoError(t, err)
	go run(t.Context())

	spans := make([]request.Span, 2)
	spans[1].Service.Metadata = map[attr.Name]string{
		attr.K8sClusterName: "cluster",
		names.GrafanaHostID: "old-host",
	}
	in.Send(spans)
	in.Close()
	got := testutil.ReadChannel(t, out, 5*time.Second)
	require.Len(t, got, 2)
	for _, span := range got {
		assert.Equal(t, "resolved-host", span.Service.Metadata[names.GrafanaHostID])
	}
	assert.Equal(t, "cluster", got[1].Service.Metadata[attr.K8sClusterName])
	assert.Nil(t, spans[0].Service.Metadata)
	assert.Equal(t, "old-host", spans[1].Service.Metadata[names.GrafanaHostID])
	select {
	case _, open := <-out:
		assert.False(t, open, "output closes when input closes")
	case <-time.After(5 * time.Second):
		t.Fatal("output did not close")
	}
}
