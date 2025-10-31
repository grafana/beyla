//go:build integration_k8s

package owners

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

	"github.com/grafana/beyla/v2/internal/test/integration/components/jaeger"
	k8s "github.com/grafana/beyla/v2/internal/test/integration/k8s/common"
)

// For the DaemonSet scenario, we only check that Beyla is able to instrument any
// process in the system. We just check that traces are properly generated without
// entering in too many details
func TestStatefulSetMetadata(t *testing.T) {
	feat := features.New("Beyla is able to decorate the metadata of a statefulset").
		Assess("it sends decorated traces for the statefulset",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				test.Eventually(t, testTimeout, func(t require.TestingT) {
					// Invoking both service instances, but we will expect that only one
					// is instrumented, according to the discovery mechanisms
					resp, err := http.Get("http://localhost:38080/pingpong")
					require.NoError(t, err)
					require.Equal(t, http.StatusOK, resp.StatusCode)

					resp, err = http.Get(jaegerQueryURL + "?service=statefulservice")
					require.NoError(t, err)
					if resp == nil {
						return
					}
					require.Equal(t, http.StatusOK, resp.StatusCode)
					var tq jaeger.TracesQuery
					require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
					traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/pingpong"})
					require.NotEmpty(t, traces)
					trace := traces[0]
					require.NotEmpty(t, trace.Spans)

					// Check that the service.namespace is set from the K8s namespace
					assert.Len(t, trace.Processes, 1)
					for _, proc := range trace.Processes {
						sd := jaeger.DiffAsRegexp([]jaeger.Tag{
							{Key: "service.namespace", Type: "string", Value: "^default$"},
							{Key: "service.instance.id", Type: "string", Value: "^default\\.statefulservice-.+\\.statefulservice"},
						}, proc.Tags)
						require.Empty(t, sd)
					}

					// Check the information of the parent span
					res := trace.FindByOperationName("GET /pingpong", "server")
					require.Len(t, res, 1)
					parent := res[0]
					sd := jaeger.DiffAsRegexp([]jaeger.Tag{
						{Key: "k8s.pod.name", Type: "string", Value: "^statefulservice-.*"},
						{Key: "k8s.container.name", Type: "string", Value: "statefulservice"},
						{Key: "k8s.node.name", Type: "string", Value: ".+-control-plane$"},
						{Key: "k8s.pod.uid", Type: "string", Value: k8s.UUIDRegex},
						{Key: "k8s.pod.start_time", Type: "string", Value: k8s.TimeRegex},
						{Key: "k8s.statefulset.name", Type: "string", Value: "^statefulservice$"},
						{Key: "k8s.namespace.name", Type: "string", Value: "^default$"},
						{Key: "k8s.cluster.name", Type: "string", Value: "^beyla-k8s-test-cluster$"},
						{Key: "service.namespace", Type: "string", Value: "^default$"},
						{Key: "service.instance.id", Type: "string", Value: "^default\\.statefulservice-.+\\.statefulservice"},
					}, trace.Processes[parent.ProcessID].Tags)
					require.Empty(t, sd)

					// check that no other labels are added
					sd = jaeger.DiffAsRegexp([]jaeger.Tag{
						{Key: "k8s.deployment.name", Type: "string"},
						{Key: "k8s.daemonset.name", Type: "string"},
					}, trace.Processes[parent.ProcessID].Tags)
					require.Equal(t, jaeger.DiffResult{
						{ErrType: jaeger.ErrTypeMissing, Expected: jaeger.Tag{Key: "k8s.deployment.name", Type: "string"}},
						{ErrType: jaeger.ErrTypeMissing, Expected: jaeger.Tag{Key: "k8s.daemonset.name", Type: "string"}},
					}, sd)
				}, test.Interval(100*time.Millisecond))
				return ctx
			},
		).Feature()
	cluster.TestEnv().Test(t, feat)
}
