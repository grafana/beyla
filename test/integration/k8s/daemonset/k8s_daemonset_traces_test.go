//go:build integration

package otel

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

	"github.com/grafana/beyla/test/integration/components/jaeger"
	k8s "github.com/grafana/beyla/test/integration/k8s/common"
)

// For the DaemonSet scenario, we only check that Beyla is able to instrument any
// process in the system. We just check that traces are properly generated without
// entering in too many details
func TestBasicTracing(t *testing.T) {
	feat := features.New("Beyla is able to instrument an arbitrary process").
		Assess("it sends traces for that service",
			func(ctx context.Context, t *testing.T, config *envconf.Config) context.Context {
				test.Eventually(t, testTimeout, func(t require.TestingT) {
					// Invoking both service instances, but we will expect that only one
					// is instrumented, according to the discovery mechanisms
					resp, err := http.Get("http://localhost:38080/pingpong")
					require.NoError(t, err)
					require.Equal(t, http.StatusOK, resp.StatusCode)

					resp, err = http.Get("http://localhost:38081/pingpong")
					require.NoError(t, err)
					require.Equal(t, http.StatusOK, resp.StatusCode)

					resp, err = http.Get(jaegerQueryURL + "?service=otherinstance")
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
						}, proc.Tags)
						require.Empty(t, sd)
					}

					// Check the information of the parent span
					res := trace.FindByOperationName("GET /pingpong")
					require.Len(t, res, 1)
					parent := res[0]
					sd := jaeger.DiffAsRegexp([]jaeger.Tag{
						{Key: "k8s.pod.name", Type: "string", Value: "^otherinstance-.*"},
						{Key: "k8s.node.name", Type: "string", Value: ".+-control-plane$"},
						{Key: "k8s.pod.uid", Type: "string", Value: k8s.UUIDRegex},
						{Key: "k8s.pod.start_time", Type: "string", Value: k8s.TimeRegex},
						{Key: "k8s.deployment.name", Type: "string", Value: "^otherinstance"},
						{Key: "k8s.namespace.name", Type: "string", Value: "^default$"},
					}, parent.Tags)
					require.Empty(t, sd)

				}, test.Interval(100*time.Millisecond))

				// Check that the "testserver" service is never instrumented
				resp, err := http.Get(jaegerQueryURL + "?service=testserver")
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, resp.StatusCode)
				var tq jaeger.TracesQuery
				require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
				assert.Empty(t, tq.Data)
				return ctx
			},
		).Feature()
	cluster.TestEnv().Test(t, feat)
}
