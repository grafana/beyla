//go:build integration_k8s

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

	"github.com/grafana/beyla/v2/internal/test/integration/components/jaeger"
	"github.com/grafana/beyla/v2/internal/test/integration/components/kube"
	k8s "github.com/grafana/beyla/v2/internal/test/integration/k8s/common"
	"github.com/grafana/beyla/v2/internal/test/integration/k8s/common/testpath"
)

// For the DaemonSet scenario, we only check that Beyla is able to instrument any
// process in the system. We just check that traces are properly generated without
// entering in too many details
func TestBasicTracing(t *testing.T) {
	feat := features.New("Beyla is able to instrument an arbitrary process").
		Assess("it sends traces for that service",
			func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
				var podID string
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
							{Key: "service.instance.id", Type: "string", Value: "^default\\.otherinstance-.+\\.otherinstance"},
						}, proc.Tags)
						require.Empty(t, sd)
					}

					// Check the information of the parent span
					res := trace.FindByOperationName("GET /pingpong", "server")
					require.Len(t, res, 1)
					parent := res[0]
					sd := jaeger.DiffAsRegexp([]jaeger.Tag{
						{Key: "k8s.pod.name", Type: "string", Value: "^otherinstance-.*"},
						{Key: "k8s.container.name", Type: "string", Value: "otherinstance"},
						{Key: "k8s.node.name", Type: "string", Value: ".+-control-plane$"},
						{Key: "k8s.pod.uid", Type: "string", Value: k8s.UUIDRegex},
						{Key: "k8s.pod.start_time", Type: "string", Value: k8s.TimeRegex},
						{Key: "k8s.owner.name", Type: "string", Value: "^otherinstance$"},
						{Key: "k8s.deployment.name", Type: "string", Value: "^otherinstance$"},
						{Key: "k8s.namespace.name", Type: "string", Value: "^default$"},
						{Key: "k8s.cluster.name", Type: "string", Value: "^beyla-k8s-test-cluster$"},
					}, trace.Processes[parent.ProcessID].Tags)
					require.Empty(t, sd)

					// Extract the pod id, so we can later check on restart of the pod that we have a different id
					tag, found := jaeger.FindIn(trace.Processes[parent.ProcessID].Tags, "k8s.pod.uid")
					assert.True(t, found)

					podID = tag.Value.(string)
					assert.NotEqual(t, "", podID)
				}, test.Interval(100*time.Millisecond))

				// Check that the "testserver" service is never instrumented
				resp, err := http.Get(jaegerQueryURL + "?service=testserver")
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, resp.StatusCode)
				var tq jaeger.TracesQuery
				require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
				assert.Empty(t, tq.Data)

				// Let's take down our services, keeping Beyla alive and then redeploy them
				err = kube.DeleteExistingManifestFile(cfg, testpath.Manifests+"/05-uninstrumented-service.yml")
				assert.NoError(t, err, "we should see no error when deleting the uninstrumented service manifest file")

				err = kube.DeployManifestFile(cfg, testpath.Manifests+"/05-uninstrumented-service.yml")
				assert.NoError(t, err, "we should see no error when re-deploying the uninstrumented service manifest file")

				// We now use a different API, this ensures that after undeploying and redeploying the application we
				// can still monitor its data
				test.Eventually(t, testTimeout, func(t require.TestingT) {
					// Invoking both service instances, but we will expect that only one
					// is instrumented, according to the discovery mechanisms
					resp, err := http.Get("http://localhost:38080/pingpongtoo")
					require.NoError(t, err)
					require.Equal(t, http.StatusOK, resp.StatusCode)

					resp, err = http.Get("http://localhost:38081/pingpongtoo")
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
					traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/pingpongtoo"})
					require.NotEmpty(t, traces)
					// get the last trace, to avoid that the old instance captured any request
					// before being restarted
					trace := traces[len(traces)-1]
					require.NotEmpty(t, trace.Spans)

					// Check that the service.namespace is set from the K8s namespace
					assert.Len(t, trace.Processes, 1)
					for _, proc := range trace.Processes {
						sd := jaeger.DiffAsRegexp([]jaeger.Tag{
							{Key: "service.namespace", Type: "string", Value: "^default$"},
							{Key: "service.instance.id", Type: "string", Value: "^default\\.otherinstance-.+\\.otherinstance"},
						}, proc.Tags)
						require.Empty(t, sd)
					}

					// Check the information of the parent span
					res := trace.FindByOperationName("GET /pingpongtoo", "server")
					require.Len(t, res, 1)
					parent := res[0]
					sd := jaeger.DiffAsRegexp([]jaeger.Tag{
						{Key: "k8s.pod.name", Type: "string", Value: "^otherinstance-.*"},
						{Key: "k8s.container.name", Type: "string", Value: "otherinstance"},
						{Key: "k8s.node.name", Type: "string", Value: ".+-control-plane$"},
						{Key: "k8s.pod.uid", Type: "string", Value: k8s.UUIDRegex},
						{Key: "k8s.pod.start_time", Type: "string", Value: k8s.TimeRegex},
						{Key: "k8s.deployment.name", Type: "string", Value: "^otherinstance"},
						{Key: "k8s.namespace.name", Type: "string", Value: "^default$"},
						{Key: "k8s.cluster.name", Type: "string", Value: "^beyla-k8s-test-cluster$"},
					}, trace.Processes[parent.ProcessID].Tags)
					require.Empty(t, sd)

					// ensure the pod really restarted, comparing the current uid with the previous pod uid
					tag, found := jaeger.FindIn(trace.Processes[parent.ProcessID].Tags, "k8s.pod.uid")
					assert.True(t, found)

					assert.NotEqual(t, podID, tag.Value.(string))
				}, test.Interval(100*time.Millisecond))

				return ctx
			},
		).Feature()
	cluster.TestEnv().Test(t, feat)
}
