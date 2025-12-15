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
func TestPythonBasicTracing(t *testing.T) {
	feat := features.New("Beyla is able to instrument an arbitrary process").
		Assess("it sends traces for that service",
			func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
				var trace jaeger.Trace
				var podID string
				test.Eventually(t, testTimeout, func(t require.TestingT) {
					resp, err := http.Get("http://localhost:7773/greeting")
					require.NoError(t, err)
					require.Equal(t, http.StatusOK, resp.StatusCode)

					resp, err = http.Get(jaegerQueryURL + "?service=mypythonapp&operation=GET%20%2Fgreeting")
					require.NoError(t, err)
					if resp == nil {
						return
					}
					require.Equal(t, http.StatusOK, resp.StatusCode)
					var tq jaeger.TracesQuery
					require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
					traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/greeting"})
					require.NotEmpty(t, traces)
					trace = traces[0]
					require.NotEmpty(t, trace.Spans)

					// Check the information of the parent span
					res := trace.FindByOperationName("GET /greeting", "server")
					require.Len(t, res, 1)
					parent := res[0]
					sd := jaeger.DiffAsRegexp([]jaeger.Tag{
						{Key: "service.namespace", Type: "string", Value: "^integration-test$"},
						{Key: "telemetry.sdk.language", Type: "string", Value: "^python$"},
						{Key: "service.instance.id", Type: "string", Value: "^default\\.pytestserver-.+\\.pytestserver$"},
					}, trace.Processes[parent.ProcessID].Tags)
					require.Empty(t, sd, sd.String())

					// check the process information
					sd = jaeger.DiffAsRegexp([]jaeger.Tag{
						{Key: "k8s.pod.name", Type: "string", Value: "^pytestserver-.*"},
						{Key: "k8s.container.name", Type: "string", Value: "pytestserver"},
						{Key: "k8s.node.name", Type: "string", Value: ".+-control-plane$"},
						{Key: "k8s.pod.uid", Type: "string", Value: k8s.UUIDRegex},
						{Key: "k8s.pod.start_time", Type: "string", Value: k8s.TimeRegex},
						{Key: "k8s.namespace.name", Type: "string", Value: "^default$"},
						{Key: "k8s.cluster.name", Type: "string", Value: "^beyla-k8s-test-cluster$"},
						{Key: "service.instance.id", Type: "string", Value: "^default\\.pytestserver-.+\\.pytestserver"},
					}, trace.Processes[parent.ProcessID].Tags)
					require.Empty(t, sd, sd.String())

					// Extract the pod id, so we can later check on restart of the pod that we have a different id
					tag, found := jaeger.FindIn(trace.Processes[parent.ProcessID].Tags, "k8s.pod.uid")
					assert.True(t, found)

					podID = tag.Value.(string)
					assert.NotEqual(t, "", podID)
				}, test.Interval(100*time.Millisecond))

				// Let's take down our services, keeping Beyla alive and then redeploy them
				err := kube.DeleteExistingManifestFile(cfg, testpath.Manifests+"/05-uninstrumented-service-python.yml")
				assert.NoError(t, err, "we should see no error when deleting the uninstrumented service manifest file")

				err = kube.DeployManifestFile(cfg, testpath.Manifests+"/05-uninstrumented-service-python.yml")
				assert.NoError(t, err, "we should see no error when re-deploying the uninstrumented service manifest file")

				// We now use /smoke instead of /greeting to ensure we see those APIs after a restart
				test.Eventually(t, testTimeout, func(t require.TestingT) {
					resp, err := http.Get("http://localhost:7773/smoke")
					require.NoError(t, err)
					require.Equal(t, http.StatusOK, resp.StatusCode)

					resp, err = http.Get(jaegerQueryURL + "?service=mypythonapp&operation=GET%20%2Fsmoke")
					require.NoError(t, err)
					if resp == nil {
						return
					}
					require.Equal(t, http.StatusOK, resp.StatusCode)
					var tq jaeger.TracesQuery
					require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
					traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/smoke"})
					require.NotEmpty(t, traces)
					trace = traces[0]
					require.NotEmpty(t, trace.Spans)

					// Check the information of the parent span
					res := trace.FindByOperationName("GET /smoke", "server")
					require.Len(t, res, 1)
					parent := res[0]
					sd := jaeger.DiffAsRegexp([]jaeger.Tag{
						{Key: "service.namespace", Type: "string", Value: "^integration-test$"},
						{Key: "telemetry.sdk.language", Type: "string", Value: "^python$"},
						{Key: "service.instance.id", Type: "string", Value: "^default\\.pytestserver-.+\\.pytestserver$"},
					}, trace.Processes[parent.ProcessID].Tags)
					require.Empty(t, sd, sd.String())

					// check the process information
					sd = jaeger.DiffAsRegexp([]jaeger.Tag{
						{Key: "k8s.pod.name", Type: "string", Value: "^pytestserver-.*"},
						{Key: "k8s.container.name", Type: "string", Value: "pytestserver"},
						{Key: "k8s.node.name", Type: "string", Value: ".+-control-plane$"},
						{Key: "k8s.pod.uid", Type: "string", Value: k8s.UUIDRegex},
						{Key: "k8s.pod.start_time", Type: "string", Value: k8s.TimeRegex},
						{Key: "k8s.namespace.name", Type: "string", Value: "^default$"},
						{Key: "k8s.cluster.name", Type: "string", Value: "^beyla-k8s-test-cluster$"},
						{Key: "service.instance.id", Type: "string", Value: "^default\\.pytestserver-.+\\.pytestserver"},
					}, trace.Processes[parent.ProcessID].Tags)
					require.Empty(t, sd, sd.String())

					// ensure the pod really restarted
					tag, found := jaeger.FindIn(trace.Processes[parent.ProcessID].Tags, "k8s.pod.uid")
					assert.True(t, found)

					assert.NotEqual(t, podID, tag.Value.(string))
				}, test.Interval(100*time.Millisecond))

				return ctx
			},
		).Feature()
	cluster.TestEnv().Test(t, feat)
}
