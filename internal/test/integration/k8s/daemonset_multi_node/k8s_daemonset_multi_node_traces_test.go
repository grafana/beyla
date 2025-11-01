//go:build integration_k8s

package otel

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

	"github.com/grafana/beyla/v2/internal/test/integration/components/jaeger"
)

// For the this scenario we run two worker nodes, with the following structure:
//   - worker 1:
//     testserver [go app] port: 8080
//     testserver [go jsonrpc app] port: 8088
//   - worker 2:
//     pythonserver [python app] port: 7773
//     ruby on rails [ruby app] port: 3040
//
// The call flow is as follows:
//
//	testserver [/gotracemetoo] -> go jsonrpc [/jsonrpc] -> Python server [/tracemetoo] -> Ruby server [/users]
//
// They should all have the same traceID. Across nodes the TCP context propagation (OTEL_EBPF_BPF_CONTEXT_PROPAGATION)
// connects the dots, while on the same node, the networking is optimized and we rely on black-box context propagation to
// connect the services.
func TestMultiNodeTracing(t *testing.T) {
	feat := features.New("OBI is able to generate distributed traces go->go jsonrpc->python->ruby").
		Assess("it sends connected traces for all services",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				var trace jaeger.Trace
				var traceID string
				test.Eventually(t, testTimeout, func(t require.TestingT) {
					resp, err := http.Get("http://localhost:38080/gotracemetoo")
					require.NoError(t, err)
					require.Equal(t, http.StatusOK, resp.StatusCode)

					resp, err = http.Get(jaegerQueryURL + "?service=testserver&operation=GET%20%2Fgotracemetoo")
					require.NoError(t, err)
					if resp == nil {
						return
					}
					require.Equal(t, http.StatusOK, resp.StatusCode)
					var tq jaeger.TracesQuery
					require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
					traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/gotracemetoo"})
					require.NotEmpty(t, traces)
					trace = traces[0]
					require.NotEmpty(t, trace.Spans)

					// Check the information of the parent span (Go app)
					res := trace.FindByOperationName("GET /gotracemetoo", "server")
					require.Len(t, res, 1)
					parent := res[0]
					require.NotEmpty(t, parent.TraceID)
					traceID = parent.TraceID
					sd := jaeger.DiffAsRegexp([]jaeger.Tag{
						{Key: "service.namespace", Type: "string", Value: "^integration-test$"},
						{Key: "telemetry.sdk.language", Type: "string", Value: "^go$"},
						{Key: "service.instance.id", Type: "string", Value: "^default\\.testserver-.+\\.testserver$"},
					}, trace.Processes[parent.ProcessID].Tags)
					require.Empty(t, sd, sd.String())

					// Check the information of the Go jsonrpc span
					res = trace.FindByOperationName("Arith.T /jsonrpc", "server")
					require.Len(t, res, 1)
					parent = res[0]
					require.NotEmpty(t, parent.TraceID)
					require.Equal(t, traceID, parent.TraceID)

					// Check the information of the Python span
					res = trace.FindByOperationName("GET /tracemetoo", "server")
					require.Len(t, res, 1)
					parent = res[0]
					require.NotEmpty(t, parent.TraceID)
					require.Equal(t, traceID, parent.TraceID)

					// Check the information of the Ruby span
					res = trace.FindByOperationName("GET /users", "server")
					require.Len(t, res, 1)
					parent = res[0]
					require.NotEmpty(t, parent.TraceID)
					require.Equal(t, traceID, parent.TraceID)
				}, test.Interval(100*time.Millisecond))

				return ctx
			},
		).Feature()
	cluster.TestEnv().Test(t, feat)
}
