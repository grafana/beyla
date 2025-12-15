//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"path"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/v2/internal/test/integration/components/docker"
	"github.com/grafana/beyla/v2/internal/test/integration/components/jaeger"
	"github.com/grafana/beyla/v2/internal/test/integration/components/prom"
)

func testREDMetricsTracesForOldGRPCLibrary(t *testing.T, svcNs string) {
	url := "http://localhost:8080"

	waitForTestComponentsSub(t, url, "/factorial/1")

	path := "/factorial/2"

	for i := 0; i < 4; i++ {
		doHTTPGetIgnoreStatus(t, url+path)
	}

	// Eventually, Prometheus would make this query visible
	pq := prom.Client{HostPort: prometheusHostPort}
	var results []prom.Result
	test.Eventually(t, time.Duration(1)*time.Minute, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_server_request_duration_seconds_count{` +
			`http_request_method="GET",` +
			`service_namespace="` + svcNs + `",` +
			`service_name="backend",` +
			`url_path="` + path + `"}`)
		require.NoError(t, err)
		// check duration_count has 3 calls and all the arguments
		enoughPromResults(t, results)
		val := totalPromCount(t, results)
		assert.LessOrEqual(t, 1, val)
		if len(results) > 0 {
			res := results[0]
			addr := res.Metric["client_address"]
			assert.NotNil(t, addr)
		}
	})

	// Eventually, Prometheus would make this query visible
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`rpc_server_duration_seconds_count{` +
			`service_namespace="integration-test",` +
			`service_name="worker",` +
			`rpc_method="/fib.Multiplier/Loop"}`)
		require.NoError(t, err)
		// check duration_count has at least 3 calls and all the arguments
		enoughPromResults(t, results)
		val := totalPromCount(t, results)
		assert.LessOrEqual(t, 3, val)
		if len(results) > 0 {
			res := results[0]
			addr := res.Metric["client_address"]
			assert.NotNil(t, addr)
		}
	})

	var trace jaeger.Trace
	test.Eventually(t, time.Duration(1)*time.Minute, func(t require.TestingT) {
		resp, err := http.Get(jaegerQueryURL + "?service=backend&operation=GET%20%2Ffactorial%2F")
		require.NoError(t, err)
		if resp == nil {
			return
		}
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: path})
		require.GreaterOrEqual(t, len(traces), 1)
		trace = traces[0]
	}, test.Interval(100*time.Millisecond))

	// Check the information of the python parent span
	res := trace.FindByOperationName("GET /factorial/", "server")
	require.Len(t, res, 1)
	parent := res[0]
	require.NotEmpty(t, parent.TraceID)
	require.NotEmpty(t, parent.SpanID)
	// check duration is at least 2us
	assert.Less(t, (2 * time.Microsecond).Microseconds(), parent.Duration)
	// check span attributes
	sd := parent.Diff(
		jaeger.Tag{Key: "http.request.method", Type: "string", Value: "GET"},
		jaeger.Tag{Key: "url.path", Type: "string", Value: path},
		jaeger.Tag{Key: "server.port", Type: "int64", Value: float64(8080)},
		jaeger.Tag{Key: "http.route", Type: "string", Value: "/factorial/"},
		jaeger.Tag{Key: "span.kind", Type: "string", Value: "server"},
	)
	assert.Empty(t, sd, sd.String())
}

func testGRPCGoClientFailsToConnect(t *testing.T) {
	// Eventually, Prometheus would make this query visible
	pq := prom.Client{HostPort: prometheusHostPort}
	var results []prom.Result

	// Eventually, Prometheus would make this query visible
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`rpc_client_duration_seconds_count{` +
			`service_namespace="integration-test",` +
			`service_name="grpcpinger",` +
			`rpc_grpc_status_code="2",` +
			`rpc_method="/routeguide.RouteGuide/GetFeature"}`)
		require.NoError(t, err)
		enoughPromResults(t, results)
		val := totalPromCount(t, results)
		assert.LessOrEqual(t, 1, val)
	})
}

func TestSuiteOtherGRPCGo(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-other-grpc.yml", path.Join(pathOutput, "test-suite-other-grpc.log"))
	// we are going to setup discovery directly in the configuration file
	compose.Env = append(compose.Env, `BEYLA_EXECUTABLE_NAME=`, `BEYLA_OPEN_PORT=`)
	lockdown := KernelLockdownMode()

	if !lockdown {
		compose.Env = append(compose.Env, `SECURITY_CONFIG_SUFFIX=_none`)
	}

	require.NoError(t, err)
	require.NoError(t, compose.Up())

	t.Run("Go RED metrics and traces: old grpc service", func(t *testing.T) {
		testREDMetricsTracesForOldGRPCLibrary(t, "integration-test")
	})

	t.Run("Go RED metrics and traces: grpc client fails to connect", func(t *testing.T) {
		testGRPCGoClientFailsToConnect(t)
	})

	require.NoError(t, compose.Close())
}
