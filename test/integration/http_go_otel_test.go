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

	"github.com/grafana/beyla/test/integration/components/docker"
	"github.com/grafana/beyla/test/integration/components/jaeger"
	"github.com/grafana/beyla/test/integration/components/prom"
)

func testForHTTPGoOTelLibrary(t *testing.T, route, svcNs string) {
	for i := 0; i < 4; i++ {
		doHTTPGet(t, "http://localhost:8080"+route, 200)
	}

	// Eventually, Prometheus would make this query visible
	pq := prom.Client{HostPort: prometheusHostPort}
	var results []prom.Result
	test.Eventually(t, time.Duration(1)*time.Minute, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_server_request_duration_seconds_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="200",` +
			`service_namespace="` + svcNs + `",` +
			`service_name="rolldice",` +
			`http_route="` + route + `",` +
			`url_path="` + route + `"}`)
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

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_server_request_body_size_bytes_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="200",` +
			`service_namespace="` + svcNs + `",` +
			`service_name="rolldice",` +
			`http_route="` + route + `",` +
			`url_path="` + route + `"}`)
		require.NoError(t, err)
		// check duration_count has 3 calls and all the arguments
		enoughPromResults(t, results)
		val := totalPromCount(t, results)
		assert.LessOrEqual(t, 3, val)
		if len(results) > 0 {
			res := results[0]
			addr := res.Metric["client_address"]
			assert.NotNil(t, addr)
		}
	})

	slug := route[1:]

	var trace jaeger.Trace
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		resp, err := http.Get(jaegerQueryURL + "?service=rolldice&operation=GET%20%2F" + slug)
		require.NoError(t, err)
		if resp == nil {
			return
		}
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/" + slug})
		assert.LessOrEqual(t, 1, len(traces))
		trace = traces[0]
		require.Len(t, trace.Spans, 3) // parent - in queue - processing
	}, test.Interval(100*time.Millisecond))

	// Check the information of the parent span
	res := trace.FindByOperationName("GET /" + slug)
	require.Len(t, res, 1)
	parent := res[0]
	require.NotEmpty(t, parent.TraceID)
}

func TestHTTPGoOTelInstrumentedApp(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-go-otel.yml", path.Join(pathOutput, "test-suite-go-otel.log"))
	// we are going to setup discovery directly in the configuration file
	compose.Env = append(compose.Env, `BEYLA_EXECUTABLE_NAME=`, `BEYLA_OPEN_PORT=8080`)
	lockdown := KernelLockdownMode()

	if !lockdown {
		compose.Env = append(compose.Env, `SECURITY_CONFIG_SUFFIX=_none`)
	}

	require.NoError(t, err)
	require.NoError(t, compose.Up())

	t.Run("Go RED metrics: http service instrumented with OTel", func(t *testing.T) {
		waitForTestComponents(t, "http://localhost:8080")
		testForHTTPGoOTelLibrary(t, "/rolldice", "integration-test")
	})

	t.Run("BPF pinning folders mounted", func(t *testing.T) {
		// 1 beyla pinned map folder for all processes
		testBPFPinningMounted(t)
	})

	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
}
