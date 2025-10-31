//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ti "go.opentelemetry.io/obi/pkg/test/integration"

	"github.com/grafana/beyla/v2/internal/test/integration/components/docker"
	"github.com/grafana/beyla/v2/internal/test/integration/components/jaeger"
	"github.com/grafana/beyla/v2/internal/test/integration/components/prom"
)

func testForHTTPGoOTelLibrary(t *testing.T, route, svcNs string) {
	for i := 0; i < 4; i++ {
		ti.DoHTTPGet(t, "http://localhost:8080"+route, 200)
	}

	// Eventually, Prometheus would make this query visible
	var (
		pq     = prom.Client{HostPort: prometheusHostPort}
		labels = `http_request_method="GET",` +
			`http_response_status_code="200",` +
			`service_namespace="` + svcNs + `",` +
			`service_name="rolldice",` +
			`http_route="` + route + `",` +
			`url_path="` + route + `"`
	)

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		query := fmt.Sprintf("http_server_request_duration_seconds_count{%s}", labels)
		checkServerPromQueryResult(t, pq, query, 1)
	})

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		query := fmt.Sprintf("http_server_request_body_size_bytes_count{%s}", labels)
		checkServerPromQueryResult(t, pq, query, 3)
	})

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		query := fmt.Sprintf("http_server_response_body_size_bytes_count{%s}", labels)
		checkServerPromQueryResult(t, pq, query, 3)
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
		require.NotEmpty(t, traces)
		trace = traces[0]
		require.Len(t, trace.Spans, 3) // parent - in queue - processing
	}, test.Interval(100*time.Millisecond))

	// Check the information of the parent span
	res := trace.FindByOperationName("GET /"+slug, "server")
	require.Len(t, res, 1)
	parent := res[0]
	require.NotEmpty(t, parent.TraceID)
}

func testInstrumentationMissing(t *testing.T, route, svcNs string) {
	for i := 0; i < 4; i++ {
		ti.DoHTTPGet(t, "http://localhost:8080"+route, 200)
	}

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		resp, err := http.Get(jaegerQueryURL + "?service=dicer&operation=Roll")
		require.NoError(t, err)
		if resp == nil {
			return
		}
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "http.method", Type: "string", Value: "GET"})
		assert.LessOrEqual(t, 1, len(traces))
	}, test.Interval(100*time.Millisecond))

	// Eventually, Prometheus would make this query visible
	pq := prom.Client{HostPort: prometheusHostPort}
	var results []prom.Result

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_server_request_duration_seconds_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="200",` +
			`service_namespace="` + svcNs + `",` +
			`service_name="rolldice",` +
			`http_route="` + route + `",` +
			`url_path="` + route + `"}`)
		require.NoError(t, err)
		require.Empty(t, results)
	})

	slug := route[1:]

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
		require.Empty(t, traces)
	}, test.Interval(100*time.Millisecond))
}

func TestHTTPGoOTelInstrumentedApp(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-go-otel.yml", path.Join(pathOutput, "test-suite-go-otel.log"))
	// we are going to setup discovery directly in the configuration file
	compose.Env = append(compose.Env, `BEYLA_EXECUTABLE_NAME=`, `BEYLA_OPEN_PORT=8080`, `APP_OTEL_ENDPOINT=http://localhost:1111`)
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

	require.NoError(t, compose.Close())
}

func otelWaitForTestComponents(t *testing.T, url, subpath string) {
	pq := prom.Client{HostPort: prometheusHostPort}
	test.Eventually(t, 1*time.Minute, func(t require.TestingT) {
		// first, verify that the test service endpoint is healthy
		req, err := http.NewRequest(http.MethodGet, url+subpath, nil)
		require.NoError(t, err)
		r, err := testHTTPClient.Do(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, r.StatusCode)

		// now, verify that the metric has been reported.
		// we don't really care that this metric could be from a previous
		// test. Once one it is visible, it means that Otel and Prometheus are healthy
		results, err := pq.Query(`http_server_duration_count{http_method="GET"}`)
		require.NoError(t, err)
		require.NotEmpty(t, results)
	}, test.Interval(time.Second))
}

func TestHTTPGoOTelAvoidsInstrumentedApp(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-go-otel.yml", path.Join(pathOutput, "test-suite-go-otel-avoids.log"))
	// we are going to setup discovery directly in the configuration file
	compose.Env = append(compose.Env, `BEYLA_EXECUTABLE_NAME=`, `BEYLA_OPEN_PORT=8080`, `APP_OTEL_METRICS_ENDPOINT=http://otelcol:4318`, `APP_OTEL_TRACES_ENDPOINT=http://jaeger:4318`)
	lockdown := KernelLockdownMode()

	if !lockdown {
		compose.Env = append(compose.Env, `SECURITY_CONFIG_SUFFIX=_none`)
	}

	require.NoError(t, err)
	require.NoError(t, compose.Up())

	t.Run("Go RED metrics: http service instrumented with OTel, no istrumentation", func(t *testing.T) {
		otelWaitForTestComponents(t, "http://localhost:8080", "/smoke")
		time.Sleep(15 * time.Second) // ensure we see some calls to /v1/metrics /v1/traces
		testInstrumentationMissing(t, "/rolldice", "integration-test")
	})

	require.NoError(t, compose.Close())
}

func TestHTTPGoOTelDisabledOptInstrumentedApp(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-go-otel.yml", path.Join(pathOutput, "test-suite-go-otel-disabled.log"))
	// we are going to setup discovery directly in the configuration file
	compose.Env = append(
		compose.Env,
		`BEYLA_EXECUTABLE_NAME=`,
		`BEYLA_OPEN_PORT=8080`,
		`APP_OTEL_METRICS_ENDPOINT=http://otelcol:4318`,
		`APP_OTEL_TRACES_ENDPOINT=http://jaeger:4318`,
		`BEYLA_EXCLUDE_OTEL_INSTRUMENTED_SERVICES=false`,
	)

	lockdown := KernelLockdownMode()

	if !lockdown {
		compose.Env = append(compose.Env, `SECURITY_CONFIG_SUFFIX=_none`)
	}

	require.NoError(t, err)
	require.NoError(t, compose.Up())

	t.Run("Go RED metrics: http service instrumented with OTel, option disabled", func(t *testing.T) {
		otelWaitForTestComponents(t, "http://localhost:8080", "/smoke")
		time.Sleep(15 * time.Second) // ensure we see some calls to /v1/metrics /v1/traces
		testForHTTPGoOTelLibrary(t, "/rolldice", "integration-test")
	})

	require.NoError(t, compose.Close())
}

func TestHTTPGoOTelInstrumentedAppGRPC(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-go-otel-grpc.yml", path.Join(pathOutput, "test-suite-go-otel-grpc.log"))
	// we are going to setup discovery directly in the configuration file
	compose.Env = append(compose.Env, `BEYLA_EXECUTABLE_NAME=`, `BEYLA_OPEN_PORT=8080`, `APP_OTEL_ENDPOINT=http://localhost:1111`)
	lockdown := KernelLockdownMode()

	if !lockdown {
		compose.Env = append(compose.Env, `SECURITY_CONFIG_SUFFIX=_none`)
	}

	require.NoError(t, err)
	require.NoError(t, compose.Up())

	t.Run("Go RED metrics: http service instrumented with OTel - GRPC", func(t *testing.T) {
		waitForTestComponents(t, "http://localhost:8080")
		testForHTTPGoOTelLibrary(t, "/rolldice", "integration-test")
	})

	require.NoError(t, compose.Close())
}

func otelWaitForTestComponentsTraces(t *testing.T, url, subpath string) {
	test.Eventually(t, 1*time.Minute, func(t require.TestingT) {
		// first, verify that the test service endpoint is healthy
		req, err := http.NewRequest(http.MethodGet, url+subpath, nil)
		require.NoError(t, err)
		r, err := testHTTPClient.Do(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, r.StatusCode)

		resp, err := http.Get(jaegerQueryURL + "?service=dicer&operation=Smoke")
		require.NoError(t, err)
		if resp == nil {
			return
		}
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "http.method", Type: "string", Value: "GET"})
		assert.LessOrEqual(t, 1, len(traces))
	}, test.Interval(time.Second))
}

func TestHTTPGoOTelAvoidsInstrumentedAppGRPC(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-go-otel-grpc.yml", path.Join(pathOutput, "test-suite-go-otel-avoids-grpc.log"))
	// we are going to setup discovery directly in the configuration file
	compose.Env = append(compose.Env, `BEYLA_EXECUTABLE_NAME=`, `BEYLA_OPEN_PORT=8080`, `APP_OTEL_METRICS_ENDPOINT=http://otelcol:4317`, `APP_OTEL_TRACES_ENDPOINT=http://jaeger:4317`)
	lockdown := KernelLockdownMode()

	if !lockdown {
		compose.Env = append(compose.Env, `SECURITY_CONFIG_SUFFIX=_none`)
	}

	require.NoError(t, err)
	require.NoError(t, compose.Up())

	t.Run("Go RED metrics: http service instrumented with OTel, no istrumentation, GRPC", func(t *testing.T) {
		otelWaitForTestComponentsTraces(t, "http://localhost:8080", "/smoke")
		time.Sleep(15 * time.Second) // ensure we see some calls to /v1/metrics /v1/traces
		testInstrumentationMissing(t, "/rolldice", "integration-test")
	})

	require.NoError(t, compose.Close())
}
