//go:build integration

package integration

import (
	"testing"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/v2/test/integration/components/prom"
)

// does a smoke test to verify that all the components that started
// asynchronously for the Java test are up and communicating properly
func waitForJavaTestComponents(t *testing.T, url string) {
	waitForTestComponentsSub(t, url, "/greeting")
}

func testREDMetricsForJavaHTTPLibrary(t *testing.T, urls []string, comm string) {
	path := "/greeting"

	// Call 3 times the instrumented service, forcing it to:
	// - take at least 30ms to respond
	// - returning a 204 code
	for i := 0; i < 4; i++ {
		for _, url := range urls {
			doHTTPGet(t, url+path+"?delay=30&response=204", 204)
		}
	}

	commMatch := `service_name="` + comm + `",`
	namespaceMatch := `service_namespace="integration-test",`
	if comm == "" {
		commMatch = ""
		namespaceMatch = ""
	}

	// Eventually, Prometheus would make this query visible
	pq := prom.Client{HostPort: prometheusHostPort}
	var results []prom.Result
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_server_request_duration_seconds_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="204",` +
			namespaceMatch +
			commMatch +
			`url_path="` + path + `"}`)
		require.NoError(t, err)
		// check duration_count has 3 calls and all the arguments
		enoughPromResults(t, results)
		if len(results) > 0 {
			val := totalPromCount(t, results)
			assert.LessOrEqual(t, 3, val)

			res := results[0]
			addr := res.Metric["client_address"]
			assert.NotNil(t, addr)
		}
	})
}

func testREDMetricsJavaHTTP(t *testing.T) {
	t.Run("http://localhost:8086", func(t *testing.T) {
		waitForJavaTestComponents(t, "http://localhost:8086")
		testREDMetricsForJavaHTTPLibrary(t, []string{"http://localhost:8086"}, "greeting")
	})
}

func testREDMetricsJavaHTTPSystemWide(t *testing.T) {
	t.Run("http://localhost:8086", func(t *testing.T) {
		waitForJavaTestComponents(t, "http://localhost:8086")
		testREDMetricsForJavaHTTPLibrary(t, []string{"http://localhost:8086", "http://localhost:8087"}, "") // The test is flaky, sometimes we get docker-proxy sometimes greeting
	})
}

func testREDMetricsForJavaOTelSDK(t *testing.T, urls []string) {
	path := "/greeting"

	// Call 3 times the instrumented service, forcing it to:
	// - take at least 30ms to respond
	// - returning a 204 code
	for i := 0; i < 4; i++ {
		for _, url := range urls {
			doHTTPGet(t, url+path+"?delay=30&response=204", 204)
		}
	}

	// Eventually, Prometheus would make this query visible
	pq := prom.Client{HostPort: prometheusHostPort}
	var results []prom.Result
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_server_request_duration_seconds_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="204",` +
			`telemetry_distro_name="grafana-opentelemetry-java",` +
			`service_name="greeting-service",` +
			`http_route="/greeting"}`)
		require.NoError(t, err)
		// check duration_count has 3 calls and all the arguments
		enoughPromResults(t, results)
	})
}

func testREDMetricsJavaOTelSDKHTTP(t *testing.T) {
	t.Run("http://localhost:8086", func(t *testing.T) {
		waitForTestComponentsRoute(t, "http://localhost:8086", "/greeting")
		testREDMetricsForJavaOTelSDK(t, []string{"http://localhost:8086"})
	})
}
