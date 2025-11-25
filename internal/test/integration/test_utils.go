//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"

	"github.com/grafana/beyla/v2/internal/test/integration/components/jaeger"
	"github.com/grafana/beyla/v2/internal/test/integration/components/prom"
)

/*
TestCaseSpan represents a span that is expected to be produced by the instrumented service
- Name: the name of the span (example: HSET)
- Attributes: a list of attributes that are expected to be present in the span
*/
type TestCaseSpan struct {
	Name       string
	Attributes []attribute.KeyValue
}

func (span TestCaseSpan) FindAttribute(key string) *attribute.KeyValue {
	for _, attr := range span.Attributes {
		if strings.EqualFold(string(attr.Key), key) {
			return &attr
		}
	}
	return nil
}

/*
TestCase represents a test case for the RED metrics, where calling an endpoint is expected to produce spans
- Route: the URL of the instrumented service (example: http://localhost:8381)
- Subpath: the subpath of the endpoint to call (without leading /) (example: redis)
- Comm: the name of the instrumented service (example: python3.12)
- Namespace: the namespace of the service (example: integration-test)
- Spans: a list of spans that are expected to be produced by the instrumented service, each span has:
*/
type TestCase struct {
	Route     string
	Subpath   string
	Comm      string
	Namespace string
	Spans     []TestCaseSpan
}

var tr = &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
}
var testHTTPClient = &http.Client{Transport: tr}

func setHTTPClientDisableKeepAlives(disableKeepAlives bool) {
	testHTTPClient.Transport.(*http.Transport).DisableKeepAlives = disableKeepAlives
}

func doHTTPPost(t *testing.T, path string, status int, jsonBody []byte) {
	req, err := http.NewRequest(http.MethodPost, path, bytes.NewReader(jsonBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	r, err := testHTTPClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, status, r.StatusCode)
}

// nolint:errcheck
func doHTTPGetWithTimeout(t *testing.T, path string, timeout time.Duration) {
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	// Random fake body to cause the request to have some size (38 bytes)
	jsonBody := []byte(`{"productId": 123456, "quantity": 100}`)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, path, bytes.NewReader(jsonBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	testHTTPClient.Do(req)
}

func doHTTPGetIgnoreStatus(t *testing.T, path string) {
	// Random fake body to cause the request to have some size (38 bytes)
	jsonBody := []byte(`{"productId": 123456, "quantity": 100}`)

	req, err := http.NewRequest(http.MethodGet, path, bytes.NewReader(jsonBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	r, _ := testHTTPClient.Do(req)
	require.NotNil(t, r)
}

func doHTTPGetFullResponse(t *testing.T, path string, status int) {
	// Random fake body to cause the request to have some size (38 bytes)
	jsonBody := []byte(`{"productId": 123456, "quantity": 100}`)

	req, err := http.NewRequest(http.MethodGet, path, bytes.NewReader(jsonBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	r, err := testHTTPClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, status, r.StatusCode)
	body, err := io.ReadAll(r.Body)
	require.NoError(t, err)
	require.NotEmpty(t, body)
}

func doHTTPGetWithTraceparent(t *testing.T, path string, status int, traceparent string) {
	// Random fake body to cause the request to have some size (38 bytes)
	jsonBody := []byte(`{"productId": 123456, "quantity": 100}`)

	req, err := http.NewRequest(http.MethodGet, path, bytes.NewReader(jsonBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Traceparent", traceparent)

	r, err := testHTTPClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, status, r.StatusCode)
}

func createTraceID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "0123456789abcdef0123456789abcdef"
	}
	return hex.EncodeToString(bytes)
}

func createParentID() string {
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		return "0123456789abcdef"
	}
	return hex.EncodeToString(bytes)
}

func createTraceparent(traceID string, parentID string) string {
	return "00-" + traceID + "-" + parentID + "-01"
}

func waitForTestComponents(t *testing.T, url string) {
	waitForTestComponentsSub(t, url, "/smoke")
}

func waitForTestComponentsHTTP2(t *testing.T, url string) {
	waitForTestComponentsHTTP2Sub(t, url, "/smoke", 1)
}

func waitForTestComponentsNoMetrics(t *testing.T, url string) {
	test.Eventually(t, 2*time.Minute, func(t require.TestingT) {
		resp, err := http.Get(url)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	}, test.Interval(time.Second))
}

func waitForTestComponentsSub(t *testing.T, url, subpath string) {
	waitForTestComponentsSubWithTime(t, url, subpath, 2)
}

func waitForTestComponentsSubStatus(t *testing.T, url, subpath string, status int) {
	waitForTestComponentsSubWithTimeAndCode(t, url, subpath, status, 2)
}

// does a smoke test to verify that all the components that started
// asynchronously are up and communicating properly
func waitForTestComponentsSubWithTime(t *testing.T, url, subpath string, minutes int) {
	pq := prom.Client{HostPort: prometheusHostPort}
	test.Eventually(t, time.Duration(minutes)*time.Minute, func(t require.TestingT) {
		// first, verify that the test service endpoint is healthy
		req, err := http.NewRequest(http.MethodGet, url+subpath, nil)
		require.NoError(t, err)
		r, err := testHTTPClient.Do(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, r.StatusCode)

		// now, verify that the metric has been reported.
		// we don't really care that this metric could be from a previous
		// test. Once one it is visible, it means that Otel and Prometheus are healthy
		results, err := pq.Query(`http_server_request_duration_seconds_count{url_path="` + subpath + `"}`)
		require.NoError(t, err)
		require.NotEmpty(t, results)
	}, test.Interval(time.Second))
}

func waitForTestComponentsSubWithTimeAndCode(t *testing.T, url, subpath string, status, minutes int) {
	pq := prom.Client{HostPort: prometheusHostPort}
	test.Eventually(t, time.Duration(minutes)*time.Minute, func(t require.TestingT) {
		// first, verify that the test service endpoint is healthy
		req, err := http.NewRequest(http.MethodGet, url+subpath, nil)
		require.NoError(t, err)
		r, err := testHTTPClient.Do(req)
		require.NoError(t, err)
		require.Equal(t, status, r.StatusCode)

		// now, verify that the metric has been reported.
		// we don't really care that this metric could be from a previous
		// test. Once one it is visible, it means that Otel and Prometheus are healthy
		results, err := pq.Query(`http_server_request_duration_seconds_count{url_path="` + subpath + `"}`)
		require.NoError(t, err)
		require.NotEmpty(t, results)
	}, test.Interval(time.Second))
}

func waitForTestComponentsRoute(t *testing.T, url, route string) {
	pq := prom.Client{HostPort: prometheusHostPort}
	test.Eventually(t, time.Duration(1)*time.Minute, func(t require.TestingT) {
		// first, verify that the test service endpoint is healthy
		req, err := http.NewRequest(http.MethodGet, url+route, nil)
		require.NoError(t, err)
		r, err := testHTTPClient.Do(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, r.StatusCode)

		// now, verify that the metric has been reported.
		// we don't really care that this metric could be from a previous
		// test. Once one it is visible, it means that Otel and Prometheus are healthy
		results, err := pq.Query(`http_server_request_duration_seconds_count{http_route="` + route + `"}`)
		require.NoError(t, err)
		require.NotEmpty(t, results)
	}, test.Interval(time.Second))
}

func waitForSQLTestComponents(t *testing.T, url, subpath string) {
	waitForSQLTestComponentsWithDB(t, url, subpath, "postgresql")
}

func waitForSQLTestComponentsMySQL(t *testing.T, url, subpath string) {
	waitForSQLTestComponentsWithDB(t, url, subpath, "mysql")
}

func waitForSQLTestComponentsWithDB(t *testing.T, url, subpath, db string) {
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
		results, err := pq.Query(`db_client_operation_duration_seconds_count{db_system_name="` + db + `"}`)
		require.NoError(t, err)
		require.NotEmpty(t, results)
	}, test.Interval(time.Second))
}

func enoughPromResults(t require.TestingT, results []prom.Result) {
	require.GreaterOrEqual(t, len(results), 1)
}

func totalPromCount(t require.TestingT, results []prom.Result) int {
	total := 0
	for _, res := range results {
		require.Len(t, res.Value, 2)
		val, err := strconv.Atoi(res.Value[1].(string))
		require.NoError(t, err)
		total += val
	}

	return total
}

func checkServerPromQueryResult(t require.TestingT, pq prom.Client, query string, promCount int) {
	results, err := pq.Query(query)
	require.NoError(t, err)
	// check duration_count has 3 calls and all the arguments
	enoughPromResults(t, results)
	val := totalPromCount(t, results)
	assert.LessOrEqual(t, promCount, val)
	if len(results) > 0 {
		res := results[0]
		addr := res.Metric["client_address"]
		assert.NotNil(t, addr)
	}
}

func checkClientPromQueryResult(t require.TestingT, pq prom.Client, query string, promCount int) {
	results, err := pq.Query(query)
	require.NoError(t, err)
	enoughPromResults(t, results)
	val := totalPromCount(t, results)
	assert.LessOrEqual(t, promCount, val)
}

func doHTTP2Post(t *testing.T, path string, status int, jsonBody []byte) {
	req, err := http.NewRequest(http.MethodPost, path, bytes.NewReader(jsonBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	tr := newHTTP2Transport()

	r, err := tr.RoundTrip(req)

	require.NoError(t, err)
	require.Equal(t, status, r.StatusCode)
	require.Equal(t, 2, r.ProtoMajor)
}

func waitForTestComponentsHTTP2Sub(t *testing.T, url, subpath string, minutes int) {
	pq := prom.Client{HostPort: prometheusHostPort}
	test.Eventually(t, time.Duration(minutes)*time.Minute, func(t require.TestingT) {
		// first, verify that the test service endpoint is healthy
		req, err := http.NewRequest(http.MethodGet, url+subpath, nil)
		require.NoError(t, err)
		tr := newHTTP2Transport()

		r, err := tr.RoundTrip(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, r.StatusCode)

		// now, verify that the metric has been reported.
		// we don't really care that this metric could be from a previous
		// test. Once one it is visible, it means that Otel and Prometheus are healthy
		results, err := pq.Query(`http_server_request_duration_seconds_count{url_path="` + subpath + `"}`)
		require.NoError(t, err)
		require.NotEmpty(t, results)
	}, test.Interval(time.Second))
}

func otelAttributeToJaegerTag(attr attribute.KeyValue) jaeger.Tag {
	var value any
	value = attr.Value.AsInterface()
	if attr.Value.Type() == attribute.INT64 {
		// jaeger encodes int64 as float64
		value = float64(attr.Value.AsInt64())
	}
	return jaeger.Tag{
		Key:   string(attr.Key),
		Type:  strings.ToLower(attr.Value.Type().String()),
		Value: value,
	}
}

// newHTTP2Transport creates an HTTP transport configured
// to use HTTP/2 with TLS verification disabled.
func newHTTP2Transport() *http.Transport {
	protocols := &http.Protocols{}
	protocols.SetHTTP2(true)
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Protocols = protocols
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	return tr
}
