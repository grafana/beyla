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
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"

	"github.com/grafana/beyla/v2/test/integration/components/prom"
)

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

func doHTTPGet(t *testing.T, path string, status int) {
	// Random fake body to cause the request to have some size (38 bytes)
	jsonBody := []byte(`{"productId": 123456, "quantity": 100}`)

	req, err := http.NewRequest(http.MethodGet, path, bytes.NewReader(jsonBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	r, err := testHTTPClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, status, r.StatusCode)
}

// nolint:errcheck
func doHTTPGetWithTimeout(t *testing.T, path string, timeout time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
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
	require.Greater(t, len(body), 0)
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

func waitForTestComponentsSub(t *testing.T, url, subpath string) {
	waitForTestComponentsSubWithTime(t, url, subpath, 1)
}

func waitForTestComponentsSubStatus(t *testing.T, url, subpath string, status int) {
	waitForTestComponentsSubWithTimeAndCode(t, url, subpath, status, 1)
}

// does a smoke test to verify that all the components that started
// asynchronously are up and communicating properly
func waitForTestComponentsSubWithTime(t *testing.T, url, subpath string, minutes int) {
	pq := prom.Client{HostPort: prometheusHostPort}
	test.Eventually(t, time.Duration(minutes)*time.Minute, func(t require.TestingT) {
		// first, verify that the test service endpoint is healthy
		req, err := http.NewRequest("GET", url+subpath, nil)
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
		req, err := http.NewRequest("GET", url+subpath, nil)
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
		req, err := http.NewRequest("GET", url+route, nil)
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
		req, err := http.NewRequest("GET", url+subpath, nil)
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

func doHTTP2Post(t *testing.T, path string, status int, jsonBody []byte) {
	req, err := http.NewRequest(http.MethodPost, path, bytes.NewReader(jsonBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	tr := &http2.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	r, err := tr.RoundTrip(req)

	require.NoError(t, err)
	require.Equal(t, status, r.StatusCode)
	require.Equal(t, 2, r.ProtoMajor)
}

func waitForTestComponentsHTTP2Sub(t *testing.T, url, subpath string, minutes int) {
	pq := prom.Client{HostPort: prometheusHostPort}
	test.Eventually(t, time.Duration(minutes)*time.Minute, func(t require.TestingT) {
		// first, verify that the test service endpoint is healthy
		req, err := http.NewRequest("GET", url+subpath, nil)
		require.NoError(t, err)
		tr := &http2.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}

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
