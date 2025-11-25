// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"

	ti "go.opentelemetry.io/obi/pkg/test/integration"

	"github.com/grafana/beyla/v2/internal/test/integration/components/jaeger"
	"github.com/grafana/beyla/v2/internal/test/integration/components/prom"
)

func testREDMetricsForPythonMongoLibrary(t *testing.T, testCase TestCase) {
	uri := testCase.Route
	urlPath := testCase.Subpath
	comm := testCase.Comm
	namespace := testCase.Namespace
	// Call 3 times the instrumented service, forcing it to:
	// - take a large JSON file
	// - returning a 200 code
	for i := 0; i < 4; i++ {
		ti.DoHTTPGet(t, uri+"/"+urlPath, 200)
	}

	// Eventually, Prometheus would make mongo operations visible
	pq := prom.Client{HostPort: prometheusHostPort}
	var results []prom.Result
	var err error
	for _, span := range testCase.Spans {
		operation := span.FindAttribute("db.operation.name")
		require.NotNil(t, operation, "db.operation.name attribute not found in span %s", span.Name)
		test.Eventually(t, testTimeout, func(t require.TestingT) {
			var err error
			results, err = pq.Query(`db_client_operation_duration_seconds_count{` +
				`db_operation_name="` + operation.Value.AsString() + `",` +
				`service_namespace="` + namespace + `"}`)
			require.NoError(t, err, "failed to query prometheus for %s", span.Name)
			enoughPromResults(t, results)
			val := totalPromCount(t, results)
			assert.LessOrEqual(t, 3, val, "expected at least 3 %s operations, got %d", span.Name, val)
		})
	}

	// Ensure we don't see any http requests
	results, err = pq.Query(`http_server_request_duration_seconds_count{}`)
	require.NoError(t, err, "failed to query prometheus for http_server_request_duration_seconds_count")
	require.Empty(t, results, "expected no HTTP requests, got %d", len(results))
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		for _, span := range testCase.Spans {
			command := span.Name
			resp, err := http.Get(jaegerQueryURL + "?service=" + comm + "&operation=" + url.QueryEscape(command))
			require.NoError(t, err, "failed to query jaeger for %s", command)
			if resp == nil {
				return
			}
			require.Equal(t, http.StatusOK, resp.StatusCode, "unexpected status code for %s: %d", command, resp.StatusCode)
			var tq jaeger.TracesQuery
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq), "failed to decode jaeger response for %s", command)
			var tags []jaeger.Tag
			for _, attr := range span.Attributes {
				tags = append(tags, otelAttributeToJaegerTag(attr))
			}
			traces := tq.FindBySpan(tags...)
			assert.LessOrEqual(t, 1, len(traces), "span %s with tags %v not found in traces in traces %v", command, tags, tq.Data)
		}
	}, test.Interval(100*time.Millisecond))

	// Ensure we don't find any HTTP traces, since we filter them out
	resp, err := http.Get(jaegerQueryURL + "?service=" + comm + "&operation=GET%20%2F" + urlPath)
	require.NoError(t, err, "failed to query jaeger for HTTP traces")
	if resp == nil {
		return
	}
	require.Equal(t, http.StatusOK, resp.StatusCode, "unexpected status code for HTTP traces: %d", resp.StatusCode)
	var tq jaeger.TracesQuery
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq), "failed to decode jaeger response for HTTP traces")
	traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/" + urlPath})
	require.Empty(t, traces, "expected no HTTP traces, got %d", len(traces))
}

func testREDMetricsPythonMongoOnly(t *testing.T) {
	mongoCommonAttributes := []attribute.KeyValue{
		attribute.String("db.system.name", "mongodb"),
		attribute.String("span.kind", "client"),
		attribute.Int("server.port", 27017),
	}
	testCases := []TestCase{
		{
			Route:     "http://localhost:8381",
			Subpath:   "mongo",
			Comm:      "python3.12",
			Namespace: "integration-test",
			Spans: []TestCaseSpan{
				{
					Name: "insert mycollection",
					Attributes: []attribute.KeyValue{
						attribute.String("db.operation.name", "insert"),
						attribute.String("db.collection.name", "mycollection"),
						attribute.String("db.namespace", "mydatabase"),
					},
				},
				{
					Name: "update mycollection",
					Attributes: []attribute.KeyValue{
						attribute.String("db.operation.name", "update"),
						attribute.String("db.collection.name", "mycollection"),
						attribute.String("db.namespace", "mydatabase"),
					},
				},
				{
					Name: "delete mycollection",
					Attributes: []attribute.KeyValue{
						attribute.String("db.operation.name", "delete"),
						attribute.String("db.collection.name", "mycollection"),
						attribute.String("db.namespace", "mydatabase"),
					},
				},
				{
					Name: "find mycollection",
					Attributes: []attribute.KeyValue{
						attribute.String("db.operation.name", "find"),
						attribute.String("db.collection.name", "mycollection"),
						attribute.String("db.namespace", "mydatabase"),
					},
				},
			},
		},
	}
	for _, testCase := range testCases {
		// Add common attributes to each span
		for i := range testCase.Spans {
			testCase.Spans[i].Attributes = append(testCase.Spans[i].Attributes, mongoCommonAttributes...)
		}

		t.Run(testCase.Route, func(t *testing.T) {
			waitForMongoTestComponents(t, testCase.Route, "/"+testCase.Subpath)
			testREDMetricsForPythonMongoLibrary(t, testCase)
		})
	}
}

func waitForMongoTestComponents(t *testing.T, url string, subpath string) {
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
		results, err := pq.Query(`db_client_operation_duration_seconds_count{db_system_name="mongodb"}`)
		require.NoError(t, err)
		require.NotEmpty(t, results)
	}, test.Interval(time.Second))
}
