// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"

	ti "go.opentelemetry.io/obi/pkg/test/integration"

	"github.com/grafana/beyla/v2/internal/test/integration/components/jaeger"
	"github.com/grafana/beyla/v2/internal/test/integration/components/promtest"
)

func runKafkaTestCase(t *testing.T, testCase TestCase) {
	t.Helper()

	var (
		pq = promtest.Client{HostPort: prometheusHostPort}

		url     = testCase.Route
		urlPath = testCase.Subpath
		comm    = testCase.Comm

		results []promtest.Result
		err     error
	)

	ti.DoHTTPGet(t, url+"/"+urlPath, 200)

	// Ensure we don't see any http requests
	results, err = pq.Query(`http_server_request_duration_seconds_count{}`)
	require.NoError(t, err, "failed to query prometheus for http_server_request_duration_seconds_count")
	require.Empty(t, results, "expected no HTTP requests, got %d", len(results))

	// Ensure we see the expected spans in Jaeger
	test.Eventually(t, 2*testTimeout, func(t require.TestingT) {
		for _, span := range testCase.Spans {
			command := span.Name
			resp, err := http.Get(jaegerQueryURL + "?service=" + comm + "&limit=1000")
			require.NoError(t, err, "failed to query jaeger for %s", comm)
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
			assert.LessOrEqual(t, 1, len(traces), "span %s with tags %v not found in traces %v", command, tags, tq.Data)
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

func testREDMetricsPythonKafkaOnly(t *testing.T) {
	commonAttrs := []attribute.KeyValue{
		attribute.String("messaging.system", "kafka"),
		attribute.Int("server.port", 9092),
	}

	testCases := []TestCase{
		{
			Route:   "http://localhost:8381",
			Subpath: "message",
			Comm:    "python3.14",
			Spans: []TestCaseSpan{
				{
					Name: "publish my-topic",
					Attributes: []attribute.KeyValue{
						attribute.String("span.kind", "producer"),
						attribute.String("messaging.operation.type", "publish"),
						attribute.String("messaging.destination.name", "my-topic"),
						attribute.String("messaging.client.id", "kafka-python-producer-1"),
						attribute.Int64("messaging.destination.partition.id", 0),
					},
				},
				{
					Name: "process my-topic",
					Attributes: []attribute.KeyValue{
						attribute.String("span.kind", "consumer"),
						attribute.String("messaging.operation.type", "process"),
						attribute.String("messaging.destination.name", "my-topic"),
						attribute.Int64("messaging.destination.partition.id", 0),
					},
				},
			},
		},
	}

	for _, testCase := range testCases {
		for i := range testCase.Spans {
			testCase.Spans[i].Attributes = append(testCase.Spans[i].Attributes, commonAttrs...)
		}

		t.Run(testCase.Route, func(t *testing.T) {
			waitForKafkaTestComponents(t, testCase.Route, "/"+testCase.Subpath)
			runKafkaTestCase(t, testCase)
		})
	}
}

func testJavaKafka(t *testing.T) {
	commonAttrs := []attribute.KeyValue{
		attribute.String("messaging.system", "kafka"),
		attribute.Int("server.port", 9092),
	}

	testCases := []TestCase{
		{
			Route:   "http://localhost:8381",
			Subpath: "message",
			Comm:    "javakafka",
			Spans: []TestCaseSpan{
				{
					Name: "publish my-topic",
					Attributes: []attribute.KeyValue{
						attribute.String("span.kind", "producer"),
						attribute.String("messaging.operation.type", "publish"),
						attribute.String("messaging.destination.name", "my-topic"),
						attribute.String("messaging.client.id", "producer-1"),
						attribute.Int64("messaging.destination.partition.id", 0),
					},
				},
				{
					// In here we can't recognize the topic name (so we use *) since the metadata response is cut to
					// the first 4 bytes in java, to get this to work we need to use eBPF large buffer feature for
					// kafka which is tested in testJavaKafkaLargeBuffer
					Name: "process *",
					Attributes: []attribute.KeyValue{
						attribute.String("span.kind", "consumer"),
						attribute.String("messaging.operation.type", "process"),
						attribute.String("messaging.destination.name", "*"),
						attribute.String("messaging.client.id", "consumer-1-1"),
						attribute.Int64("messaging.destination.partition.id", 0),
					},
				},
			},
		},
	}

	for _, testCase := range testCases {
		for i := range testCase.Spans {
			testCase.Spans[i].Attributes = append(testCase.Spans[i].Attributes, commonAttrs...)
		}

		t.Run(testCase.Route, func(t *testing.T) {
			waitForKafkaTestComponents(t, testCase.Route, "/"+testCase.Subpath)
			runKafkaTestCase(t, testCase)
		})
	}
}

func testJavaKafkaLargeBuffer(t *testing.T) {
	commonAttrs := []attribute.KeyValue{
		attribute.String("messaging.system", "kafka"),
		attribute.Int("server.port", 9092),
	}

	testCases := []TestCase{
		{
			Route:   "http://localhost:8381",
			Subpath: "message",
			Comm:    "javakafka-lb",
			Spans: []TestCaseSpan{
				{
					Name: "publish theotelebpfagentisperfectlyimpatientitskipsthecodethesdkandfindsthekernelssecretkeyitwatcheshttpandgrpctogiveyoumetricsforfreeapowerfulkernellevelspree",
					Attributes: []attribute.KeyValue{
						attribute.String("span.kind", "producer"),
						attribute.String("messaging.operation.type", "publish"),
						attribute.String("messaging.destination.name", "theotelebpfagentisperfectlyimpatientitskipsthecodethesdkandfindsthekernelssecretkeyitwatcheshttpandgrpctogiveyoumetricsforfreeapowerfulkernellevelspree"),
						attribute.String("messaging.client.id", "producer-1"),
						attribute.Int64("messaging.destination.partition.id", 0),
					},
				},
				{
					Name: "process theotelebpfagentisperfectlyimpatientitskipsthecodethesdkandfindsthekernelssecretkeyitwatcheshttpandgrpctogiveyoumetricsforfreeapowerfulkernellevelspree",
					Attributes: []attribute.KeyValue{
						attribute.String("span.kind", "consumer"),
						attribute.String("messaging.operation.type", "process"),
						attribute.String("messaging.destination.name", "theotelebpfagentisperfectlyimpatientitskipsthecodethesdkandfindsthekernelssecretkeyitwatcheshttpandgrpctogiveyoumetricsforfreeapowerfulkernellevelspree"),
						attribute.String("messaging.client.id", "consumer-1-1"),
						attribute.Int64("messaging.destination.partition.id", 0),
					},
				},
			},
		},
	}

	for _, testCase := range testCases {
		for i := range testCase.Spans {
			testCase.Spans[i].Attributes = append(testCase.Spans[i].Attributes, commonAttrs...)
		}

		t.Run(testCase.Route, func(t *testing.T) {
			waitForKafkaTestComponents(t, testCase.Route, "/"+testCase.Subpath)
			runKafkaTestCase(t, testCase)
		})
	}
}

func waitForKafkaTestComponents(t *testing.T, url string, subpath string) {
	t.Helper()

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		req, err := http.NewRequest(http.MethodGet, url+subpath, nil)
		require.NoError(ct, err)
		r, err := testHTTPClient.Do(req)
		require.NoError(ct, err)
		require.Equal(ct, http.StatusOK, r.StatusCode)
	}, time.Minute, time.Second)
}
