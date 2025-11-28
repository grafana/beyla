// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	neturl "net/url"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ti "go.opentelemetry.io/obi/pkg/test/integration"

	"github.com/grafana/beyla/v2/internal/test/integration/components/jaeger"
)

const (
	comm          = "python3.12"
	testIndex     = "test_index"
	testServerURL = "http://localhost:8381"
)

func testPythonElasticsearch(t *testing.T, dbSystemName string) {
	var url string
	switch dbSystemName {
	case "elasticsearch":
		url = "http://elasticsearchserver:9200"
	case "opensearch":
		url = "http://opensearchserver:9200"
	}
	queryParam := "?host_url=" + url
	waitForTestComponentsNoMetrics(t, testServerURL+"/health"+queryParam)
	testElasticsearchSearch(t, dbSystemName, queryParam)
	// populate the server is optional, the elasticsearch request will fail
	// but we will have the span
	testElasticsearchMsearch(t, dbSystemName, queryParam)
	testElasticsearchBulk(t, dbSystemName, queryParam)
	testElasticsearchDoc(t, dbSystemName, queryParam)
}

func testElasticsearchSearch(t *testing.T, dbSystemName, queryParam string) {
	queryText := "{\"query\": {\"match\": {\"name\": \"OBI\"}}}"
	urlPath := "/search"
	ti.DoHTTPGet(t, testServerURL+urlPath+queryParam, 200)
	assertElasticsearchOperation(t, dbSystemName, "search", queryText, testIndex)
}

func assertElasticsearchOperation(t *testing.T, dbSystemName, op, queryText, index string) {
	params := neturl.Values{}
	params.Add("service", comm)
	var operationName string
	if index != "" {
		operationName = op + " " + index
	} else {
		operationName = op
	}
	params.Add("operationName", operationName)
	fullJaegerURL := fmt.Sprintf("%s?%s", jaegerQueryURL, params.Encode())

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		resp, err := http.Get(fullJaegerURL)
		require.NoError(t, err)
		if resp == nil {
			return
		}
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var tq jaeger.TracesQuery
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "db.operation.name", Type: "string", Value: op})
		require.GreaterOrEqual(t, len(traces), 1, resp.Body)
		lastTrace := traces[len(traces)-1]
		span := lastTrace.Spans[0]

		assert.Contains(t, span.OperationName, operationName)

		tag, found := jaeger.FindIn(span.Tags, "db.query.text")
		assert.True(t, found)
		assert.Equal(t, queryText, tag.Value.(string))

		tag, found = jaeger.FindIn(span.Tags, "db.collection.name")
		assert.True(t, found)
		assert.Equal(t, index, tag.Value)

		tag, found = jaeger.FindIn(span.Tags, "db.namespace")
		assert.True(t, found)
		assert.Empty(t, tag.Value)

		tag, found = jaeger.FindIn(span.Tags, "db.system.name")
		assert.True(t, found)
		assert.Equal(t, dbSystemName, tag.Value)

		tag, found = jaeger.FindIn(span.Tags, "elasticsearch.node.name")
		assert.True(t, found)
		assert.Empty(t, tag.Value)
	}, test.Interval(100*time.Millisecond))
}

func testElasticsearchMsearch(t *testing.T, dbSystemName, queryParam string) {
	queryText := "[{}, {\"query\": {\"match\": {\"message\": \"this is a test\"}}}, {\"index\": \"my-index-000002\"}, {\"query\": {\"match_all\": {}}}]"
	urlPath := "/msearch"
	ti.DoHTTPGet(t, testServerURL+urlPath+queryParam, 200)
	assertElasticsearchOperation(t, dbSystemName, "msearch", queryText, "")
}

func testElasticsearchBulk(t *testing.T, dbSystemName, queryParam string) {
	queryText := "[{\"index\": {\"_index\": \"test\", \"_id\": \"1\"}}, {\"field1\": \"value1\"}, {\"delete\": {\"_index\": \"test\", \"_id\": \"2\"}}, {\"create\": {\"_index\": \"test\", \"_id\": \"3\"}}, {\"field1\": \"value3\"}, {\"update\": {\"_id\": \"1\", \"_index\": \"test\"}}, {\"doc\": {\"field2\": \"value2\"}}]"
	urlPath := "/bulk"
	ti.DoHTTPGet(t, testServerURL+urlPath+queryParam, 200)
	assertElasticsearchOperation(t, dbSystemName, "bulk", queryText, "")
}

func testElasticsearchDoc(t *testing.T, dbSystemName, queryParam string) {
	queryText := ""
	urlPath := "/doc"
	ti.DoHTTPGet(t, testServerURL+urlPath+queryParam, 200)
	assertElasticsearchOperation(t, dbSystemName, "doc", queryText, testIndex)
}
