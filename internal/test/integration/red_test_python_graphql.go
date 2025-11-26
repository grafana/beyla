// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	neturl "net/url"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/v2/internal/test/integration/components/jaeger"
)

func testPythonGraphQL(t *testing.T) {
	const (
		comm          = "python3.12"
		address       = "http://localhost:8381/graphql/"
		query         = `{"query": "query TestMe { testme }"}`
		operationName = "GraphQL query"
	)

	var tq jaeger.TracesQuery
	params := neturl.Values{}
	params.Add("service", comm)
	params.Add("operation", operationName)
	fullJaegerURL := fmt.Sprintf("%s?%s", jaegerQueryURL, params.Encode())

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		resp, err := http.Post(address, "application/json", bytes.NewBuffer([]byte(query)))
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)

		resp, err = http.Get(fullJaegerURL)
		require.NoError(t, err)
		if resp == nil {
			return
		}
		require.Equal(t, http.StatusOK, resp.StatusCode)

		require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "graphql.operation.type", Type: "string", Value: "query"})
		require.GreaterOrEqual(t, len(traces), 1)
		lastTrace := traces[len(traces)-1]
		span := lastTrace.Spans[0]

		assert.Equal(t, operationName, span.OperationName)

		tag, found := jaeger.FindIn(span.Tags, "graphql.operation.name")
		assert.True(t, found)
		assert.Equal(t, "TestMe", tag.Value)

		tag, found = jaeger.FindIn(span.Tags, "graphql.document")
		assert.True(t, found)
		assert.Equal(t, "query TestMe { testme }", tag.Value)
	}, test.Interval(100*time.Millisecond))
}
