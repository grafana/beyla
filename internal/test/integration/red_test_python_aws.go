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
	"github.com/stretchr/testify/require"

	ti "go.opentelemetry.io/obi/pkg/test/integration"

	"github.com/grafana/beyla/v2/internal/test/integration/components/jaeger"
)

const (
	awsProxyAddress   = "http://localhost:8381"
	localstackAddress = "http://localhost:4566"
)

func awsReq(t *testing.T, url string) {
	t.Helper()

	resp, err := http.Get(url)
	require.NoError(t, err)
	require.True(t, resp.StatusCode >= 200 && resp.StatusCode <= 204)
}

func waitAWSProxy(t *testing.T) {
	waitForTestComponentsNoMetrics(t, awsProxyAddress+"/health")

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		ti.DoHTTPGet(t, awsProxyAddress+"/health", 200)
		resp, err := http.Get(jaegerQueryURL + "?service=python3.12&operation=GET%20%2Fhealth")
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var tq jaeger.TracesQuery
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/health"})
		require.GreaterOrEqual(t, len(traces), 1)
	}, test.Interval(1*time.Second))
}

func fetchAWSSpanByOP(t require.TestingT, op string) jaeger.Span {
	var tq jaeger.TracesQuery

	params := neturl.Values{}
	params.Add("service", "python3.12")
	params.Add("operation", op)
	fullJaegerURL := fmt.Sprintf("%s?%s", jaegerQueryURL, params.Encode())

	resp, err := http.Get(fullJaegerURL)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
	require.GreaterOrEqual(t, len(tq.Data), 1)

	for _, tr := range tq.Data {
		spans := tr.FindByOperationName(op, "client")
		if len(spans) > 0 {
			return spans[0]
		}
	}

	// Unreachable
	t.FailNow()
	return jaeger.Span{}
}
