// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"path"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/require"

	ti "go.opentelemetry.io/obi/pkg/test/integration"

	"github.com/grafana/beyla/v2/internal/test/integration/components/docker"
	"github.com/grafana/beyla/v2/internal/test/integration/components/jaeger"
)

func testSampler(t *testing.T) {
	waitForTestComponents(t, "http://localhost:5000")
	waitForTestComponents(t, "http://localhost:5002")
	waitForTestComponents(t, "http://localhost:5003")

	// give enough time for the NodeJS injector to finish
	// TODO: once we implement the instrumentation status query API, replace
	// this with  a proper check to see if the target process has finished
	// being instrumented
	time.Sleep(60 * time.Second)

	// Add and check for specific trace ID
	// Run couple of requests to make sure we flush out any transactions that might be
	// stuck because of our tracking of full request times
	for i := 0; i < 10; i++ {
		ti.DoHTTPGet(t, "http://localhost:5000/a", 200)
	}

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		resp, err := http.Get(jaegerQueryURL + "?service=service-a&operation=GET%20%2Fa")

		require.NoError(t, err)

		if resp == nil {
			return
		}

		require.Equal(t, http.StatusOK, resp.StatusCode)

		var tq jaeger.TracesQuery

		require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))

		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/a"})

		lenA := len(traces)

		require.LessOrEqual(t, 10, lenA)

		resp, err = http.Get(jaegerQueryURL + "?service=service-c&operation=GET%20%2Fc")

		require.NoError(t, err)

		if resp == nil {
			return
		}

		require.Equal(t, http.StatusOK, resp.StatusCode)

		traces = tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/c"})

		lenC := len(traces)

		require.NotZero(t, lenC)
		require.Less(t, lenC, lenA)
	}, test.Interval(1500*time.Millisecond))
}

func TestSampler(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-sampler.yml", path.Join(pathOutput, "test-suite-sampler.log"))
	require.NoError(t, err)

	// we are going to setup discovery directly in the configuration file
	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=`, `OTEL_EBPF_OPEN_PORT=`)
	require.NoError(t, compose.Up())

	t.Run("Sampler", testSampler)

	require.NoError(t, compose.Close())
}
