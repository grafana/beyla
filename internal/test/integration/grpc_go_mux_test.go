//go:build integration

package integration

import (
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/v3/internal/test/integration/components/docker"
	"github.com/grafana/beyla/v3/internal/test/integration/components/promtest"
)

func testREDMetricsForGRPCMuxLibrary(t *testing.T, route, svcNs, serverPort string) {
	// Eventually, Prometheus would make this query visible
	pq := promtest.Client{HostPort: prometheusHostPort}
	var results []promtest.Result
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		var err error
		results, err = pq.Query(`rpc_server_duration_seconds_count{` +
			`rpc_grpc_status_code="0",` +
			`service_namespace="` + svcNs + `",` +
			`service_name="server",` +
			`rpc_method="` + route + `",` +
			`server_port="` + serverPort + `"}`)
		require.NoError(ct, err)
		// check duration_count has 3 calls and all the arguments
		enoughPromResults(ct, results)
		val := totalPromCount(ct, results)
		assert.LessOrEqual(ct, 1, val)
		if len(results) > 0 {
			res := results[0]
			assert.NotNil(ct, res.Metric["server_port"])
		}
	}, time.Minute, 100*time.Millisecond)
}

func TestGRPCMux(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-grpc-http2-mux.yml", path.Join(pathOutput, "test-suite-grpc-http2-mux.log"))
	// we are going to setup discovery directly in the configuration file
	compose.Env = append(compose.Env, `BEYLA_EXECUTABLE_NAME=`, `BEYLA_OPEN_PORT=`, `TARGET_URL=testserver:8080`, `TARGET_PORTS=8080:8080`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())

	t.Run("Go RED metrics: grpc-http2 mux service", func(t *testing.T) {
		testREDMetricsForGRPCMuxLibrary(t, "/grpc.health.v1.Health/Check", "grpc-http2-go", "8080")
	})

	require.NoError(t, compose.Close())
}

func TestGRPCMuxTLS(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-grpc-http2-mux.yml", path.Join(pathOutput, "test-suite-grpc-http2-mux-tls.log"))
	// we are going to setup discovery directly in the configuration file
	compose.Env = append(compose.Env, `BEYLA_EXECUTABLE_NAME=`, `BEYLA_OPEN_PORT=`, `TARGET_URL=testserver:8383`, `TARGET_PORTS=8383:8383`, `TEST_SUFFIX=_tls`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())

	t.Run("Go RED metrics: grpc-http2 mux service TLS", func(t *testing.T) {
		testREDMetricsForGRPCMuxLibrary(t, "/grpc.health.v1.Health/Check", "grpc-http2-go", "8383")
	})

	require.NoError(t, compose.Close())
}
