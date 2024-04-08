//go:build integration

package integration

import (
	"net/http"
	"path"
	"regexp"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/test/integration/components/docker"
	"github.com/grafana/beyla/test/integration/components/prom"
)

const allowAllAttrs = "BEYLA_NETWORK_ALLOWED_ATTRIBUTES=beyla.ip,src.address,dst.address,src.name,dst.name," +
	"src.namespace,dst.namespace,src.cidr,dst.cidr,iface,direction"

func TestNetwork_Deduplication(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-netolly.yml", path.Join(pathOutput, "test-suite-netolly-dedupe.log"))
	compose.Env = append(compose.Env, "BEYLA_NETWORK_DEDUPER=first_come", "BEYLA_EXECUTABLE_NAME=", allowAllAttrs)
	require.NoError(t, err)
	require.NoError(t, compose.Up())

	// When there flow deduplication, results must neither include "iface" nor "direction" fields.
	for _, f := range getNetFlows(t) {
		require.NotContains(t, f.Metric, "iface")
		require.NotContains(t, f.Metric, "direction")
	}

	require.NoError(t, compose.Close())
}

func TestNetwork_Deduplication_Use_Socket_Filter(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-netolly.yml", path.Join(pathOutput, "test-suite-netolly-dedupe-no-tc.log"))
	compose.Env = append(compose.Env, "BEYLA_NETWORK_DEDUPER=first_come", "BEYLA_EXECUTABLE_NAME=", "BEYLA_NETWORK_SOURCE=socket_filter", allowAllAttrs)
	require.NoError(t, err)
	require.NoError(t, compose.Up())

	// When there flow deduplication, results must neither include "iface" nor "direction" fields.
	for _, f := range getNetFlows(t) {
		require.NotContains(t, f.Metric, "iface")
		require.NotContains(t, f.Metric, "direction")
	}

	require.NoError(t, compose.Close())
}

func TestNetwork_NoDeduplication(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-netolly.yml", path.Join(pathOutput, "test-suite-netolly-nodedupe.log"))
	compose.Env = append(compose.Env, "BEYLA_NETWORK_DEDUPER=none", "BEYLA_EXECUTABLE_NAME=", allowAllAttrs)
	require.NoError(t, err)
	require.NoError(t, compose.Up())

	// When there is no flow deduplication, results must include "iface" and "direction" fields.
	validDirections := regexp.MustCompile("^(ingress|egress)$")
	for _, f := range getNetFlows(t) {
		require.Contains(t, f.Metric, "iface")
		require.Contains(t, f.Metric, "direction")
		assert.NotEmpty(t, f.Metric["iface"])
		assert.Regexp(t, validDirections, f.Metric["direction"])
	}

	require.NoError(t, compose.Close())
}

func TestNetwork_AllowedAttributes(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-netolly.yml", path.Join(pathOutput, "test-suite-netolly-allowed-attrs.log"))
	compose.Env = append(compose.Env, "BEYLA_EXECUTABLE_NAME=", `BEYLA_NETWORK_ALLOWED_ATTRIBUTES=beyla.ip,src.name`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())

	// When there flow deduplication, results must only include the BEYLA_NETWORK_ALLOWED_ATTRIBUTES
	for _, f := range getNetFlows(t) {
		require.Contains(t, f.Metric, "beyla_ip")
		require.Contains(t, f.Metric, "src_name")
		assert.NotEmpty(t, f.Metric["beyla_ip"])
		assert.NotEmpty(t, f.Metric["src_name"])

		assert.NotContains(t, f.Metric, "src_address")
		assert.NotContains(t, f.Metric, "dst_address")
		assert.NotContains(t, f.Metric, "dst_name")
	}

	require.NoError(t, compose.Close())
}

func getNetFlows(t *testing.T) []prom.Result {
	var results []prom.Result
	pq := prom.Client{HostPort: prometheusHostPort}
	test.Eventually(t, 4*testTimeout, func(t require.TestingT) {
		// first, verify that the test service endpoint is healthy
		req, err := http.NewRequest("GET", instrumentedServiceStdURL, nil)
		require.NoError(t, err)
		r, err := testHTTPClient.Do(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, r.StatusCode)

		// now, verify that the network metric has been reported.
		results, err = pq.Query(`beyla_network_flow_bytes_total`)
		require.NoError(t, err)
		require.NotEmpty(t, results)
	}, test.Interval(time.Second))
	return results
}
