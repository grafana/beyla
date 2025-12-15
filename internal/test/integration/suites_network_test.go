//go:build integration

package integration

import (
	"net/http"
	"path"
	"regexp"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/v2/internal/test/integration/components/docker"
	"github.com/grafana/beyla/v2/internal/test/integration/components/prom"
)

func TestNetwork_Deduplication(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-netolly.yml", path.Join(pathOutput, "test-suite-netolly-dedupe.log"))
	compose.Env = append(compose.Env, "BEYLA_NETWORK_DEDUPER=first_come", "BEYLA_EXECUTABLE_NAME=")
	require.NoError(t, err)
	require.NoError(t, compose.Up())

	// When there flow deduplication, results must not include "iface" field.
	for _, f := range getNetFlows(t) {
		require.NotContains(t, f.Metric, "iface")
		require.Contains(t, f.Metric, "iface_direction")
	}

	require.NoError(t, compose.Close())
}

func TestNetwork_Deduplication_Use_Socket_Filter(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-netolly.yml", path.Join(pathOutput, "test-suite-netolly-dedupe-no-tc.log"))
	compose.Env = append(compose.Env, "BEYLA_NETWORK_DEDUPER=first_come", "BEYLA_EXECUTABLE_NAME=", "BEYLA_NETWORK_SOURCE=socket_filter")
	require.NoError(t, err)
	require.NoError(t, compose.Up())

	// When there flow deduplication, results must not include "iface" field.
	for _, f := range getNetFlows(t) {
		require.NotContains(t, f.Metric, "iface")
		require.Contains(t, f.Metric, "iface_direction")
	}

	require.NoError(t, compose.Close())
}

func TestNetwork_NoDeduplication(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-netolly.yml", path.Join(pathOutput, "test-suite-netolly-nodedupe.log"))
	compose.Env = append(compose.Env, "BEYLA_NETWORK_DEDUPER=none", "BEYLA_EXECUTABLE_NAME=")
	require.NoError(t, err)
	require.NoError(t, compose.Up())

	// When there is no flow deduplication, results must include "iface".
	validIfaceDirections := regexp.MustCompile("^(ingress|egress)$")
	for _, f := range getNetFlows(t) {
		require.Contains(t, f.Metric, "iface")
		require.Contains(t, f.Metric, "iface_direction")
		assert.NotEmpty(t, f.Metric["iface"])
		assert.Regexp(t, validIfaceDirections, f.Metric["iface_direction"])
	}

	require.NoError(t, compose.Close())
}

func TestNetwork_AllowedAttributes(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-netolly.yml", path.Join(pathOutput, "test-suite-netolly-allowed-attrs.log"))
	compose.Env = append(compose.Env, "BEYLA_EXECUTABLE_NAME=", `BEYLA_CONFIG_SUFFIX=-disallowattrs`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())

	// When there flow deduplication, results must only include
	// the attributes under the attributes.allow section
	for _, f := range getNetFlows(t) {
		require.Contains(t, f.Metric, "beyla_ip")
		require.Contains(t, f.Metric, "src_name")
		require.Contains(t, f.Metric, "dst_port")
		assert.NotEmpty(t, f.Metric["beyla_ip"])
		assert.NotEmpty(t, f.Metric["src_name"])
		assert.NotEmpty(t, f.Metric["dst_port"])

		assert.NotContains(t, f.Metric, "src_address")
		assert.NotContains(t, f.Metric, "dst_address")
		assert.NotContains(t, f.Metric, "dst_name")
		assert.NotContains(t, f.Metric, "src_port")

		// src_name is just an IP address, as reverse DNS is disabled
		assert.Regexp(t, `^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`, f.Metric["src_name"])
	}

	require.NoError(t, compose.Close())
}

func TestNetwork_ReverseDNS(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-netolly-rdns.yml", path.Join(pathOutput, "test-suite-netolly-reverse-dns.log"))
	require.NoError(t, err)
	require.NoError(t, compose.Up())

	var checkCurlFlows = func(query string) {
		pq := prom.Client{HostPort: prometheusHostPort}
		test.Eventually(t, 4*testTimeout, func(t require.TestingT) {
			// now, verify that the network metric has been reported.
			results, err := pq.Query(`beyla_network_flow_bytes_total` + query)
			require.NoError(t, err)
			require.NotEmpty(t, results)
		})
	}

	checkCurlFlows(`{dst_name="github.com"}`)
	checkCurlFlows(`{src_name="github.com"}`)

	require.NoError(t, compose.Close())
}

func TestNetwork_Direction(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-netolly-direction.yml", path.Join(pathOutput, "test-suite-netolly-direction.log"))
	compose.Env = append(compose.Env, "BEYLA_NETWORK_DEDUPER=first_come", "BEYLA_NETWORK_SOURCE=tc", "BEYLA_EXECUTABLE_NAME=", `BEYLA_CONFIG_SUFFIX=-direction`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())

	results := getDirectionNetFlows(t)
	for _, f := range results {
		require.Contains(t, f.Metric, "iface_direction")
	}

	// test correct direction labels and client/server ports
	client := results[slices.IndexFunc(results, func(result prom.Result) bool { return result.Metric["dst_port"] == "8080" })]
	assert.Equal(t, "request", client.Metric["direction"])
	assert.Equal(t, "egress", client.Metric["iface_direction"])
	assert.Equal(t, "7000", client.Metric["client_port"])
	assert.Equal(t, "8080", client.Metric["server_port"])

	server := results[slices.IndexFunc(results, func(result prom.Result) bool { return result.Metric["src_port"] == "8080" })]
	assert.Equal(t, "response", server.Metric["direction"])
	assert.Equal(t, "ingress", server.Metric["iface_direction"], "ingress")
	assert.Equal(t, "7000", server.Metric["client_port"])
	assert.Equal(t, "8080", server.Metric["server_port"])

	require.NoError(t, compose.Close())
}

func TestNetwork_IfaceDirection_Use_Socket_Filter(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-netolly-direction.yml", path.Join(pathOutput, "test-suite-netolly-direction-no-tc.log"))
	compose.Env = append(compose.Env, "BEYLA_NETWORK_DEDUPER=first_come", "BEYLA_EXECUTABLE_NAME=", "BEYLA_NETWORK_SOURCE=socket_filter", `BEYLA_CONFIG_SUFFIX=-direction`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())

	results := getDirectionNetFlows(t)
	for _, f := range results {
		require.Contains(t, f.Metric, "iface_direction")
	}

	// test correct direction labels and client/server ports
	client := results[slices.IndexFunc(results, func(result prom.Result) bool { return result.Metric["dst_port"] == "8080" })]
	require.Equal(t, "request", client.Metric["direction"])
	require.Equal(t, "egress", client.Metric["iface_direction"])
	require.Equal(t, "7000", client.Metric["client_port"])
	require.Equal(t, "8080", client.Metric["server_port"])

	server := results[slices.IndexFunc(results, func(result prom.Result) bool { return result.Metric["src_port"] == "8080" })]
	require.Equal(t, "response", server.Metric["direction"])
	require.Equal(t, "ingress", server.Metric["iface_direction"])
	require.Equal(t, "7000", server.Metric["client_port"])
	require.Equal(t, "8080", server.Metric["server_port"])

	require.NoError(t, compose.Close())
}

func getNetFlows(t *testing.T) []prom.Result {
	var results []prom.Result
	pq := prom.Client{HostPort: prometheusHostPort}
	test.Eventually(t, 4*testTimeout, func(t require.TestingT) {
		// first, verify that the test service endpoint is healthy
		req, err := http.NewRequest(http.MethodGet, instrumentedServiceStdURL, nil)
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

func getDirectionNetFlows(t *testing.T) []prom.Result {
	var results []prom.Result
	pq := prom.Client{HostPort: prometheusHostPort}

	// wait for first network flow metrics
	test.Eventually(t, 4*testTimeout, func(t require.TestingT) {
		results, err := pq.Query(`beyla_network_flow_bytes_total`)
		require.NoError(t, err)
		require.NotEmpty(t, results)
	}, test.Interval(time.Second))

	// make a few calls to the testserver, which will call testserver2 with a source port lower than a destination port (7000 -> 8080)
	req, err := http.NewRequest(http.MethodGet, "http://localhost:8080/echoLowPort", nil)
	require.NoError(t, err)
	clientBytes, serverBytes := callAndCheckMetrics(t, req, pq, 0, 0)
	clientBytes, serverBytes = callAndCheckMetrics(t, req, pq, clientBytes, serverBytes)
	callAndCheckMetrics(t, req, pq, clientBytes, serverBytes)

	// verify that the correct network metric has been reported.
	test.Eventually(t, 4*testTimeout, func(t require.TestingT) {
		results, err = pq.Query(`beyla_network_flow_bytes_total{src_port="7000", dst_port="8080"} or beyla_network_flow_bytes_total{src_port="8080", dst_port="7000"}`)
		require.NoError(t, err)
		require.Len(t, results, 2)
		require.NotEmpty(t, results)
	}, test.Interval(time.Second))
	return results
}

func callAndCheckMetrics(t *testing.T, req *http.Request, pq prom.Client, previousClientValue int, previousServerValue int) (int, int) {
	var clientValue, serverValue int

	// make call
	r, err := testHTTPClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, r.StatusCode)

	// wait for fetching aggregated flows in beyla about this call
	test.Eventually(t, 4*testTimeout, func(t require.TestingT) {
		results, err := pq.Query(`beyla_network_flow_bytes_total{src_port="7000", dst_port="8080"} or beyla_network_flow_bytes_total{src_port="8080", dst_port="7000"}`)
		require.NoError(t, err)
		require.Len(t, results, 2)
		require.NotEmpty(t, results)
		// wait till the amount of bytes is greater than the previous read
		client := results[slices.IndexFunc(results, func(result prom.Result) bool { return result.Metric["dst_port"] == "8080" })]
		clientValue, _ = strconv.Atoi(client.Value[1].(string))
		require.Greater(t, clientValue, previousClientValue)
		server := results[slices.IndexFunc(results, func(result prom.Result) bool { return result.Metric["src_port"] == "8080" })]
		serverValue, _ = strconv.Atoi(server.Value[1].(string))
		require.Greater(t, serverValue, previousServerValue)
	}, test.Interval(time.Second))
	return clientValue, serverValue
}
