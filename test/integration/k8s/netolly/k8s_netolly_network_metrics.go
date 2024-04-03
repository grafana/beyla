//go:build integration

package otel

import (
	"context"
	"net"
	"regexp"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/e2e-framework/pkg/envconf"

	"github.com/grafana/beyla/test/integration/components/prom"
)

const (
	testTimeout        = 3 * time.Minute
	prometheusHostPort = "localhost:39090"
)

// values according to official Kind documentation: https://kind.sigs.k8s.io/docs/user/configuration/#pod-subnet
var podSubnets = []string{"10.244.0.0/16", "fd00:10:244::/56"}
var svcSubnets = []string{"10.96.0.0/16", "fd00:10:96::/112"}

func DoTestNetFlowBytesForExistingConnections(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	pq := prom.Client{HostPort: prometheusHostPort}

	// testing request flows (to testserver as Service)
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		results, err := pq.Query(`beyla_network_flow_bytes_total{src_name="internal-pinger",dst_name="testserver"}`)
		require.NoError(t, err)
		require.NotEmpty(t, results)

		// check that the metrics are properly decorated
		require.Len(t, results, 1)
		metric := results[0].Metric
		assertIsIP(t, metric["src_address"])
		assertIsIP(t, metric["dst_address"])
		assert.Equal(t, "beyla-network-flows", metric["job"])
		assert.Equal(t, "my-kube", metric["k8s_cluster_name"])
		assert.Equal(t, "default", metric["k8s_src_namespace"])
		assert.Equal(t, "internal-pinger", metric["k8s_src_name"])
		assert.Equal(t, "Pod", metric["k8s_src_owner_type"])
		assert.Equal(t, "Pod", metric["k8s_src_type"])
		assert.Equal(t, "test-kind-cluster-netolly-control-plane",
			metric["k8s_src_node_name"])
		assertIsIP(t, metric["k8s_src_node_ip"])
		assert.Equal(t, "default", metric["k8s_dst_namespace"])
		assert.Equal(t, "testserver", metric["k8s_dst_name"])
		assert.Equal(t, "Service", metric["k8s_dst_owner_type"])
		assert.Equal(t, "Service", metric["k8s_dst_type"])
		assert.Contains(t, podSubnets, metric["src_cidr"], metric)
		assert.Contains(t, svcSubnets, metric["dst_cidr"], metric)
		// services don't have host IP or name
	})
	// testing request flows (to testserver as Pod)
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		results, err := pq.Query(`beyla_network_flow_bytes_total{src_name="internal-pinger",dst_name=~"testserver-.*"}`)
		require.NoError(t, err)
		require.NotEmpty(t, results)

		// check that the metrics are properly decorated
		require.Len(t, results, 1)
		metric := results[0].Metric
		assertIsIP(t, metric["src_address"])
		assertIsIP(t, metric["dst_address"])
		assert.Equal(t, "beyla-network-flows", metric["job"])
		assert.Equal(t, "default", metric["k8s_src_namespace"])
		assert.Equal(t, "internal-pinger", metric["k8s_src_name"])
		assert.Equal(t, "Pod", metric["k8s_src_owner_type"])
		assert.Equal(t, "Pod", metric["k8s_src_type"])
		assert.Equal(t, "test-kind-cluster-netolly-control-plane",
			metric["k8s_src_node_name"])
		assertIsIP(t, metric["k8s_src_node_ip"])
		assert.Equal(t, "default", metric["k8s_dst_namespace"])
		assert.Regexp(t, regexp.MustCompile("^testserver-"), metric["k8s_dst_name"])
		assert.Equal(t, "Deployment", metric["k8s_dst_owner_type"])
		assert.Equal(t, "testserver", metric["k8s_dst_owner_name"])
		assert.Equal(t, "Pod", metric["k8s_dst_type"])
		assert.Equal(t, "test-kind-cluster-netolly-control-plane",
			metric["k8s_dst_node_name"])
		assertIsIP(t, metric["k8s_dst_node_ip"])
		assert.Contains(t, podSubnets, metric["src_cidr"], metric)
		assert.Contains(t, podSubnets, metric["dst_cidr"], metric)
	})

	// testing response flows (from testserver Pod)
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		results, err := pq.Query(`beyla_network_flow_bytes_total{src_name=~"testserver-.*",dst_name="internal-pinger"}`)
		require.NoError(t, err)
		require.NotEmpty(t, results)

		// check that the metrics are properly decorated
		require.Len(t, results, 1)
		metric := results[0].Metric
		assertIsIP(t, metric["src_address"])
		assertIsIP(t, metric["dst_address"])
		assert.Equal(t, "beyla-network-flows", metric["job"])
		assert.Equal(t, "default", metric["k8s_src_namespace"])
		assert.Regexp(t, regexp.MustCompile("^testserver-"), metric["k8s_src_name"])
		assert.Equal(t, "Deployment", metric["k8s_src_owner_type"])
		assert.Equal(t, "Pod", metric["k8s_src_type"])
		assert.Equal(t, "test-kind-cluster-netolly-control-plane", metric["k8s_src_node_name"])
		assertIsIP(t, metric["k8s_src_node_ip"])
		assert.Equal(t, "default", metric["k8s_dst_namespace"])
		assert.Equal(t, "internal-pinger", metric["k8s_dst_name"])
		assert.Equal(t, "Pod", metric["k8s_dst_owner_type"])
		assert.Equal(t, "Pod", metric["k8s_dst_type"])
		assert.Equal(t, "test-kind-cluster-netolly-control-plane", metric["k8s_dst_node_name"])
		assertIsIP(t, metric["k8s_dst_node_ip"])
		assert.Contains(t, podSubnets, metric["src_cidr"], metric)
		assert.Contains(t, podSubnets, metric["dst_cidr"], metric)
	})

	// testing response flows (from testserver Service)
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		results, err := pq.Query(`beyla_network_flow_bytes_total{src_name="testserver",dst_name="internal-pinger"}`)
		require.NoError(t, err)
		require.NotEmpty(t, results)

		// check that the metrics are properly decorated
		require.Len(t, results, 1)
		metric := results[0].Metric
		assertIsIP(t, metric["src_address"])
		assertIsIP(t, metric["dst_address"])
		assert.Equal(t, "beyla-network-flows", metric["job"])
		assert.Equal(t, "default", metric["k8s_src_namespace"])
		assert.Equal(t, "testserver", metric["k8s_src_name"])
		assert.Equal(t, "Service", metric["k8s_src_owner_type"])
		assert.Equal(t, "Service", metric["k8s_src_type"])
		// services don't have host IP or name
		assert.Equal(t, "default", metric["k8s_dst_namespace"])
		assert.Equal(t, "internal-pinger", metric["k8s_dst_name"])
		assert.Equal(t, "Pod", metric["k8s_dst_owner_type"])
		assert.Equal(t, "Pod", metric["k8s_dst_type"])
		assert.Equal(t, "test-kind-cluster-netolly-control-plane", metric["k8s_dst_node_name"])
		assertIsIP(t, metric["k8s_dst_node_ip"])
		assert.Contains(t, svcSubnets, metric["src_cidr"], metric)
		assert.Contains(t, podSubnets, metric["dst_cidr"], metric)
	})

	// check that there aren't captured flows if there is no communication
	results, err := pq.Query(`beyla_network_flow_bytes_total{src_name="internal-pinger",dst_name="otherinstance"}`)
	require.NoError(t, err)
	require.Empty(t, results)

	return ctx
}

func testNetFlowBytesForExternalTraffic(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	pq := prom.Client{HostPort: prometheusHostPort}

	// test external traffic (this test --> prometheus)
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		// checks that at least one source without src kubernetes label is there
		results, err := pq.Query(`beyla_network_flow_bytes_total{k8s_dst_owner_name="prometheus",k8s_src_owner_name=""}`)
		require.NoError(t, err)
		require.NotEmpty(t, results)
	})

	// test external traffic (prometheus --> this test)
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		// checks that at least one source without dst kubernetes label is there
		results, err := pq.Query(`beyla_network_flow_bytes_total{k8s_src_owner_name="prometheus",k8s_dst_owner_name=""}`)
		require.NoError(t, err)
		require.NotEmpty(t, results)
	})
	return ctx
}

func assertIsIP(t require.TestingT, str string) {
	if net.ParseIP(str) == nil {
		assert.Failf(t, "error parsing IP address", "expected IP. Got %s", str)
	}
}
