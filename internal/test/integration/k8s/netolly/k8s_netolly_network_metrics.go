//go:build integration_k8s

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
	"sigs.k8s.io/e2e-framework/pkg/features"

	"github.com/grafana/beyla/v2/internal/test/integration/components/kube"
	"github.com/grafana/beyla/v2/internal/test/integration/components/prom"
	k8s "github.com/grafana/beyla/v2/internal/test/integration/k8s/common"
)

const (
	testTimeout        = 3 * time.Minute
	prometheusHostPort = "localhost:39090"
)

// values according to official Kind documentation: https://kind.sigs.k8s.io/docs/user/configuration/#pod-subnet
var podSubnets = []string{"10.244.0.0/16", "fd00:10:244::/56"}
var svcSubnets = []string{"10.96.0.0/16", "fd00:10:96::/112"}

func FeatureNetworkFlowBytes() features.Feature {
	pinger := kube.Template[k8s.Pinger]{
		TemplateFile: k8s.UninstrumentedPingerManifest,
		Data: k8s.Pinger{
			PodName:   "internal-pinger-net",
			TargetURL: "http://testserver:8080/iping",
		},
	}
	return features.New("network flow bytes").
		Setup(pinger.Deploy()).
		Teardown(pinger.Delete()).
		Assess("catches network metrics between connected pods", testNetFlowBytesForExistingConnections).
		Assess("catches external traffic", testNetFlowBytesForExternalTraffic).
		Feature()
}

func testNetFlowBytesForExistingConnections(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	pq := prom.Client{HostPort: prometheusHostPort}
	// testing request flows (to testserver as Service)
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		results, err := pq.Query(`beyla_network_flow_bytes_total{src_name="internal-pinger-net",dst_name="testserver"}`)
		require.NoError(t, err)
		require.NotEmpty(t, results)

		// check that the metrics are properly decorated
		require.GreaterOrEqual(t, len(results), 1) // tests could establish more than one connection from different client_ports
		metric := results[0].Metric
		assertIsIP(t, metric["src_address"])
		assertIsIP(t, metric["dst_address"])
		assert.Equal(t, "my-kube", metric["k8s_cluster_name"])
		assert.Equal(t, "default", metric["k8s_src_namespace"])
		assert.Equal(t, "internal-pinger-net", metric["k8s_src_name"])
		assert.Equal(t, "Pod", metric["k8s_src_owner_type"])
		assert.Equal(t, "Pod", metric["k8s_src_type"])
		assert.Regexp(t,
			regexp.MustCompile("^test-kind-cluster-.*control-plane"),
			metric["k8s_src_node_name"])
		assertIsIP(t, metric["k8s_src_node_ip"])
		assert.Equal(t, "default", metric["k8s_dst_namespace"])
		assert.Equal(t, "testserver", metric["k8s_dst_name"])
		assert.Equal(t, "Service", metric["k8s_dst_owner_type"])
		assert.Equal(t, "Service", metric["k8s_dst_type"])
		assert.Contains(t, podSubnets, metric["src_cidr"], metric)
		assert.Contains(t, svcSubnets, metric["dst_cidr"], metric)
		assert.Equal(t, "8080", metric["server_port"])
		assert.NotEqual(t, "8080", metric["client_port"])
		// services don't have host IP or name
	})
	// testing request flows (to testserver as Pod)
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		results, err := pq.Query(`beyla_network_flow_bytes_total{src_name="internal-pinger-net",dst_name=~"testserver-.*"}`)
		require.NoError(t, err)
		require.NotEmpty(t, results)

		// check that the metrics are properly decorated
		require.GreaterOrEqual(t, len(results), 1) // tests could establish more than one connection from different client_ports
		metric := results[0].Metric
		assertIsIP(t, metric["src_address"])
		assertIsIP(t, metric["dst_address"])
		assert.Equal(t, "default", metric["k8s_src_namespace"])
		assert.Equal(t, "internal-pinger-net", metric["k8s_src_name"])
		assert.Equal(t, "Pod", metric["k8s_src_owner_type"])
		assert.Equal(t, "Pod", metric["k8s_src_type"])
		assert.Regexp(t,
			regexp.MustCompile("^test-kind-cluster-.*control-plane"),
			metric["k8s_src_node_name"])
		assertIsIP(t, metric["k8s_src_node_ip"])
		assert.Equal(t, "default", metric["k8s_dst_namespace"])
		assert.Regexp(t, regexp.MustCompile("^testserver-"), metric["k8s_dst_name"])
		assert.Equal(t, "Deployment", metric["k8s_dst_owner_type"])
		assert.Equal(t, "testserver", metric["k8s_dst_owner_name"])
		assert.Equal(t, "Pod", metric["k8s_dst_type"])
		assert.Regexp(t,
			regexp.MustCompile("^test-kind-cluster-.*control-plane"),
			metric["k8s_dst_node_name"])
		assertIsIP(t, metric["k8s_dst_node_ip"])
		assert.Contains(t, podSubnets, metric["src_cidr"], metric)
		assert.Contains(t, podSubnets, metric["dst_cidr"], metric)
		assert.Equal(t, "8080", metric["server_port"])
		assert.NotEqual(t, "8080", metric["client_port"])
	})

	// testing response flows (from testserver Pod)
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		results, err := pq.Query(`beyla_network_flow_bytes_total{src_name=~"testserver-.*",dst_name="internal-pinger-net"}`)
		require.NoError(t, err)
		require.NotEmpty(t, results)

		// check that the metrics are properly decorated
		require.GreaterOrEqual(t, len(results), 1) // tests could establish more than one connection from different client_ports
		metric := results[0].Metric
		assertIsIP(t, metric["src_address"])
		assertIsIP(t, metric["dst_address"])
		assert.Equal(t, "default", metric["k8s_src_namespace"])
		assert.Regexp(t, regexp.MustCompile("^testserver-"), metric["k8s_src_name"])
		assert.Equal(t, "Deployment", metric["k8s_src_owner_type"])
		assert.Equal(t, "Pod", metric["k8s_src_type"])
		assert.Regexp(t,
			regexp.MustCompile("^test-kind-cluster-.*control-plane"),
			metric["k8s_src_node_name"])
		assertIsIP(t, metric["k8s_src_node_ip"])
		assert.Equal(t, "default", metric["k8s_dst_namespace"])
		assert.Equal(t, "internal-pinger-net", metric["k8s_dst_name"])
		assert.Equal(t, "Pod", metric["k8s_dst_owner_type"])
		assert.Equal(t, "Pod", metric["k8s_dst_type"])
		assert.Regexp(t,
			regexp.MustCompile("^test-kind-cluster-.*control-plane"),
			metric["k8s_dst_node_name"])
		assertIsIP(t, metric["k8s_dst_node_ip"])
		assert.Contains(t, podSubnets, metric["src_cidr"], metric)
		assert.Contains(t, podSubnets, metric["dst_cidr"], metric)
		assert.Equal(t, "TCP", metric["transport"])
		assert.Equal(t, "8080", metric["server_port"])
		assert.NotEqual(t, "8080", metric["client_port"])
	})

	// testing response flows (from testserver Service)
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		results, err := pq.Query(`beyla_network_flow_bytes_total{src_name="testserver",dst_name="internal-pinger-net"}`)
		require.NoError(t, err)
		require.NotEmpty(t, results)

		// check that the metrics are properly decorated
		require.GreaterOrEqual(t, len(results), 1) // tests could establish more than one connection from different client_ports
		metric := results[0].Metric
		assertIsIP(t, metric["src_address"])
		assertIsIP(t, metric["dst_address"])
		assert.Equal(t, "default", metric["k8s_src_namespace"])
		assert.Equal(t, "testserver", metric["k8s_src_name"])
		assert.Equal(t, "Service", metric["k8s_src_owner_type"])
		assert.Equal(t, "Service", metric["k8s_src_type"])
		// services don't have host IP or name
		assert.Equal(t, "default", metric["k8s_dst_namespace"])
		assert.Equal(t, "internal-pinger-net", metric["k8s_dst_name"])
		assert.Equal(t, "Pod", metric["k8s_dst_owner_type"])
		assert.Equal(t, "Pod", metric["k8s_dst_type"])
		assert.Regexp(t,
			regexp.MustCompile("^test-kind-cluster-.*control-plane"),
			metric["k8s_dst_node_name"])
		assertIsIP(t, metric["k8s_dst_node_ip"])
		assert.Contains(t, svcSubnets, metric["src_cidr"], metric)
		assert.Contains(t, podSubnets, metric["dst_cidr"], metric)
		assert.Equal(t, "8080", metric["server_port"])
		assert.NotEqual(t, "8080", metric["client_port"])
	})

	// check that there aren't captured flows if there is no communication
	results, err := pq.Query(`beyla_network_flow_bytes_total{src_name="internal-pinger-net",dst_name="otherinstance"}`)
	require.NoError(t, err)
	require.Empty(t, results)

	// check that only TCP traffic is captured, according to the Protocols configuration option
	results, err = pq.Query(`beyla_network_flow_bytes_total`)
	require.NoError(t, err)
	require.NotEmpty(t, results)
	for _, result := range results {
		assert.Equal(t, "TCP", result.Metric["transport"])
	}

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
