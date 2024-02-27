//go:build integration

package otel

import (
	"context"
	"net"
	"regexp"
	"testing"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

	"github.com/grafana/beyla/test/integration/components/kube"
	"github.com/grafana/beyla/test/integration/components/prom"
	k8s "github.com/grafana/beyla/test/integration/k8s/common"
)

func TestNetworkFlowBytes(t *testing.T) {
	pinger := kube.Template[k8s.Pinger]{
		TemplateFile: k8s.UninstrumentedPingerManifest,
		Data: k8s.Pinger{
			PodName:   "internal-pinger",
			TargetURL: "http://testserver:8080/iping",
		},
	}
	cluster.TestEnv().Test(t, features.New("network flow bytes").
		Setup(pinger.Deploy()).
		Teardown(pinger.Delete()).
		Assess("catches network metrics between connected pods", testNetFlowBytesForExistingConnections).
		Feature(),
	)
}

func testNetFlowBytesForExistingConnections(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	pq := prom.Client{HostPort: prometheusHostPort}

	// testing request flows (to testserver as Service)
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		results, err := pq.Query(`network_flow_bytes_total{src_name="internal-pinger",dst_name="testserver"}`)
		require.NoError(t, err)
		require.NotEmpty(t, results)

		// check that the metrics are properly decorated
		require.Len(t, results, 1)
		metric := results[0].Metric
		assertIsIP(t, metric["src_address"])
		assertIsIP(t, metric["dst_address"])
		assert.Equal(t, "my-kube", metric["cluster_name"])
		assert.Equal(t, "default", metric["src_namespace"])
		assert.Equal(t, "default", metric["dst_namespace"])
		assert.Equal(t, "beyla-network-flows", metric["job"])
		assert.Equal(t, "default", metric["k8s_src_namespace"])
		assert.Equal(t, "internal-pinger", metric["k8s_src_name"])
		assert.Equal(t, "Pod", metric["k8s_src_owner_type"])
		assert.Equal(t, "Pod", metric["k8s_src_type"])
		assert.Equal(t, "test-kind-cluster-netolly-control-plane",
			metric["k8s_src_host_name"])
		assertIsIP(t, metric["k8s_src_host_ip"])
		assert.Equal(t, "default", metric["k8s_dst_namespace"])
		assert.Equal(t, "testserver", metric["k8s_dst_name"])
		assert.Equal(t, "Service", metric["k8s_dst_owner_type"])
		assert.Equal(t, "Service", metric["k8s_dst_type"])
		// services don't have host IP or name
	})
	// testing request flows (to testserver as Pod)
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		results, err := pq.Query(`network_flow_bytes_total{src_name="internal-pinger",dst_name=~"testserver-.*"}`)
		require.NoError(t, err)
		require.NotEmpty(t, results)

		// check that the metrics are properly decorated
		require.Len(t, results, 1)
		metric := results[0].Metric
		assertIsIP(t, metric["src_address"])
		assertIsIP(t, metric["dst_address"])
		assert.Equal(t, "default", metric["src_namespace"])
		assert.Equal(t, "default", metric["dst_namespace"])
		assert.Equal(t, "beyla-network-flows", metric["job"])
		assert.Equal(t, "default", metric["k8s_src_namespace"])
		assert.Equal(t, "internal-pinger", metric["k8s_src_name"])
		assert.Equal(t, "Pod", metric["k8s_src_owner_type"])
		assert.Equal(t, "Pod", metric["k8s_src_type"])
		assert.Equal(t, "test-kind-cluster-netolly-control-plane",
			metric["k8s_src_host_name"])
		assertIsIP(t, metric["k8s_src_host_ip"])
		assert.Equal(t, "default", metric["k8s_dst_namespace"])
		assert.Regexp(t, regexp.MustCompile("^testserver-"), metric["k8s_dst_name"])
		assert.Equal(t, "Deployment", metric["k8s_dst_owner_type"])
		assert.Equal(t, "testserver", metric["k8s_dst_owner_name"])
		assert.Equal(t, "Pod", metric["k8s_dst_type"])
		assert.Equal(t, "test-kind-cluster-netolly-control-plane",
			metric["k8s_dst_host_name"])
		assertIsIP(t, metric["k8s_dst_host_ip"])
	})

	// testing response flows (from testserver Pod)
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		results, err := pq.Query(`network_flow_bytes_total{src_name=~"testserver-.*",dst_name="internal-pinger"}`)
		require.NoError(t, err)
		require.NotEmpty(t, results)

		// check that the metrics are properly decorated
		require.Len(t, results, 1)
		metric := results[0].Metric
		assertIsIP(t, metric["src_address"])
		assertIsIP(t, metric["dst_address"])
		assert.Equal(t, "default", metric["src_namespace"])
		assert.Equal(t, "default", metric["dst_namespace"])
		assert.Equal(t, "beyla-network-flows", metric["job"])
		assert.Equal(t, "default", metric["k8s_src_namespace"])
		assert.Regexp(t, regexp.MustCompile("^testserver-"), metric["k8s_src_name"])
		assert.Equal(t, "Deployment", metric["k8s_src_owner_type"])
		assert.Equal(t, "Pod", metric["k8s_src_type"])
		assert.Equal(t, "test-kind-cluster-netolly-control-plane", metric["k8s_src_host_name"])
		assertIsIP(t, metric["k8s_src_host_ip"])
		assert.Equal(t, "default", metric["k8s_dst_namespace"])
		assert.Equal(t, "internal-pinger", metric["k8s_dst_name"])
		assert.Equal(t, "Pod", metric["k8s_dst_owner_type"])
		assert.Equal(t, "Pod", metric["k8s_dst_type"])
		assert.Equal(t, "test-kind-cluster-netolly-control-plane", metric["k8s_dst_host_name"])
		assertIsIP(t, metric["k8s_dst_host_ip"])
	})

	// testing response flows (from testserver Service)
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		results, err := pq.Query(`network_flow_bytes_total{src_name="testserver",dst_name="internal-pinger"}`)
		require.NoError(t, err)
		require.NotEmpty(t, results)

		// check that the metrics are properly decorated
		require.Len(t, results, 1)
		metric := results[0].Metric
		assertIsIP(t, metric["src_address"])
		assertIsIP(t, metric["dst_address"])
		assert.Equal(t, "default", metric["src_namespace"])
		assert.Equal(t, "default", metric["dst_namespace"])
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
		assert.Equal(t, "test-kind-cluster-netolly-control-plane", metric["k8s_dst_host_name"])
		assertIsIP(t, metric["k8s_dst_host_ip"])
	})

	// check that there aren't captured flows if there is no communication
	results, err := pq.Query(`network_flow_bytes_total{src_name="internal-pinger",dst_name="otherinstance"}`)
	require.NoError(t, err)
	require.Empty(t, results)

	return ctx
}

func assertIsIP(t require.TestingT, str string) {
	if net.ParseIP(str) == nil {
		assert.Failf(t, "error parsing IP address", "expected IP. Got %s", str)
	}
}
