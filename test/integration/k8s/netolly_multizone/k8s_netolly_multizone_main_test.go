//go:build integration_k8s

package otel

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

	"github.com/grafana/beyla/test/integration/components/docker"
	"github.com/grafana/beyla/test/integration/components/kube"
	"github.com/grafana/beyla/test/integration/components/prom"
	k8s "github.com/grafana/beyla/test/integration/k8s/common"
	"github.com/grafana/beyla/test/integration/k8s/common/testpath"
	"github.com/grafana/beyla/test/tools"
)

const (
	testTimeout        = 3 * time.Minute
	prometheusHostPort = "localhost:39090"
)

var cluster *kube.Kind

func TestMain(m *testing.M) {
	if err := docker.Build(os.Stdout, tools.ProjectDir(),
		docker.ImageBuild{Tag: "testserver:dev", Dockerfile: k8s.DockerfileTestServer},
		docker.ImageBuild{Tag: "beyla:dev", Dockerfile: k8s.DockerfileBeyla},
		docker.ImageBuild{Tag: "httppinger:dev", Dockerfile: k8s.DockerfileHTTPPinger},
		docker.ImageBuild{Tag: "quay.io/prometheus/prometheus:v2.53.0"},
		docker.ImageBuild{Tag: "otel/opentelemetry-collector-contrib:0.103.0"},
	); err != nil {
		slog.Error("can't build docker images", "error", err)
		os.Exit(-1)
	}

	cluster = kube.NewKind("test-kind-cluster-netolly-multizone",
		kube.KindConfig(testpath.Manifests+"/00-kind-multi-zone.yml"),
		kube.LocalImage("testserver:dev"),
		kube.LocalImage("beyla:dev"),
		kube.LocalImage("httppinger:dev"),
		kube.LocalImage("quay.io/prometheus/prometheus:v2.53.0"),
		kube.LocalImage("otel/opentelemetry-collector-contrib:0.103.0"),
		kube.Deploy(testpath.Manifests+"/01-volumes.yml"),
		kube.Deploy(testpath.Manifests+"/01-serviceaccount.yml"),
		kube.Deploy(testpath.Manifests+"/02-prometheus-otelscrape-multi-node.yml"),
		kube.Deploy(testpath.Manifests+"/03-otelcol-multi-node.yml"),
		kube.Deploy(testpath.Manifests+"/05-uninstrumented-multizone-client-server.yml"),
		kube.Deploy(testpath.Manifests+"/06-beyla-netolly-multizone.yml"),
	)

	cluster.Run(m)
}

func TestMultizoneNetworkFlows(t *testing.T) {
	cluster.TestEnv().Test(t, FeatureMultizoneNetworkFlows())
}

func FeatureMultizoneNetworkFlows() features.Feature {
	return features.New("Multizone Network flows").
		Assess("flows are decorated with zone", testFlowsDecoratedWithZone).
		Assess("interzone bytes are reported as their own metric", testInterZoneMetric).
		Feature()
}

func testFlowsDecoratedWithZone(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	pq := prom.Client{HostPort: prometheusHostPort}

	// checking pod-to-pod node communication (request)
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		results, err := pq.Query(`beyla_network_flow_bytes_total{` +
			`k8s_src_name="httppinger",k8s_dst_name=~"testserver.*",` +
			`k8s_src_type="Pod",k8s_dst_type="Pod"` +
			`}`)
		require.NoError(t, err)
		require.NotEmpty(t, results)

		// check that the metrics are properly decorated
		// should have 2 exact metrics, measured from Beyla instances in both nodes
		require.GreaterOrEqual(t, len(results), 2)
		for _, res := range results {
			assert.Equal(t, "client-zone", res.Metric["src_zone"])
			assert.Equal(t, "server-zone", res.Metric["dst_zone"])
		}
	})
	// checking pod-to-pod node communication (response)
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		results, err := pq.Query(`beyla_network_flow_bytes_total{` +
			`k8s_dst_name="httppinger",k8s_src_name=~"testserver.*",` +
			`k8s_src_type="Pod",k8s_dst_type="Pod"` +
			`}`)
		require.NoError(t, err)
		require.NotEmpty(t, results)

		// check that the metrics are properly decorated
		// should have 2 exact metrics, measured from Beyla instances in both nodes
		require.GreaterOrEqual(t, len(results), 2)
		for _, res := range results {
			assert.Equal(t, "server-zone", res.Metric["src_zone"])
			assert.Equal(t, "client-zone", res.Metric["dst_zone"])
		}
	})

	// checking node-to-node communication (e.g between control plane and workers)
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		results, err := pq.Query(`beyla_network_flow_bytes_total{` +
			`src_zone="server-zone",dst_zone="control-plane-zone",` +
			`k8s_src_type="Node",k8s_dst_type="Node"` +
			`}`)
		require.NoError(t, err)
		require.NotEmpty(t, results)

		// check that the metrics are properly decorated
		// should have 2 exact metrics, measured from Beyla instances in both nodes
		require.GreaterOrEqual(t, len(results), 2)
	})
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		results, err := pq.Query(`beyla_network_flow_bytes_total{` +
			`dst_zone="server-zone",src_zone="control-plane-zone",` +
			`k8s_src_type="Node",k8s_dst_type="Node"` +
			`}`)
		require.NoError(t, err)
		require.NotEmpty(t, results)

		// check that the metrics are properly decorated
		// should have 2 exact metrics, measured from Beyla instances in both nodes
		require.GreaterOrEqual(t, len(results), 2)
	})
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		results, err := pq.Query(`beyla_network_flow_bytes_total{` +
			`src_zone="client-zone",dst_zone="control-plane-zone",` +
			`k8s_src_type="Node",k8s_dst_type="Node"` +
			`}`)
		require.NoError(t, err)
		require.NotEmpty(t, results)

		// check that the metrics are properly decorated
		// should have 2 exact metrics, measured from Beyla instances in both nodes
		require.GreaterOrEqual(t, len(results), 2)
	})
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		results, err := pq.Query(`beyla_network_flow_bytes_total{` +
			`dst_zone="client-zone",src_zone="control-plane-zone",` +
			`k8s_src_type="Node",k8s_dst_type="Node"` +
			`}`)
		require.NoError(t, err)
		require.NotEmpty(t, results)

		// check that the metrics are properly decorated
		// should have 2 exact metrics, measured from Beyla instances in both nodes
		require.GreaterOrEqual(t, len(results), 2)
	})
	return ctx
}

func testInterZoneMetric(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	pq := prom.Client{HostPort: prometheusHostPort}

	// inter-zone bytes are reported
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		results, err := pq.Query(`beyla_network_inter_zone_bytes_total{` +
			`src_zone="client-zone", dst_zone="server-zone"}`)
		require.NoError(t, err)
		require.NotEmpty(t, results)
	})
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		results, err := pq.Query(`beyla_network_inter_zone_bytes_total{` +
			`dst_zone="client-zone", src_zone="server-zone"}`)
		require.NoError(t, err)
		require.NotEmpty(t, results)
		// AND the reported attributes are different from the flow bytes attributes
		require.NotContains(t, results, "k8s_src_type")
		require.NotContains(t, results, "iface_direction")
	})

	// BUT same-zone bytes are not reported in this metric
	results, err := pq.Query(`beyla_network_inter_zone_bytes_total{` +
		`src_zone="client-zone", dst_zone="client-zone"}`)
	require.NoError(t, err)
	require.Empty(t, results)
	results, err = pq.Query(`beyla_network_inter_zone_bytes_total{` +
		`src_zone="server-zone", dst_zone="server-zone"}`)
	require.NoError(t, err)
	require.Empty(t, results)

	return ctx
}
