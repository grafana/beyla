//go:build integration_k8s

package informer_cache

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/test/integration/components/docker"
	"github.com/grafana/beyla/test/integration/components/kube"
	"github.com/grafana/beyla/test/integration/components/prom"
	k8s "github.com/grafana/beyla/test/integration/k8s/common"
	otel "github.com/grafana/beyla/test/integration/k8s/netolly"
	"github.com/grafana/beyla/test/tools"
)

const (
	prometheusHostPort = "localhost:39090"
)

var cluster *kube.Kind

func TestMain(m *testing.M) {
	if err := docker.Build(os.Stdout, tools.ProjectDir(),
		docker.ImageBuild{Tag: "beyla:dev", Dockerfile: k8s.DockerfileBeyla},
		docker.ImageBuild{Tag: "testserver:dev", Dockerfile: k8s.DockerfileTestServer},
		docker.ImageBuild{Tag: "httppinger:dev", Dockerfile: k8s.DockerfileHTTPPinger},
		docker.ImageBuild{Tag: "beyla-k8s-cache:dev", Dockerfile: k8s.DockerfileBeylaK8sCache},
		docker.ImageBuild{Tag: "quay.io/prometheus/prometheus:v2.53.0"},
	); err != nil {
		slog.Error("can't build docker images", "error", err)
		os.Exit(-1)
	}

	cluster = kube.NewKind("test-kind-cluster-external-cache",
		kube.ExportLogs(k8s.PathKindLogs),
		kube.KindConfig(k8s.PathManifests+"/00-kind.yml"),
		kube.LocalImage("beyla:dev"),
		kube.LocalImage("testserver:dev"),
		kube.LocalImage("httppinger:dev"),
		kube.LocalImage("beyla-k8s-cache:dev"),
		kube.LocalImage("quay.io/prometheus/prometheus:v2.53.0"),
		kube.Deploy(k8s.PathManifests+"/01-volumes.yml"),
		kube.Deploy(k8s.PathManifests+"/01-serviceaccount.yml"),
		kube.Deploy(k8s.PathManifests+"/02-prometheus-promscrape.yml"),
		kube.Deploy(k8s.PathManifests+"/05-uninstrumented-service.yml"),
		kube.Deploy(k8s.PathManifests+"/06-beyla-external-informer.yml"),
	)

	cluster.Run(m)
}

// Run it alphabetically first (AA-prefix), with a longer timeout, to wait until all the components are up and
// traces/metrics are flowing normally
func TestInformersCache_MetricsDecoration_AA_WaitForComponents(t *testing.T) {
	k8s.DoWaitForComponentsAvailable(t)
}

func TestInformersCache_MetricsDecoration_HTTP(t *testing.T) {
	cluster.TestEnv().Test(t, k8s.FeatureHTTPMetricsDecoration(k8s.UninstrumentedPingerManifest,
		map[string]string{
			"server_service_namespace": "default",
			"k8s_cluster_name":         "my-kube",
		}))
}

func TestInformersCache_ProcessMetrics(t *testing.T) {
	cluster.TestEnv().Test(t, k8s.FeatureProcessMetricsDecoration(
		map[string]string{
			"k8s_cluster_name": "my-kube",
		}))
}

func TestInformersCache_NetworkMetrics(t *testing.T) {
	cluster.TestEnv().Test(t, otel.FeatureNetworkFlowBytes())
}

func TestInformersCache_InternalMetrics(t *testing.T) {
	require.NotZero(t, metricVal(t, `beyla_kube_cache_client_messages_total{status="submit"}`))
	require.NotZero(t, metricVal(t, `beyla_kube_cache_connected_clients`))
	require.NotZero(t, metricVal(t, `beyla_kube_cache_informer_events_total{type="new"}`))
	require.NotZero(t, metricVal(t, `beyla_kube_cache_informer_events_total{type="update"}`))
	require.NotZero(t, metricVal(t, `beyla_kube_cache_internal_build_info`))
}

func metricVal(t *testing.T, promQLQuery string) int {
	pq := prom.Client{HostPort: prometheusHostPort}

	results, err := pq.Query(promQLQuery)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Len(t, results[0].Value, 2)
	n, err := strconv.Atoi(fmt.Sprint(results[0].Value[1]))
	require.NoError(t, err)
	return n
}
