//go:build integration

package k8s

import (
	"crypto/tls"
	"net/http"
	"os"
	"path"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/slog"

	"github.com/grafana/ebpf-autoinstrument/test/integration/components/docker"
	"github.com/grafana/ebpf-autoinstrument/test/integration/components/kube"
	"github.com/grafana/ebpf-autoinstrument/test/integration/components/prom"
)

const (
	prometheusHostPort = "localhost:39090"
)

var (
	pathRoot     = path.Join("..", "..", "..")
	pathOutput   = path.Join(pathRoot, "testoutput")
	pathKindLogs = path.Join(pathOutput, "kind")

	tr             = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	testHTTPClient = &http.Client{Transport: tr}
)

var cluster *kube.Kind

func TestMain(m *testing.M) {
	if err := docker.Build(os.Stdout, "../../..",
		docker.ImageBuild{Tag: "testserver:dev", Dockerfile: "../components/testserver/Dockerfile"},
		docker.ImageBuild{Tag: "beyla:dev", Dockerfile: "../components/beyla/Dockerfile"},
	); err != nil {
		slog.Error("can't build docker images", err)
		os.Exit(-1)
	}

	cluster = kube.NewKind("test-kind-cluster",
		kube.ExportLogs(pathKindLogs),
		kube.KindConfig("manifests/00-kind.yml"),
		kube.LocalImage("testserver:dev"),
		kube.LocalImage("beyla:dev"),
		kube.Deploy("manifests/01-volumes.yml"),
		kube.Deploy("manifests/02-prometheus.yml"),
		kube.Deploy("manifests/03-otelcol.yml"),
		kube.Deploy("manifests/04-jaeger.yml"),
		kube.Deploy("manifests/05-instrumented-service.yml"),
		kube.Deploy("manifests/06-instrumented-client.yml"),
	)

	cluster.Run(m)
}

// Run it alphabetically first to wait until all the components are up and
// traces/metrics are flowing normally
func TestAASmoke(t *testing.T) {
	const (
		subpath = "/smoke"
		url     = "http://localhost:38080"
	)
	pq := prom.Client{HostPort: prometheusHostPort}
	test.Eventually(t, 2*time.Minute, func(t require.TestingT) {
		// first, verify that the test service endpoint is healthy
		req, err := http.NewRequest("GET", url+subpath, nil)
		require.NoError(t, err)
		r, err := testHTTPClient.Do(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, r.StatusCode)

		// now, verify that the metric has been reported.
		// we don't really care that this metric could be from a previous
		// test. Once one it is visible, it means that Otel and Prometheus are healthy
		results, err := pq.Query(`http_server_duration_seconds_count{http_target="` + subpath + `"}`)
		require.NoError(t, err)
		require.NotZero(t, len(results))
	}, test.Interval(time.Second))
}

var (
	serverMetrics = []string{
		"http_server_duration_seconds_count",
		"http_server_duration_seconds_sum",
		"http_server_duration_seconds_bucket",
		"http_server_request_size_bytes_count",
		"http_server_request_size_bytes_sum",
		"http_server_request_size_bytes_bucket",
	}
	clientMetrics = []string{
		"http_client_duration_seconds_count",
		"http_client_duration_seconds_sum",
		"http_client_duration_seconds_bucket",
		"http_client_request_size_bytes_count",
		"http_client_request_size_bytes_sum",
		"http_client_request_size_bytes_bucket",
	}
)

func TestServerDecoration_Pod2Pod(t *testing.T) {
	testDecoration(t, serverMetrics, `{http_target="/iping",k8s_src_name="internal-pinger"}`, map[string]string{
		"k8s_src_name":      "internal-pinger",
		"k8s_dst_name":      "testserver",
		"k8s_src_namespace": "default",
		"k8s_dst_namespace": "default",
		"k8s_dst_type":      "Pod",
	})
}

func TestClientDecoration_Pod2Service(t *testing.T) {
	testDecoration(t, clientMetrics, `{k8s_src_name="internal-pinger"}`, map[string]string{
		"k8s_src_name":      "internal-pinger",
		"k8s_dst_name":      "testserver",
		"k8s_src_namespace": "default",
		"k8s_dst_namespace": "default",
		"k8s_dst_type":      "Service",
	})
}

func testDecoration(t *testing.T, metricsSet []string, queryArgs string, expectedLabels map[string]string) {
	// Testing the decoration of the server-side HTTP calls from the internal-pinger pod
	pq := prom.Client{HostPort: prometheusHostPort}
	for _, metric := range metricsSet {
		t.Run(metric, func(t *testing.T) {
			var results []prom.Result
			test.Eventually(t, 30*time.Second, func(t require.TestingT) {
				var err error
				results, err = pq.Query(metric + queryArgs)
				require.NoError(t, err)
				require.NotZero(t, len(results))
			})

			for _, r := range results {
				for ek, ev := range expectedLabels {
					assert.Equalf(t, ev, r.Metric[ek], "expected %q:%q entry in map %v", ek, ev, r.Metric)
				}
			}
		})
	}
}
