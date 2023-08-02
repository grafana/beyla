//go:build integration

package k8s

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"path"
	"testing"
	"text/template"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/slog"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

	"github.com/grafana/ebpf-autoinstrument/test/integration/components/docker"
	"github.com/grafana/ebpf-autoinstrument/test/integration/components/kube"
	"github.com/grafana/ebpf-autoinstrument/test/integration/components/prom"
)

const (
	testTimeout = 30 * time.Second

	prometheusHostPort = "localhost:39090"

	pingerManifest = "manifests/06-instrumented-client.template.yml"
)

var (
	pathRoot     = path.Join("..", "..", "..")
	pathOutput   = path.Join(pathRoot, "testoutput")
	pathKindLogs = path.Join(pathOutput, "kind")

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
		r, err := http.Get(url + subpath)
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

func TestDecoration_Pod2Service(t *testing.T) {
	pinger := Pinger{
		ManifestTemplate: pingerManifest,
		PodName:          "internal-pinger",
		TargetURL:        "http://testserver:8080/iping",
	}
	feat := features.New("Decoration of Pod-to-Service communications").
		Setup(pinger.deploy).
		Teardown(pinger.undeploy).
		Assess("all the server metrics are properly decorated",
			testDecoration(serverMetrics, `{http_target="/iping",k8s_src_name="internal-pinger"}`, map[string]string{
				"k8s_src_name":      "internal-pinger",
				"k8s_dst_name":      "testserver",
				"k8s_src_namespace": "default",
				"k8s_dst_namespace": "default",
				// data captured at the server side will be always "Pod" as destination type, as the
				// server Pod doesn't see the service URL but itself as a Pod
				"k8s_dst_type": "Pod",
			})).
		Assess("all the client metrics are properly decorated",
			testDecoration(clientMetrics, `{k8s_src_name="internal-pinger"}`, map[string]string{
				"k8s_src_name":      "internal-pinger",
				"k8s_dst_name":      "testserver",
				"k8s_src_namespace": "default",
				"k8s_dst_namespace": "default",
				"k8s_dst_type":      "Service",
			}),
		).Feature()

	cluster.TestEnv().Test(t, feat)
}

func TestClientDecoration_Pod2Pod(t *testing.T) {
	pinger := Pinger{
		ManifestTemplate: pingerManifest,
		PodName:          "ping-to-pod",
	}
	feat := features.New("Client-side decoration of Pod-to-Pod direct communications").
		Setup(func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			kclient, err := kubernetes.NewForConfig(cfg.Client().RESTConfig())
			require.NoError(t, err)
			// First, get the testserver IP address
			testserver, err := kclient.CoreV1().Pods("default").Get(ctx, "testserver", metav1.GetOptions{})
			require.NoError(t, err)
			// Then we use it in the target URL of the pinger pod, to avoid going through a service
			pinger.TargetURL = "http://" + testserver.Status.PodIP + ":8080/iping"

			return pinger.deploy(ctx, t, cfg)
		}).
		Teardown(pinger.undeploy).
		Assess("all the client metrics are properly decorated",
			testDecoration(clientMetrics, `{k8s_src_name="ping-to-pod"}`, map[string]string{
				"k8s_src_name":      "ping-to-pod",
				"k8s_dst_name":      "testserver",
				"k8s_src_namespace": "default",
				"k8s_dst_namespace": "default",
				"k8s_dst_type":      "Pod",
			}),
		).Feature()

	cluster.TestEnv().Test(t, feat)
}

func TestDecoration_Pod2External(t *testing.T) {
	pinger := Pinger{
		ManifestTemplate: pingerManifest,
		PodName:          "ping-to-grafana",
		TargetURL:        "https://grafana.com/",
	}
	feat := features.New("Client-side decoration of Pod-to-External communications").
		Setup(pinger.deploy).
		Teardown(pinger.undeploy).
		Assess("all the client metrics are properly decorated",
			testDecoration(clientMetrics, `{k8s_src_name="ping-to-grafana"}`, map[string]string{
				"k8s_src_name":      "ping-to-grafana",
				"k8s_src_namespace": "default",
			},
				"k8s_dst_name", "k8s_dst_namespace", "k8s_dst_type"), // expected missing labels
		).Feature()
	cluster.TestEnv().Test(t, feat)
}

func testDecoration(
	metricsSet []string, queryArgs string, expectedLabels map[string]string, expectedMissingLabels ...string,
) features.Func {
	return func(ctx context.Context, t *testing.T, config *envconf.Config) context.Context {
		// Testing the decoration of the server-side HTTP calls from the internal-pinger pod
		pq := prom.Client{HostPort: prometheusHostPort}
		for _, metric := range metricsSet {
			t.Run(metric, func(t *testing.T) {
				var results []prom.Result
				test.Eventually(t, testTimeout, func(t require.TestingT) {
					var err error
					results, err = pq.Query(metric + queryArgs)
					require.NoError(t, err)
					require.NotZero(t, len(results))
				})

				for _, r := range results {
					for ek, ev := range expectedLabels {
						assert.Equalf(t, ev, r.Metric[ek], "expected %q:%q entry in map %v", ek, ev, r.Metric)
					}
					for _, ek := range expectedMissingLabels {
						assert.NotContainsf(t, r.Metric, ek, "not expected %q entry in map %v", ek, r.Metric)
					}
				}
			})
		}
		return ctx
	}
}

type Pinger struct {
	ManifestTemplate string
	PodName          string
	TargetURL        string

	compiledManifest string
}

func (ping *Pinger) deploy(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
	tmpl, err := template.ParseFiles(ping.ManifestTemplate)
	require.NoError(t, err)
	compiled := &bytes.Buffer{}
	require.NoError(t, tmpl.Execute(compiled, ping))
	ping.compiledManifest = compiled.String()

	require.NoError(t, kube.DeployManifest(cfg, ping.compiledManifest))
	return ctx
}

func (ping *Pinger) undeploy(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
	kclient, err := kubernetes.NewForConfig(cfg.Client().RESTConfig())
	require.NoError(t, err)

	delSelector := metav1.ListOptions{LabelSelector: "component=pinger"}
	require.NoError(t, kclient.CoreV1().Pods("default").DeleteCollection(ctx, metav1.DeleteOptions{}, delSelector))
	require.NoError(t, kclient.CoreV1().ConfigMaps("default").DeleteCollection(ctx, metav1.DeleteOptions{}, delSelector))

	return ctx
}
