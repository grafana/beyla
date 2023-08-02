//go:build integration

package k8s

import (
	"bytes"
	"context"
	"crypto/tls"
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
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

	"github.com/grafana/ebpf-autoinstrument/test/integration/components/docker"
	"github.com/grafana/ebpf-autoinstrument/test/integration/components/kube"
	"github.com/grafana/ebpf-autoinstrument/test/integration/components/prom"
)

const (
	prometheusHostPort = "localhost:39090"

	httpTargetURLEnvName = "HTTP_TARGET_URL"
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
	pinger := Pinger{
		ManifestTemplate: "manifests/06-instrumented-client.template.yml",
		PodName:          "internal-pinger",
		TargetURL:        "http://testserver:8080/iping",
	}
	feat := features.New("Server decoration of Pod-to-Pod direct communications").
		Setup(pinger.deploy).
		Teardown(pinger.undeploy).
		Assess("all the metrics are properly decorated",
			testDecoration(serverMetrics, `{http_target="/iping",k8s_src_name="internal-pinger"}`, map[string]string{
				"k8s_src_name":      "internal-pinger",
				"k8s_dst_name":      "testserver",
				"k8s_src_namespace": "default",
				"k8s_dst_namespace": "default",
				"k8s_dst_type":      "Pod",
			}),
		).Feature()

	cluster.TestEnv().Test(t, feat)
}

func TestClientDecoration_Pod2Service(t *testing.T) {
	feat := features.New("Server decoration of Pod-to-Pod direct communications").
		//Setup(pinger.deploy).
		//Teardown(pinger.undeploy).
		Assess("all the metrics are properly decorated",
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

/*
	func TestClientDecoration_Pod2Pod(t *testing.T) {
		var oldPingerURL string

		feat := features.New("Client decoration of Pod-to-Pod direct communications").
			Setup(func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
				// change the target URL of the internal pinger to point to the pod IP instead of the service behind it
				kclient, err := kubernetes.NewForConfig(cfg.Client().RESTConfig())
				require.NoError(t, err)
				// Get the testserver IP address
				p, err := kclient.CoreV1().Pods("default").Get(ctx, "testserver", metav1.GetOptions{})
				require.NotZero(t, err)
				podIp := p.Status.PodIP
				// Replace the Pinger target URL by the pod IP instead of the hostname
				cm, err := kclient.CoreV1().ConfigMaps("default").Get(ctx, "pinger-env", metav1.GetOptions{})
				require.NotZero(t, err)
				oldPingerURL = cm.Data[httpTargetURLEnvName]
				require.NotEmpty(t, oldPingerURL)
				cm.Data[httpTargetURLEnvName] = podIp
				_, err = kclient.CoreV1().ConfigMaps("default").Update(ctx, cm, metav1.UpdateOptions{})
				require.NoError(t, err)
				// Restart pinger so changes take effect
				p, err = kclient.CoreV1().Pods("default").Get(ctx, "internal-pinger", metav1.GetOptions{})
				require.NoError(t, err)
				p.Labels["restart"] = strconv.Itoa(rand.Int())
				return ctx
			}).Teardown(func(ctx context.Context, t *testing.T, config *envconf.Config) context.Context {
			// Restore old Pinger URL
			return ctx
		}).Feature()

		cluster.TestEnv().Test(t, feat)

		testDecoration()
	}
*/
func testDecoration(metricsSet []string, queryArgs string, expectedLabels map[string]string) features.Func {
	return func(ctx context.Context, t *testing.T, config *envconf.Config) context.Context {
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

	kclient, err := kubernetes.NewForConfig(cfg.Client().RESTConfig())
	require.NoError(t, err)
	require.NoError(t, kube.DeployManifest(ping.compiledManifest, cfg, kclient))

	return ctx
}

func (ping *Pinger) undeploy(ctx context.Context, t *testing.T, config *envconf.Config) context.Context {

	return ctx
}
