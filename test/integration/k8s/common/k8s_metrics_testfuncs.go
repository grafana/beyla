//go:build integration

package k8s

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

	"github.com/grafana/beyla/test/integration/components/kube"
	"github.com/grafana/beyla/test/integration/components/prom"
)

// This file contains some functions and features that are accessed/used
// from diverse integration tests
const (
	testTimeout        = 2 * time.Minute
	prometheusHostPort = "localhost:39090"
)

var (
	httpServerMetrics = []string{
		"http_server_duration_seconds_count",
		"http_server_duration_seconds_sum",
		"http_server_duration_seconds_bucket",
		"http_server_request_size_bytes_count",
		"http_server_request_size_bytes_sum",
		"http_server_request_size_bytes_bucket",
	}
	httpClientMetrics = []string{
		"http_client_duration_seconds_count",
		"http_client_duration_seconds_sum",
		"http_client_duration_seconds_bucket",
		"http_client_request_size_bytes_count",
		"http_client_request_size_bytes_sum",
		"http_client_request_size_bytes_bucket",
	}
	grpcServerMetrics = []string{
		"rpc_server_duration_seconds_count",
		"rpc_server_duration_seconds_sum",
		"rpc_server_duration_seconds_bucket",
	}
	grpcClientMetrics = []string{
		"rpc_client_duration_seconds_count",
		"rpc_client_duration_seconds_sum",
		"rpc_client_duration_seconds_bucket",
	}
)

func DoTestHTTPMetricsDecorationExternalToPod(t *testing.T) {
	const (
		subpath = "/smoke"
		url     = "http://localhost:38080"
	)
	pq := prom.Client{HostPort: prometheusHostPort}
	var results []prom.Result
	test.Eventually(t, 4*testTimeout, func(t require.TestingT) {
		// first, verify that the test service endpoint is healthy
		r, err := http.Get(url + subpath)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, r.StatusCode)

		// now, verify that the metric has been reported.
		// we don't really care that this metric could be from a previous
		// test. Once one it is visible, it means that Otel and Prometheus are healthy
		results, err = pq.Query(`http_server_duration_seconds_count{http_target="` + subpath + `",k8s_dst_name="testserver"}`)
		require.NoError(t, err)
		require.NotZero(t, len(results))
	}, test.Interval(time.Second))

	for _, r := range results {
		assert.Equal(t, "default", r.Metric["k8s_dst_namespace"])
		assert.Equal(t, "Pod", r.Metric["k8s_dst_type"])

		assert.NotContains(t, r.Metric, "k8s_src_name")
		assert.NotContains(t, r.Metric, "k8s_src_namespace")
	}
}

func FeatureHTTPDecorationPod2Service() features.Feature {
	pinger := kube.Template[Pinger]{
		TemplateFile: PingerManifest,
		Data: Pinger{
			PodName:   "internal-pinger",
			TargetURL: "http://testserver:8080/iping",
		},
	}
	return features.New("Decoration of Pod-to-Service communications").
		Setup(pinger.Deploy()).
		Teardown(pinger.Delete()).
		Assess("all the server metrics are properly decorated",
			testMetricsDecoration(httpServerMetrics, `{http_target="/iping",k8s_src_name="internal-pinger"}`, map[string]string{
				"k8s_src_name":      "internal-pinger",
				"k8s_dst_name":      "testserver",
				"k8s_src_namespace": "default",
				"k8s_dst_namespace": "default",
				// data captured at the server side will be always "Pod" as destination type, as the
				// server Pod doesn't see the service URL but itself as a Pod
				"k8s_dst_type": "Pod",
			})).
		Assess("all the client metrics are properly decorated",
			testMetricsDecoration(httpClientMetrics, `{k8s_src_name="internal-pinger"}`, map[string]string{
				"k8s_src_name":      "internal-pinger",
				"k8s_dst_name":      "testserver",
				"k8s_src_namespace": "default",
				"k8s_dst_namespace": "default",
				"k8s_dst_type":      "Service",
			}),
		).Feature()
}

func FeatureHTTPClientMetricsDecorationPod2Pod() features.Feature {
	pinger := kube.Template[Pinger]{
		TemplateFile: PingerManifest,
		Data: Pinger{
			PodName: "ping-to-pod",
		},
	}
	return features.New("Client-side decoration of Pod-to-Pod direct communications").
		Setup(func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			testserver := getPodIP(ctx, t, cfg, "testserver", "default")
			// Setting the testserver Pod IP in the target URL of the pinger pod, to avoid going through a service
			pinger.Data.TargetURL = "http://" + testserver.Status.PodIP + ":8080/iping"
			return pinger.Deploy()(ctx, t, cfg)
		}).
		Teardown(pinger.Delete()).
		Assess("all the client metrics are properly decorated",
			testMetricsDecoration(httpClientMetrics, `{k8s_src_name="ping-to-pod"}`, map[string]string{
				"k8s_src_name":      "ping-to-pod",
				"k8s_dst_name":      "testserver",
				"k8s_src_namespace": "default",
				"k8s_dst_namespace": "default",
				"k8s_dst_type":      "Pod",
			}),
		).Feature()
}

func FeatureHTTPMetricsDecorationPod2External() features.Feature {
	pinger := kube.Template[Pinger]{
		TemplateFile: PingerManifest,
		Data: Pinger{
			PodName:   "ping-to-grafana",
			TargetURL: "https://grafana.com/",
		},
	}
	return features.New("Client-side decoration of Pod-to-External communications").
		Setup(pinger.Deploy()).
		Teardown(pinger.Delete()).
		Assess("all the client metrics are properly decorated",
			testMetricsDecoration(httpClientMetrics, `{k8s_src_name="ping-to-grafana"}`, map[string]string{
				"k8s_src_name":      "ping-to-grafana",
				"k8s_src_namespace": "default",
			},
				"k8s_dst_name", "k8s_dst_namespace", "k8s_dst_type"), // expected missing labels
		).Feature()
}

func FeatureGRPCMetricsDecorationPod2Service() features.Feature {
	pinger := kube.Template[Pinger]{
		TemplateFile: GrpcPingerManifest,
		Data: Pinger{
			PodName:   "internal-grpc-pinger",
			TargetURL: "testserver:50051",
		},
	}
	return features.New("Decoration of Pod-to-Service communications").
		Setup(pinger.Deploy()).
		Teardown(pinger.Delete()).
		Assess("all the server metrics are properly decorated",
			testMetricsDecoration(grpcServerMetrics, `{k8s_src_name="internal-grpc-pinger"}`, map[string]string{
				"k8s_src_name":      "internal-grpc-pinger",
				"k8s_dst_name":      "testserver",
				"k8s_src_namespace": "default",
				"k8s_dst_namespace": "default",
				// data captured at the server side will be always "Pod" as destination type, as the
				// server Pod doesn't see the service URL but itself as a Pod
				"k8s_dst_type": "Pod",
			})).
		Assess("all the client metrics are properly decorated",
			testMetricsDecoration(grpcClientMetrics, `{k8s_src_name="internal-grpc-pinger"}`, map[string]string{
				"k8s_src_name":      "internal-grpc-pinger",
				"k8s_dst_name":      "testserver",
				"k8s_src_namespace": "default",
				"k8s_dst_namespace": "default",
				"k8s_dst_type":      "Service",
			}),
		).Feature()
}

func FeatureGRPCMetricsDecorationPod2Pod() features.Feature {
	pinger := kube.Template[Pinger]{
		TemplateFile: GrpcPingerManifest,
		Data: Pinger{
			PodName: "internal-grpc-pinger-2pod",
		},
	}
	return features.New("Decoration of Pod-to-Service communications").
		Setup(func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			testserver := getPodIP(ctx, t, cfg, "testserver", "default")
			// Setting the testserver Pod IP in the target URL of the pinger pod, to avoid going through a service
			pinger.Data.TargetURL = testserver.Status.PodIP + ":50051"
			return pinger.Deploy()(ctx, t, cfg)
		}).
		Teardown(pinger.Delete()).
		Assess("all the server metrics are properly decorated",
			testMetricsDecoration(grpcServerMetrics, `{k8s_src_name="internal-grpc-pinger-2pod"}`, map[string]string{
				"k8s_src_name":      "internal-grpc-pinger-2pod",
				"k8s_dst_name":      "testserver",
				"k8s_src_namespace": "default",
				"k8s_dst_namespace": "default",
				// data captured at the server side will be always "Pod" as destination type, as the
				// server Pod doesn't see the service URL but itself as a Pod
				"k8s_dst_type": "Pod",
			})).
		Assess("all the client metrics are properly decorated",
			testMetricsDecoration(grpcClientMetrics, `{k8s_src_name="internal-grpc-pinger-2pod"}`, map[string]string{
				"k8s_src_name":      "internal-grpc-pinger-2pod",
				"k8s_dst_name":      "testserver",
				"k8s_src_namespace": "default",
				"k8s_dst_namespace": "default",
				"k8s_dst_type":      "Pod",
			}),
		).Feature()
}

func testMetricsDecoration(
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

func getPodIP(ctx context.Context, t *testing.T, cfg *envconf.Config, podName, podNS string) *v1.Pod {
	kclient, err := kubernetes.NewForConfig(cfg.Client().RESTConfig())
	require.NoError(t, err)
	testserver, err := kclient.CoreV1().Pods(podNS).Get(ctx, podName, metav1.GetOptions{})
	require.NoError(t, err)
	return testserver
}
