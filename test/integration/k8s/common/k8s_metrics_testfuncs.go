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

	UUIDRegex = `^[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}$`
	TimeRegex = `^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d`
)

var (
	httpServerMetrics = []string{
		"http_server_request_duration_seconds_count",
		"http_server_request_duration_seconds_sum",
		"http_server_request_duration_seconds_bucket",
		"http_server_request_body_size_bytes_count",
		"http_server_request_body_size_bytes_sum",
		"http_server_request_body_size_bytes_bucket",
	}
	httpClientMetrics = []string{
		"http_client_request_duration_seconds_count",
		"http_client_request_duration_seconds_sum",
		"http_client_request_duration_seconds_bucket",
		"http_client_request_body_size_bytes_count",
		"http_client_request_body_size_bytes_sum",
		"http_client_request_body_size_bytes_bucket",
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

func DoWaitForComponentsAvailable(t *testing.T) {
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
		results, err = pq.Query(`http_server_request_duration_seconds_count{url_path="` + subpath + `",k8s_pod_name=~"testserver-.*"}`)
		require.NoError(t, err)
		require.NotEmpty(t, results)
	}, test.Interval(time.Second))
}

func FeatureHTTPMetricsDecoration() features.Feature {
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
		Assess("all the client metrics are properly decorated",
			testMetricsDecoration(httpClientMetrics, `{k8s_pod_name="internal-pinger"}`, map[string]string{
				"k8s_namespace_name": "^default$",
				"k8s_node_name":      ".+-control-plane$",
				"k8s_pod_uid":        UUIDRegex,
				"k8s_pod_start_time": TimeRegex,
			}, "k8s_deployment_name")).
		Assess("all the server metrics are properly decorated",
			testMetricsDecoration(httpServerMetrics, `{url_path="/iping",k8s_pod_name=~"testserver-.*"}`, map[string]string{
				"k8s_namespace_name":  "^default$",
				"k8s_node_name":       ".+-control-plane$",
				"k8s_pod_uid":         UUIDRegex,
				"k8s_pod_start_time":  TimeRegex,
				"k8s_deployment_name": "^testserver$",
				"k8s_replicaset_name": "^testserver-",
			}),
		).Feature()
}

func FeatureGRPCMetricsDecoration() features.Feature {
	pinger := kube.Template[Pinger]{
		TemplateFile: GrpcPingerManifest,
		Data: Pinger{
			PodName:   "internal-grpc-pinger",
			TargetURL: "testserver:5051",
		},
	}
	return features.New("Decoration of Pod-to-Service communications").
		Setup(pinger.Deploy()).
		Teardown(pinger.Delete()).
		Assess("all the client metrics are properly decorated",
			testMetricsDecoration(grpcClientMetrics, `{k8s_pod_name="internal-grpc-pinger"}`, map[string]string{
				"k8s_namespace_name": "^default$",
				"k8s_node_name":      ".+-control-plane$",
				"k8s_pod_uid":        UUIDRegex,
				"k8s_pod_start_time": TimeRegex,
			}, "k8s_deployment_name")).
		Assess("all the server metrics are properly decorated",
			testMetricsDecoration(grpcServerMetrics, `{k8s_pod_name=~"testserver-.*"}`, map[string]string{
				"k8s_namespace_name":  "^default$",
				"k8s_node_name":       ".+-control-plane$",
				"k8s_pod_uid":         UUIDRegex,
				"k8s_pod_start_time":  TimeRegex,
				"k8s_deployment_name": "^testserver$",
				"k8s_replicaset_name": "^testserver-",
			}),
		).Feature()
}

func testMetricsDecoration(
	metricsSet []string, queryArgs string, expectedLabels map[string]string, expectedMissingLabels ...string,
) features.Func {
	return func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
		// Testing the decoration of the server-side HTTP calls from the internal-pinger pod
		pq := prom.Client{HostPort: prometheusHostPort}
		for _, metric := range metricsSet {
			t.Run(metric, func(t *testing.T) {
				var results []prom.Result
				test.Eventually(t, testTimeout, func(t require.TestingT) {
					var err error
					results, err = pq.Query(metric + queryArgs)
					require.NoError(t, err)
					require.NotEmpty(t, results)
				})

				for _, r := range results {
					for ek, ev := range expectedLabels {
						assert.Regexpf(t, ev, r.Metric[ek], "%s: expected %q:%q entry in map %v", metric, ek, ev, r.Metric)
					}
					for _, ek := range expectedMissingLabels {
						assert.NotContainsf(t, r.Metric, ek, "%s: not expected %q entry in map %v", metric, ek, r.Metric)
					}
				}
			})
		}
		return ctx
	}
}
