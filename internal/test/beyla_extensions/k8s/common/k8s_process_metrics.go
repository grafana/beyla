//go:build ignore

package k8s

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

	"github.com/grafana/beyla/v3/internal/test/integration/components/promtest"
)

var processMetrics = []string{
	"process_cpu_time_seconds_total",
	"process_cpu_utilization_ratio",
	"process_memory_usage_bytes",
	"process_memory_virtual_bytes",
	"process_disk_io_bytes_total",
	"process_network_io_bytes_total",
}

// FeatureProcessMetricsDecoration returns a feature that asserts process metrics
// (e.g. process_cpu_time_seconds_total) are decorated with the expected K8s
// attributes. overrideAttrs can override default expected attributes (e.g. for
// testing otherinstance instead of testserver); pass nil for defaults.
func FeatureProcessMetricsDecoration(overrideProperties map[string]string) features.Feature {
	properties := map[string]string{
		"k8s_namespace_name":  "^default$",
		"k8s_node_name":       ".+-control-plane$",
		"k8s_pod_name":        "^testserver-.*",
		"k8s_pod_uid":         UUIDRegex,
		"k8s_pod_start_time":  TimeRegex,
		"k8s_deployment_name": "^testserver$",
		"k8s_replicaset_name": "^testserver-",
		"k8s_cluster_name":    "^obi-k8s-test-cluster",
	}
	for k, v := range overrideProperties {
		properties[k] = v
	}
	return features.New("Process metrics decoration").
		Assess("process metrics are decorated with K8s attributes",
			processMetricsDecoration(processMetrics, `{k8s_pod_name=~"`+properties["k8s_pod_name"]+`"}`, properties)).
		Feature()
}

// FeatureSurveyMetricsDecoration returns a feature that asserts survey_info
// metrics are decorated with the expected K8s attributes. overrideAttrs can
// override default expected attributes; pass nil for defaults.
func FeatureSurveyMetricsDecoration(overrideProperties map[string]string) features.Feature {
	properties := map[string]string{
		"k8s_namespace_name":  "^default$",
		"k8s_node_name":       ".+-control-plane$",
		"k8s_pod_name":        "^testserver-.*",
		"k8s_pod_uid":         UUIDRegex,
		"k8s_pod_start_time":  TimeRegex,
		"k8s_deployment_name": "^testserver$",
		"k8s_replicaset_name": "^testserver-",
		"k8s_cluster_name":    "^obi-k8s-test-cluster",
	}
	for k, v := range overrideProperties {
		properties[k] = v
	}
	surveyMetrics := []string{"survey_info"}
	return features.New("Survey metrics decoration").
		Assess("survey_info metrics are decorated with K8s attributes",
			processMetricsDecoration(surveyMetrics, `{k8s_pod_name=~"`+properties["k8s_pod_name"]+`"}`, properties)).
		Feature()
}

func processMetricsDecoration(
	metricsSet []string, queryArgs string, expectedLabels map[string]string,
) features.Func {
	return func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
		pq := promtest.Client{HostPort: prometheusHostPort}
		for _, metric := range metricsSet {
			t.Run(metric, func(t *testing.T) {
				var results []promtest.Result
				require.EventuallyWithT(t, func(ct *assert.CollectT) {
					var err error
					results, err = pq.Query(metric + queryArgs)
					require.NoErrorf(ct, err, "failed to query Prometheus for metric %s", metric+queryArgs)
					require.NotEmptyf(ct, results, "no results for metric %s", metric+queryArgs)
				}, testTimeout, 100*time.Millisecond)

				for _, r := range results {
					for ek, ev := range expectedLabels {
						assert.Regexpf(t, ev, r.Metric[ek], "%s: expected %q:%q entry in map %v", metric, ek, ev, r.Metric)
					}
				}
			})
		}
		return ctx
	}
}
