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
	"process_resident_memory_bytes",
}

// FeatureProcessMetricsDecoration returns a feature that asserts process metrics
// (e.g. process_cpu_time_seconds_total) are decorated with the expected K8s
// attributes. overrideAttrs can override default expected attributes (e.g. for
// testing otherinstance instead of testserver); pass nil for defaults.
func FeatureProcessMetricsDecoration(overrideAttrs map[string]string) features.Feature {
	allAttributes := map[string]string{
		"k8s_namespace_name":     "^default$",
		"k8s_node_name":         ".+-control-plane$",
		"k8s_pod_uid":           UUIDRegex,
		"k8s_pod_start_time":    TimeRegex,
		"k8s_owner_name":        "^testserver$",
		"k8s_deployment_name":   "^testserver$",
		"k8s_replicaset_name":   "^testserver-",
		"k8s_cluster_name":      "^obi-k8s-test-cluster$",
		"service_instance_id":   "^default\\.testserver-.+\\.testserver",
		"deployment_environment": "integration-test",
		"service_version":       "3.2.1",
	}
	attrs := attributeMap(allAttributes, overrideAttrs,
		"k8s_namespace_name",
		"k8s_node_name",
		"k8s_pod_uid",
		"k8s_pod_start_time",
		"k8s_owner_name",
		"k8s_deployment_name",
		"k8s_replicaset_name",
		"k8s_cluster_name",
		"service_instance_id",
		"deployment_environment",
		"service_version",
	)
	queryArgs := `{k8s_pod_name=~"testserver-.*"}`
	if overrideAttrs != nil {
		if podName, ok := overrideAttrs["k8s_pod_name"]; ok {
			// Strip leading ^ for Prometheus regex (e.g. "^otherinstance-.*" -> "otherinstance-.*")
			if len(podName) > 0 && podName[0] == '^' {
				podName = podName[1:]
			}
			queryArgs = `{k8s_pod_name=~"` + podName + `"}`
		}
	}
	return features.New("Process metrics decoration").
		Assess("process metrics are decorated with K8s attributes",
			processMetricsDecoration(processMetrics, queryArgs, attrs)).
		Feature()
}

// FeatureSurveyMetricsDecoration returns a feature that asserts survey_info
// metrics are decorated with the expected K8s attributes. overrideAttrs can
// override default expected attributes; pass nil for defaults.
func FeatureSurveyMetricsDecoration(overrideAttrs map[string]string) features.Feature {
	allAttributes := map[string]string{
		"k8s_namespace_name":     "^default$",
		"k8s_node_name":          ".+-control-plane$",
		"k8s_pod_uid":            UUIDRegex,
		"k8s_pod_start_time":     TimeRegex,
		"k8s_owner_name":         "^testserver$",
		"k8s_deployment_name":    "^testserver$",
		"k8s_replicaset_name":    "^testserver-",
		"k8s_cluster_name":      "^obi-k8s-test-cluster$",
		"k8s_kind":               "Deployment",
		"service_instance_id":    "^default\\.testserver-.+\\.testserver",
		"deployment_environment": "integration-test",
		"service_version":        "3.2.1",
	}
	attrs := attributeMap(allAttributes, overrideAttrs,
		"k8s_namespace_name",
		"k8s_node_name",
		"k8s_pod_uid",
		"k8s_pod_start_time",
		"k8s_owner_name",
		"k8s_deployment_name",
		"k8s_replicaset_name",
		"k8s_cluster_name",
		"k8s_kind",
		"service_instance_id",
		"deployment_environment",
		"service_version",
	)
	queryArgs := `{k8s_pod_name=~"testserver-.*"}`
	if overrideAttrs != nil {
		if podName, ok := overrideAttrs["k8s_pod_name"]; ok {
			if len(podName) > 0 && podName[0] == '^' {
				podName = podName[1:]
			}
			queryArgs = `{k8s_pod_name=~"` + podName + `"}`
		}
	}
	surveyMetrics := []string{"beyla_survey_info"}
	return features.New("Survey metrics decoration").
		Assess("survey_info metrics are decorated with K8s attributes",
			processMetricsDecoration(surveyMetrics, queryArgs, attrs)).
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
