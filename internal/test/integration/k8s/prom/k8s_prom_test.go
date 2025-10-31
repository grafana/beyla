//go:build integration_k8s

package prom

import (
	"testing"

	k8s "github.com/grafana/beyla/v2/internal/test/integration/k8s/common"
)

// Run it alphabetically first (AA-prefix), with a longer timeout, to wait until all the components are up and
// traces/metrics are flowing normally
func TestPrometheus_MetricsDecoration_AA_WaitForComponents(t *testing.T) {
	k8s.DoWaitForComponentsAvailable(t)
}

func TestPrometheus_MetricsDecoration_HTTP(t *testing.T) {
	cluster.TestEnv().Test(t, k8s.FeatureHTTPMetricsDecoration(k8s.PingerManifestProm, map[string]string{
		// service_instance_id is reported in target_info for prometheus metrics. Will check in another test
		"service_instance_id": "",
		"component":           "pinger",
	}))
}

func TestPrometheus_MetricsDecoration_GRPC(t *testing.T) {
	cluster.TestEnv().Test(t, k8s.FeatureGRPCMetricsDecoration(k8s.GrpcPingerManifestProm, map[string]string{
		// service_instance_id is reported in target_info for prometheus metrics. Will check in another test
		"service_instance_id": "",
	}))
}

func TestPrometheus_ProcessMetrics(t *testing.T) {
	cluster.TestEnv().Test(t, k8s.FeatureProcessMetricsDecoration(nil))
}

func TestPrometheus_SurveyMetrics(t *testing.T) {
	cluster.TestEnv().Test(t, k8s.FeatureSurveyMetricsDecoration(map[string]string{
		"k8s_namespace_name":  "^default$",
		"k8s_node_name":       ".+-control-plane$",
		"k8s_container_name":  "^testserver$",
		"k8s_deployment_name": "^testserver$",
		"k8s_replicaset_name": "^testserver-",
		"k8s_kind":            "Deployment",
		"k8s_cluster_name":    "^beyla-k8s-test-cluster$",
	}))
}
