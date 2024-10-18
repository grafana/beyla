//go:build integration_k8s

package otel

import (
	"testing"

	k8s "github.com/grafana/beyla/test/integration/k8s/common"
)

// Run it alphabetically first (AA-prefix), with a longer timeout, to wait until all the components are up and
// traces/metrics are flowing normally
func TestOTEL_MetricsDecoration_AA_WaitForComponents(t *testing.T) {
	k8s.DoWaitForComponentsAvailable(t)
}

func TestOTEL_MetricsDecoration_HTTP(t *testing.T) {
	cluster.TestEnv().Test(t, k8s.FeatureHTTPMetricsDecoration(k8s.PingerManifest, nil))
}

func TestOTEL_MetricsDecoration_GRPC(t *testing.T) {
	cluster.TestEnv().Test(t, k8s.FeatureGRPCMetricsDecoration(k8s.GrpcPingerManifest))
}

func TestOTEL_ProcessMetrics(t *testing.T) {
	cluster.TestEnv().Test(t, k8s.FeatureProcessMetricsDecoration(nil))
}
