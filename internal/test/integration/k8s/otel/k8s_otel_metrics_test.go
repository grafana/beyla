//go:build integration_k8s

package otel

import (
	"testing"

	k8s "github.com/grafana/beyla/v2/internal/test/integration/k8s/common"
)

// Run it alphabetically first (AA-prefix), with a longer timeout, to wait until all the components are up and
// traces/metrics are flowing normally
func TestOTEL_MetricsDecoration_AA_WaitForComponents(t *testing.T) {
	k8s.DoWaitForComponentsAvailable(t)
}

func TestOTEL_MetricsDecoration_HTTP(t *testing.T) {
	cluster.TestEnv().Test(t,
		k8s.FeatureHTTPMetricsDecoration(k8s.PingerManifest, nil),
		k8s.FeatureGraphMetricsOverridingClientNameNs(k8s.PingerManifest, "pinger-1", map[string]string{
			"OTEL_RESOURCE_ATTRIBUTES": "service.name=otel-client,service.namespace=otel-namespace",
		}),
		k8s.FeatureGraphMetricsOverridingClientNameNs(k8s.PingerManifest, "pinger-2", map[string]string{
			"OTEL_SERVICE_NAME":      "otel-client",
			"OTEL_SERVICE_NAMESPACE": "otel-namespace",
		}),
	)
}

func TestOTEL_MetricsDecoration_GRPC(t *testing.T) {
	cluster.TestEnv().Test(t,
		k8s.FeatureGRPCMetricsDecoration(k8s.GrpcPingerManifest, nil),
		k8s.FeatureGraphMetricsOverridingClientNameNs(k8s.GrpcPingerManifest, "gpinger-1", map[string]string{
			"OTEL_RESOURCE_ATTRIBUTES": "service.name=otel-client,service.namespace=otel-namespace",
		}),
		k8s.FeatureGraphMetricsOverridingClientNameNs(k8s.GrpcPingerManifest, "gpinger-2", map[string]string{
			"OTEL_SERVICE_NAME":      "otel-client",
			"OTEL_SERVICE_NAMESPACE": "otel-namespace",
		}),
	)
}

func TestOTEL_ProcessMetrics(t *testing.T) {
	cluster.TestEnv().Test(t, k8s.FeatureProcessMetricsDecoration(nil))
}
