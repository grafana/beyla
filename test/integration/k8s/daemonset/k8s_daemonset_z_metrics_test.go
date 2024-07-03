//go:build integration_k8s

package otel

import (
	"testing"

	k8s "github.com/grafana/beyla/test/integration/k8s/common"
)

// to find process information in the prometheus database,
// we need to make sure that this test is executed after the
// tests in k8s_daemonsset_traces_test.go file
func TestProcessMetrics(t *testing.T) {
	cluster.TestEnv().Test(t, k8s.FeatureProcessMetricsDecoration(map[string]string{
		"k8s_deployment_name": "^otherinstance$",
		"k8s_replicaset_name": "^otherinstance-.*",
		"k8s_pod_name":        "^otherinstance-.*",
	}))
}
