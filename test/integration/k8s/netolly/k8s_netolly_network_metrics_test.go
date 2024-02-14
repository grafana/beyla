//go:build integration

package otel

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

	"github.com/grafana/beyla/test/integration/components/kube"
	"github.com/grafana/beyla/test/integration/components/prom"
	k8s "github.com/grafana/beyla/test/integration/k8s/common"
)

func TestNetworkFlowBytes(t *testing.T) {
	pinger := kube.Template[k8s.Pinger]{
		TemplateFile: k8s.PingerManifest,
		Data: k8s.Pinger{
			PodName:   "internal-pinger",
			TargetURL: "http://testserver:8080/iping",
		},
	}
	cluster.TestEnv().Test(t, features.New("network flow bytes").
		Setup(pinger.Deploy()).
		Teardown(pinger.Delete()).
		Assess("catches network metrics between connected pods", testNetFlowBytesForExistingConnections).
		Feature(),
	)
}

func testNetFlowBytesForExistingConnections(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	pq := prom.Client{HostPort: prometheusHostPort}

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		results, err := pq.Query(`network_flows_bytes_total{k8s_src_name="internal-pinger",k8s_dst_name="testserver"}`)
		require.NoError(t, err)
		require.NotEmpty(t, results)
		txt, _ := json.Marshal(results)
		fmt.Println(string(txt))
	})


	return ctx
}
