//go:build integration

package k8s

import (
	"context"
	"testing"

	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

	"github.com/grafana/beyla/test/integration/components/kube"
)

func TestPrometheusDecoration(t *testing.T) {
	t.Skip("Prometheus K8s metadata decoration is WIP")
	pinger := kube.Template[Pinger]{
		TemplateFile: pingerManifest,
		Data: Pinger{
			PodName:      "prom-pinger",
			TargetURL:    "http://testserver:8080/prom-ping",
			ConfigSuffix: "-promscrape",
		},
	}
	feat := features.New("Decoration of Pod-to-Service communications").
		Setup(pinger.Deploy()).
		Teardown(pinger.Delete()).
		Assess("all the traces are properly decorated",
			func(ctx context.Context, t *testing.T, config *envconf.Config) context.Context {

				return ctx
			},
		).Feature()
	cluster.TestEnv().Test(t, feat)
}
