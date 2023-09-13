//go:build integration

package prom

import (
	"context"
	"testing"

	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

	"github.com/grafana/beyla/test/integration/components/kube"
	"github.com/grafana/beyla/test/integration/k8s/otel"
)

func TestPrometheusDecoration(t *testing.T) {
	t.Skip("Prometheus K8s metadata decoration is WIP")
	pinger := kube.Template[otel.Pinger]{
		TemplateFile: otel.pingerManifest,
		Data: otel.Pinger{
			PodName:      "prom-pinger",
			TargetURL:    "http://testserver:8080/prom-ping",
			ConfigSuffix: "-promscrape",
		},
	}
	feat := features.New("Decoration of Pod-to-Service communications").
		Setup(pinger.Deploy()).
		Teardown(pinger.Delete()).
		Assess("all the metrics are properly decorated",
			func(ctx context.Context, t *testing.T, config *envconf.Config) context.Context {

				return ctx
			},
		).Feature()
	otel.cluster.TestEnv().Test(t, feat)
}
