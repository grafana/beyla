//go:build integration_k8s

package otel

import (
	"log/slog"
	"os"
	"testing"

	"github.com/grafana/beyla/v2/test/integration/components/docker"
	"github.com/grafana/beyla/v2/test/integration/components/kube"
	k8s "github.com/grafana/beyla/v2/test/integration/k8s/common"
	"github.com/grafana/beyla/v2/test/integration/k8s/common/testpath"
	"github.com/grafana/beyla/v2/test/tools"
)

var cluster *kube.Kind

func TestMain(m *testing.M) {
	if err := docker.Build(os.Stdout, tools.ProjectDir(),
		docker.ImageBuild{Tag: "testserver:dev", Dockerfile: k8s.DockerfileTestServer},
		docker.ImageBuild{Tag: "beyla:dev", Dockerfile: k8s.DockerfileBeyla},
		docker.ImageBuild{Tag: "httppinger:dev", Dockerfile: k8s.DockerfileHTTPPinger},
		docker.ImageBuild{Tag: "quay.io/prometheus/prometheus:v2.55.1"},
		docker.ImageBuild{Tag: "otel/opentelemetry-collector-contrib:0.103.0"},
		docker.ImageBuild{Tag: "jaegertracing/all-in-one:1.57"},
	); err != nil {
		slog.Error("can't build docker images", "error", err)
		os.Exit(-1)
	}

	cluster = kube.NewKind("test-kind-cluster-daemonset",
		kube.KindConfig(testpath.Manifests+"/00-kind.yml"),
		kube.LocalImage("testserver:dev"),
		kube.LocalImage("beyla:dev"),
		kube.LocalImage("httppinger:dev"),
		kube.LocalImage("quay.io/prometheus/prometheus:v2.55.1"),
		kube.LocalImage("otel/opentelemetry-collector-contrib:0.103.0"),
		kube.LocalImage("jaegertracing/all-in-one:1.57"),
		kube.Deploy(testpath.Manifests+"/01-volumes.yml"),
		kube.Deploy(testpath.Manifests+"/01-serviceaccount.yml"),
		kube.Deploy(testpath.Manifests+"/02-prometheus-otelscrape.yml"),
		kube.Deploy(testpath.Manifests+"/03-otelcol.yml"),
		kube.Deploy(testpath.Manifests+"/04-jaeger.yml"),
		kube.Deploy(testpath.Manifests+"/05-uninstrumented-service.yml"),
		kube.Deploy(testpath.Manifests+"/06-beyla-daemonset-disable-informers.yml"),
	)

	cluster.Run(m)
}

func TestDisableInformers(t *testing.T) {
	cluster.TestEnv().Test(t, k8s.FeatureDisableInformersAppMetricsDecoration())
}
