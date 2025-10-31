//go:build integration_k8s

package otel

import (
	"log/slog"
	"os"
	"testing"

	"github.com/grafana/beyla/v2/internal/test/integration/components/docker"
	"github.com/grafana/beyla/v2/internal/test/integration/components/kube"
	k8s "github.com/grafana/beyla/v2/internal/test/integration/k8s/common"
	"github.com/grafana/beyla/v2/internal/test/integration/k8s/common/testpath"
	otel "github.com/grafana/beyla/v2/internal/test/integration/k8s/netolly_multizone"
	"github.com/grafana/beyla/v2/internal/test/tools"
)

var cluster *kube.Kind

func TestMain(m *testing.M) {
	if err := docker.Build(os.Stdout, tools.ProjectDir(),
		docker.ImageBuild{Tag: "testserver:dev", Dockerfile: k8s.DockerfileTestServer},
		docker.ImageBuild{Tag: "beyla:dev", Dockerfile: k8s.DockerfileBeyla},
		docker.ImageBuild{Tag: "httppinger:dev", Dockerfile: k8s.DockerfileHTTPPinger},
	); err != nil {
		slog.Error("can't build docker images", "error", err)
		os.Exit(-1)
	}

	cluster = kube.NewKind("test-kind-cluster-netolly-multizone-prom",
		kube.KindConfig(testpath.Manifests+"/00-kind-multi-zone.yml"),
		kube.LocalImage("testserver:dev"),
		kube.LocalImage("beyla:dev"),
		kube.LocalImage("httppinger:dev"),
		kube.Deploy(testpath.Manifests+"/01-volumes.yml"),
		kube.Deploy(testpath.Manifests+"/01-serviceaccount.yml"),
		kube.Deploy(testpath.Manifests+"/02-prometheus-promscrape-multizone.yml"),
		kube.Deploy(testpath.Manifests+"/05-uninstrumented-multizone-client-server.yml"),
		kube.Deploy(testpath.Manifests+"/06-beyla-netolly-promexport.yml"),
	)

	cluster.Run(m)
}

func TestMultizoneNetworkFlows_Prom(t *testing.T) {
	cluster.TestEnv().Test(t, otel.FeatureMultizoneNetworkFlows())
}
