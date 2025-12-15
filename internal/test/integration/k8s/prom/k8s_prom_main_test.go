//go:build integration_k8s

package prom

import (
	"log/slog"
	"os"
	"testing"

	"github.com/grafana/beyla/v2/internal/test/integration/components/docker"
	"github.com/grafana/beyla/v2/internal/test/integration/components/kube"
	k8s "github.com/grafana/beyla/v2/internal/test/integration/k8s/common"
	"github.com/grafana/beyla/v2/internal/test/integration/k8s/common/testpath"
	"github.com/grafana/beyla/v2/internal/test/tools"
)

var cluster *kube.Kind

// TestMain is run once before all the tests in the package. If you need to mount a different cluster for
// a different test suite, you should add a new TestMain in a new package together with the new test suite
func TestMain(m *testing.M) {
	if err := docker.Build(os.Stdout, tools.ProjectDir(),
		docker.ImageBuild{Tag: "testserver:dev", Dockerfile: k8s.DockerfileTestServer},
		docker.ImageBuild{Tag: "beyla:dev", Dockerfile: k8s.DockerfileBeyla},
		docker.ImageBuild{Tag: "grpcpinger:dev", Dockerfile: k8s.DockerfilePinger},
		docker.ImageBuild{Tag: "httppinger:dev", Dockerfile: k8s.DockerfileHTTPPinger},
	); err != nil {
		slog.Error("can't build docker images", "error", err)
		os.Exit(-1)
	}

	cluster = kube.NewKind("test-kind-cluster-prom",
		kube.KindConfig(testpath.Manifests+"/00-kind.yml"),
		kube.LocalImage("testserver:dev"),
		kube.LocalImage("beyla:dev"),
		kube.LocalImage("grpcpinger:dev"),
		kube.LocalImage("httppinger:dev"),
		kube.Deploy(testpath.Manifests+"/01-volumes.yml"),
		kube.Deploy(testpath.Manifests+"/01-serviceaccount.yml"),
		kube.Deploy(testpath.Manifests+"/02-prometheus-promscrape.yml"),
		kube.Deploy(testpath.Manifests+"/05-instrumented-service-prometheus.yml"),
	)

	cluster.Run(m)
}
