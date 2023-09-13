//go:build integration

package prom

import (
	"os"
	"testing"
	"time"

	"golang.org/x/exp/slog"

	"github.com/grafana/beyla/test/integration/components/docker"
	"github.com/grafana/beyla/test/integration/components/kube"
	k8s "github.com/grafana/beyla/test/integration/k8s/common"
)

const (
	testTimeout = 2 * time.Minute

	prometheusHostPort = "localhost:39090"
	jaegerQueryURL     = "http://localhost:36686/api/traces"

	pingerManifest     = "manifests/06-instrumented-client.template.yml"
	grpcPingerManifest = "manifests/06-instrumented-grpc-client.template.yml"
)

var cluster *kube.Kind

// TestMain is run once before all the tests in the package. If you need to mount a different cluster for
// a different test suite, you should add a new TestMain in a new package together with the new test suite
func TestMain(m *testing.M) {
	if err := docker.Build(os.Stdout, k8s.PathRoot,
		docker.ImageBuild{Tag: "testserver:dev", Dockerfile: k8s.DockerfileTestServer},
		docker.ImageBuild{Tag: "beyla:dev", Dockerfile: k8s.DockerfileBeyla},
		docker.ImageBuild{Tag: "grpcpinger:dev", Dockerfile: k8s.DockerfilePinger},
	); err != nil {
		slog.Error("can't build docker images", err)
		os.Exit(-1)
	}

	cluster = kube.NewKind("test-kind-cluster",
		kube.ExportLogs(k8s.PathKindLogs),
		kube.KindConfig("manifests/00-kind.yml"),
		kube.LocalImage("testserver:dev"),
		kube.LocalImage("beyla:dev"),
		kube.LocalImage("grpcpinger:dev"),
		kube.Deploy("manifests/01-volumes.yml"),
		kube.Deploy("manifests/02-prometheus.yml"),
		kube.Deploy("manifests/03-otelcol.yml"),
		kube.Deploy("manifests/04-jaeger.yml"),
		kube.Deploy("manifests/05-instrumented-service.yml"),
	)

	cluster.Run(m)
}
