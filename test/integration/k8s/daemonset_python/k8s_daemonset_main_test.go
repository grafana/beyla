//go:build integration

package otel

import (
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/grafana/beyla/test/integration/components/docker"
	"github.com/grafana/beyla/test/integration/components/kube"
	k8s "github.com/grafana/beyla/test/integration/k8s/common"
	"github.com/grafana/beyla/test/tools"
)

const (
	testTimeout = 3 * time.Minute

	jaegerQueryURL = "http://localhost:36686/api/traces"
)

var cluster *kube.Kind

func TestMain(m *testing.M) {
	if err := docker.Build(os.Stdout, tools.ProjectDir(),
		docker.ImageBuild{Tag: "pythontestserver:dev", Dockerfile: k8s.DockerfilePythonTestServer},
		docker.ImageBuild{Tag: "beyla:dev", Dockerfile: k8s.DockerfileBeyla},
	); err != nil {
		slog.Error("can't build docker images", err)
		os.Exit(-1)
	}

	cluster = kube.NewKind("test-kind-cluster-otel-python",
		kube.ExportLogs(k8s.PathKindLogs),
		kube.KindConfig(k8s.PathManifests+"/00-kind.yml"),
		kube.LocalImage("pythontestserver:dev"),
		kube.LocalImage("beyla:dev"),
		kube.Deploy(k8s.PathManifests+"/01-volumes.yml"),
		kube.Deploy(k8s.PathManifests+"/01-serviceaccount.yml"),
		kube.Deploy(k8s.PathManifests+"/03-otelcol.yml"),
		kube.Deploy(k8s.PathManifests+"/04-jaeger.yml"),
		kube.Deploy(k8s.PathManifests+"/05-uninstrumented-service-python.yml"),
		kube.Deploy(k8s.PathManifests+"/06-beyla-daemonset-python.yml"),

		kube.DeleteBeforeDestroy(k8s.PathManifests+"/06-beyla-daemonset-python.yml"),
	)

	cluster.Run(m)
}
