//go:build integration

package integration

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/slog"

	"github.com/grafana/ebpf-autoinstrument/test/integration/components/docker"
	"github.com/grafana/ebpf-autoinstrument/test/integration/components/kube"
)

const (
	kindImage = "kindest/node:v1.27.0"
)

func TestMain(m *testing.M) {
	if err := docker.Build(os.Stdout, "../..",
		docker.ImageBuild{Tag: "testserver:dev", Dockerfile: "components/testserver/Dockerfile"},
		docker.ImageBuild{Tag: "beyla:dev", Dockerfile: "components/beyla/Dockerfile"},
	); err != nil {
		slog.Error("can't build docker images", err)
		os.Exit(-1)
	}

	cluster := kube.NewKind("test-kind-cluster",
		kube.ExportLogs("logs-stuff"),
		kube.KindConfig("components/kube/base/00-kind.yml"),
		kube.ContextDir("../.."),
		kube.LocalImage("testserver:dev"),
		kube.LocalImage("beyla:dev"),
		kube.Deploy("components/kube/base/01-volumes.yml"),
		kube.Deploy("components/kube/base/03-otelcol.yml"),
		kube.Deploy("components/kube/base/04-jaeger.yml"),
		kube.Deploy("components/kube/base/05-instrumented-service.yml"),
	)

	cluster.Run(m)
}

func TestTracatraca(t *testing.T) {
	assert.True(t, true)
}
