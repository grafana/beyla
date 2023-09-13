//go:build integration

package k8s

import (
	"os"
	"path"
	"testing"
	"time"

	"golang.org/x/exp/slog"

	"github.com/grafana/beyla/test/integration/components/docker"
	"github.com/grafana/beyla/test/integration/components/kube"
	"github.com/grafana/beyla/test/tools"
)

const (
	testTimeout = 2 * time.Minute

	prometheusHostPort = "localhost:39090"
	jaegerQueryURL     = "http://localhost:36686/api/traces"

	pingerManifest     = "manifests/06-instrumented-client.template.yml"
	grpcPingerManifest = "manifests/06-instrumented-grpc-client.template.yml"
)

var (
	pathRoot       = tools.ProjectDir()
	pathOutput     = path.Join(pathRoot, "testoutput")
	pathKindLogs   = path.Join(pathOutput, "kind")
	componentsPath = path.Join(pathRoot, "test", "integration", "components")
)

// Ping stores the configuration data of a local pod that will be used to
// send recurring requests to the test server
type Pinger struct {
	PodName      string
	TargetURL    string
	ConfigSuffix string
}

var cluster *kube.Kind

// TestMain is run once before all the tests in the package. If you need to mount a different cluster for
// a different test suite, you should add a new TestMain in a new package together with the new test suite
func TestMain(m *testing.M) {
	if err := docker.Build(os.Stdout, pathRoot,
		docker.ImageBuild{Tag: "testserver:dev", Dockerfile: componentsPath + "/testserver/Dockerfile"},
		docker.ImageBuild{Tag: "beyla:dev", Dockerfile: componentsPath + "/beyla/Dockerfile"},
		docker.ImageBuild{Tag: "grpcpinger:dev", Dockerfile: componentsPath + "/grpcpinger/Dockerfile"},
	); err != nil {
		slog.Error("can't build docker images", err)
		os.Exit(-1)
	}

	cluster = kube.NewKind("test-kind-cluster",
		kube.ExportLogs(pathKindLogs),
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
