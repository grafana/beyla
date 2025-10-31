//go:build integration_k8s

package prom

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

	"github.com/grafana/beyla/v2/internal/test/integration/components/docker"
	"github.com/grafana/beyla/v2/internal/test/integration/components/kube"
	"github.com/grafana/beyla/v2/internal/test/integration/components/prom"
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

	cluster = kube.NewKind("test-kind-cluster-process-notraces",
		kube.KindConfig(testpath.Manifests+"/00-kind.yml"),
		kube.LocalImage("testserver:dev"),
		kube.LocalImage("beyla:dev"),
		kube.Deploy(testpath.Manifests+"/01-volumes.yml"),
		kube.Deploy(testpath.Manifests+"/01-serviceaccount.yml"),
		kube.Deploy(testpath.Manifests+"/02-prometheus-promscrape.yml"),
		kube.Deploy(testpath.Manifests+"/05-uninstrumented-service.yml"),
		kube.Deploy(testpath.Manifests+"/06-beyla-all-processes.yml"),
	)

	cluster.Run(m)
}

// will test that process metrics are decorated correctly with all the metadata, even when
// Beyla hasn't instrumented still any single trace
func TestProcessMetrics_NoTraces(t *testing.T) {
	cluster.TestEnv().Test(t,
		waitForSomeMetrics(),
		k8s.FeatureProcessMetricsDecoration(nil))
}

const prometheusHostPort = "localhost:39090"

func waitForSomeMetrics() features.Feature {
	return features.New("wait for some metrics to appear before starting the actual test").
		Assess("smoke test", func(ctx context.Context, t *testing.T, config *envconf.Config) context.Context {
			pq := prom.Client{HostPort: prometheusHostPort}
			// timeout needs to be high, as the K8s cluster needs to be spinned up at this right moment
			test.Eventually(t, 5*time.Minute, func(t require.TestingT) {
				results, err := pq.Query("process_cpu_time_seconds_total")
				require.NoError(t, err)
				require.NotEmpty(t, results)
			})
			return ctx
		}).Feature()
}
