//go:build integration

package integration

import (
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/slog"

	"github.com/grafana/ebpf-autoinstrument/test/integration/components/docker"
	"github.com/grafana/ebpf-autoinstrument/test/integration/components/kube"
	"github.com/grafana/ebpf-autoinstrument/test/integration/components/prom"
)

var cluster *kube.Kind

func TestMain(m *testing.M) {
	if err := docker.Build(os.Stdout, "../..",
		docker.ImageBuild{Tag: "testserver:dev", Dockerfile: "components/testserver/Dockerfile"},
		docker.ImageBuild{Tag: "beyla:dev", Dockerfile: "components/beyla/Dockerfile"},
	); err != nil {
		slog.Error("can't build docker images", err)
		os.Exit(-1)
	}

	cluster = kube.NewKind("test-kind-cluster",
		kube.ExportLogs(pathKindLogs),
		kube.KindConfig("components/kube/base/00-kind.yml"),
		kube.ContextDir("../.."),
		kube.LocalImage("testserver:dev"),
		kube.LocalImage("beyla:dev"),
		kube.Deploy("components/kube/base/01-volumes.yml"),
		kube.Deploy("components/kube/base/02-prometheus.yml"),
		kube.Deploy("components/kube/base/03-otelcol.yml"),
		kube.Deploy("components/kube/base/04-jaeger.yml"),
		kube.Deploy("components/kube/base/05-instrumented-service.yml"),
	)

	cluster.Run(m)
}

func TestAllComponentsWork(t *testing.T) {
	// smoke test that just waits until all the components are up and
	// applications traces are reported are traced
	const (
		prometheusHostPort = "localhost:39090"
		subpath            = "/smoke"
		url                = "http://localhost:38080"
	)
	pq := prom.Client{HostPort: prometheusHostPort}
	test.Eventually(t, 2*time.Minute, func(t require.TestingT) {
		// first, verify that the test service endpoint is healthy
		req, err := http.NewRequest("GET", url+subpath, nil)
		require.NoError(t, err)
		r, err := testHTTPClient.Do(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, r.StatusCode)

		// now, verify that the metric has been reported.
		// we don't really care that this metric could be from a previous
		// test. Once one it is visible, it means that Otel and Prometheus are healthy
		results, err := pq.Query(`http_server_duration_seconds_count{http_target="` + subpath + `"}`)
		require.NoError(t, err)
		require.NotZero(t, len(results))
	}, test.Interval(time.Second))

}
