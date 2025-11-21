//go:build integration_k8s

package otel

import (
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/v2/internal/test/integration/components/docker"
	"github.com/grafana/beyla/v2/internal/test/integration/components/kube"
	"github.com/grafana/beyla/v2/internal/test/integration/components/prom"
	k8s "github.com/grafana/beyla/v2/internal/test/integration/k8s/common"
	"github.com/grafana/beyla/v2/internal/test/integration/k8s/common/testpath"
	"github.com/grafana/beyla/v2/internal/test/tools"
)

const (
	prometheusHostPort = "localhost:39090"
	testTimeout        = 3 * time.Minute
)

var cluster *kube.Kind

func TestMain(m *testing.M) {
	if err := docker.Build(os.Stdout, tools.ProjectDir(),
		docker.ImageBuild{Tag: "beyla:dev", Dockerfile: k8s.DockerfileBeyla},
	); err != nil {
		slog.Error("can't build docker images", "error", err)
		os.Exit(-1)
	}

	cluster = kube.NewKind("test-kind-cluster-otel-multi",
		kube.KindConfig(testpath.Manifests+"/00-kind-multi-node.yml"),
		kube.LocalImage("beyla:dev"),
		kube.Deploy(testpath.Manifests+"/01-volumes.yml"),
		kube.Deploy(testpath.Manifests+"/01-serviceaccount.yml"),
		kube.Deploy(testpath.Manifests+"/02-prometheus-otelscrape-multi-node.yml"),
		kube.Deploy(testpath.Manifests+"/03-otelcol.yml"),
		kube.Deploy(testpath.Manifests+"/05-uninstrumented-server-client-different-nodes.yml"),
		kube.Deploy(testpath.Manifests+"/06-beyla-netolly.yml"),
	)

	cluster.Run(m)
}

func TestNoSourceAndDestAvailable(t *testing.T) {
	// Wait for some metrics available at Prometheus
	pq := prom.Client{HostPort: prometheusHostPort}
	for _, args := range []string{
		`k8s_dst_name="httppinger"`,
		`k8s_src_name="httppinger"`,
		`k8s_dst_name=~"otherinstance.*"`,
		`k8s_src_name=~"otherinstance.*"`,
	} {
		t.Run("check "+args, func(t *testing.T) {
			test.Eventually(t, testTimeout, func(t require.TestingT) {
				var err error
				results, err := pq.Query(`beyla_network_flow_bytes_total{` + args + `}`)
				require.NoError(t, err)
				require.NotEmpty(t, results)
			})
		})
	}

	// Verify that HTTP pinger/testserver metrics can't have both source and destination labels,
	// as the test client and server are in different nodes, and Beyla is only getting information
	// from its local node
	results, err := pq.Query(`beyla_network_flow_bytes_total{k8s_dst_name="httppinger",k8s_src_name=~"otherinstance.*",k8s_src_kind="Pod"}`)
	require.NoError(t, err)
	require.Empty(t, results)

	results, err = pq.Query(`beyla_network_flow_bytes_total{k8s_src_name="httppinger",k8s_dst_name=~"otherinstance.*",k8s_dst_kind="Pod"}`)
	require.NoError(t, err)
	require.Empty(t, results)
}
