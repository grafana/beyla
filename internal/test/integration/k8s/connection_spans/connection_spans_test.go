//go:build integration_k8s

package connection_spans

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

	"github.com/grafana/beyla/v2/internal/test/integration/components/docker"
	"github.com/grafana/beyla/v2/internal/test/integration/components/jaeger"
	"github.com/grafana/beyla/v2/internal/test/integration/components/kube"
	k8s "github.com/grafana/beyla/v2/internal/test/integration/k8s/common"
	"github.com/grafana/beyla/v2/internal/test/integration/k8s/common/testpath"
	"github.com/grafana/beyla/v2/internal/test/tools"
)

const (
	testTimeout = 3 * time.Minute

	jaegerHost     = "http://localhost:36686"
	jaegerQueryURL = jaegerHost + "/api/traces"
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

	cluster = kube.NewKind("test-kind-cluster-daemonset",
		kube.KindConfig(testpath.Manifests+"/00-kind.yml"),
		kube.LocalImage("testserver:dev"),
		kube.LocalImage("beyla:dev"),
		kube.LocalImage("httppinger:dev"),
		kube.Deploy(testpath.Manifests+"/01-volumes.yml"),
		kube.Deploy(testpath.Manifests+"/01-serviceaccount.yml"),
		kube.Deploy(testpath.Manifests+"/02-prometheus-otelscrape.yml"),
		kube.Deploy(testpath.Manifests+"/03-otelcol.yml"),
		kube.Deploy(testpath.Manifests+"/04-jaeger.yml"),
		kube.Deploy(testpath.Manifests+"/05-uninstrumented-service.yml"),
		kube.Deploy(testpath.Manifests+"/06-beyla-daemonset-topology-extern.yml"),
	)

	cluster.Run(m)
}

func TestConnectionSpans(t *testing.T) {
	cluster.TestEnv().Test(t, featureConnectionSpans())
}

func featureConnectionSpans() features.Feature {
	pinger := kube.Template[k8s.Pinger]{
		TemplateFile: k8s.PingerManifest,
		Data: k8s.Pinger{
			PodName:   "internal-pinger",
			TargetURL: "http://testserver:8080/iping",
		},
	}
	return features.New("Connection spans").
		Setup(pinger.Deploy()).
		Teardown(pinger.Delete()).
		Assess("it doesn't have connection spans for internal traffic",
			func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
				// first, make sure that we have traces for the pinger pod
				test.Eventually(t, testTimeout, func(t require.TestingT) {
					tq := getTraces(t, "?service=testserver")
					assert.NotEmpty(t, tq.Data)
				}, test.Interval(200*time.Millisecond))
				// BUT we don't have any connection spans
				tq := getTraces(t, "?service=testserver&tags="+
					// matching also client.address to ignore the first unresolved pings, before the
					// K8s informer gets thet pinger metadata
					url.QueryEscape(`{"beyla.topology":"external","client.address":"internal-pinger.default"}`))
				assert.Empty(t, tq.Data)
				return ctx
			}).
		Assess("it creates connection spans for external traffic",
			func(ctx context.Context, t *testing.T, config *envconf.Config) context.Context {
				// establishing a connection from outside the cluster
				resp, err := http.Get("http://localhost:38080/testing-external-traces")
				require.NoError(t, err)
				require.NotNil(t, resp)
				require.Equal(t, http.StatusOK, resp.StatusCode)

				// check that now we get the connection spans
				test.Eventually(t, testTimeout, func(t require.TestingT) {
					tq := getTraces(t, "?service=testserver&operation="+
						url.QueryEscape("GET /testing-external-traces")+"&tags="+
						url.QueryEscape(`{"beyla.topology":"external"}`))
					require.Len(t, tq.Data, 1)
				})

				return ctx
			},
		).Feature()
}

func getTraces(t require.TestingT, query string) jaeger.TracesQuery {
	resp, err := http.Get(jaegerQueryURL + query)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var tq jaeger.TracesQuery
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
	return tq
}
