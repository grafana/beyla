// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration_k8s

package otel

import (
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/grafana/beyla/v2/internal/test/integration/components/docker"
	"github.com/grafana/beyla/v2/internal/test/integration/components/kube"
	k8s "github.com/grafana/beyla/v2/internal/test/integration/k8s/common"
	"github.com/grafana/beyla/v2/internal/test/integration/k8s/common/testpath"
	"github.com/grafana/beyla/v2/internal/test/tools"
)

const (
	testTimeout = 3 * time.Minute

	jaegerQueryURL = "http://localhost:36686/api/traces"
)

var cluster *kube.Kind

func TestMain(m *testing.M) {
	if err := docker.Build(os.Stdout, tools.ProjectDir(),
		docker.ImageBuild{Tag: "testserver:dev", Dockerfile: k8s.DockerfileTestServer},
		docker.ImageBuild{Tag: "pythontestserver:dev", Dockerfile: k8s.DockerfilePythonTestServer},
		docker.ImageBuild{Tag: "beyla:dev", Dockerfile: k8s.DockerfileBeyla},
		// Pull public images but don't pre-load them into Kind nodes
		// Kubernetes will pull them only to the nodes where they're scheduled
		docker.ImageBuild{Tag: "otel/opentelemetry-collector-contrib:0.104.0"},
		docker.ImageBuild{Tag: "jaegertracing/all-in-one:1.57"},
		docker.ImageBuild{Tag: "ghcr.io/open-telemetry/obi-testimg:rails-0.1.0"},
	); err != nil {
		slog.Error("can't build docker images", "error", err)
		os.Exit(-1)
	}

	cluster = kube.NewKind("test-kind-cluster-otel-multi",
		kube.KindConfig(testpath.Manifests+"/00-kind-multi-node.yml"),
		// Only pre-load locally built images
		kube.LocalImage("testserver:dev"),
		kube.LocalImage("pythontestserver:dev"),
		kube.LocalImage("beyla:dev"),
		kube.Deploy(testpath.Manifests+"/01-volumes.yml"),
		kube.Deploy(testpath.Manifests+"/01-serviceaccount.yml"),
		kube.Deploy(testpath.Manifests+"/03-otelcol-multi-node.yml"),
		kube.Deploy(testpath.Manifests+"/04-jaeger-multi-node.yml"),
		kube.Deploy(testpath.Manifests+"/05-uninstrumented-few-services.yml"),
		kube.Deploy(testpath.Manifests+"/06-beyla-daemonset-multi-node.yml"),
	)

	cluster.Run(m)
}
