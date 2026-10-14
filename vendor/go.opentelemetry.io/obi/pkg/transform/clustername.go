// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Few lines of code in this file are taken from
// https://github.com/DataDog/datadog-agent,
// published under Apache License 2.0

package transform // import "go.opentelemetry.io/obi/pkg/transform"

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"k8s.io/client-go/rest"

	"go.opentelemetry.io/contrib/detectors/aws/eks"

	attr2 "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/kube"
)

const (
	gcpMetadataURL     = "http://metadata.google.internal/computeMetadata/v1/instance/attributes/cluster-name"
	azureMetadataURL   = "http://169.254.169.254/metadata/instance/compute/resourceGroupName?api-version=2017-08-01&format=text"
	openshiftInfraPath = "/apis/config.openshift.io/v1/infrastructures/cluster"
)

var (
	gcpMetadataHeaders   = map[string]string{"Metadata-Flavor": "Google"}
	azureMetadataHeaders = map[string]string{"Metadata": "true"}
)

var metadataClient = http.Client{Timeout: time.Second}

type clusterNameFetcher func(context.Context) (string, error)

// fetchClusterName tries to automatically guess the cluster name from
// node labels, cloud providers (EC2, GCP, Azure), or OpenShift.
// TODO: consider other providers (Alibaba, Oracle, etc...)
func fetchClusterName(ctx context.Context, k8sInformer *kube.MetadataProvider) string {
	log := klog().With("func", "fetchClusterName")
	clusterNameFetchers := []struct {
		provider string
		fetch    clusterNameFetcher
	}{
		{"Label", nodeLabelsClusterNameFetcher(k8sInformer)},
		{"OpenShift", openshiftClusterNameFetcher(k8sInformer)},
		{"EC2", eksClusterNameFetcher},
		{"GCP", gcpClusterNameFetcher},
		{"Azure", azureClusterNameFetcher},
	}
	for _, f := range clusterNameFetchers {
		provider, fetch := f.provider, f.fetch
		log := log.With("provider", provider)
		log.Debug("trying to retrieve cluster name")
		if name, err := fetch(ctx); err != nil {
			log.Debug("didn't get cluster name", "error", err)
		} else if name != "" {
			log.Debug("successfully got cluster name", "name", name)
			return name
		}
	}
	return ""
}

func httpGet(ctx context.Context, url string, headers map[string]string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	req = req.WithContext(ctx)
	if err != nil {
		return "", fmt.Errorf("creating HTTP request for %s: %w", url, err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := metadataClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("invoking GET %s: %w", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s unexpected response: %d %s",
			url, resp.StatusCode, resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response body: %w", err)
	}
	return string(bytes.TrimSpace(body)), nil
}

func gcpClusterNameFetcher(ctx context.Context) (string, error) {
	return httpGet(ctx, gcpMetadataURL, gcpMetadataHeaders)
}

func azureClusterNameFetcher(ctx context.Context) (string, error) {
	all, err := httpGet(ctx, azureMetadataURL, azureMetadataHeaders)
	if err != nil {
		return "", err
	}

	// It expects the resource group name to have the format (MC|mc)_resource-group_cluster-name_zone
	splitAll := strings.Split(all, "_")
	if len(splitAll) < 4 || strings.ToLower(splitAll[0]) != "mc" {
		return "", fmt.Errorf("cannot parse the clustername from resource group name: %s", all)
	}

	return splitAll[len(splitAll)-2], nil
}

func eksClusterNameFetcher(ctx context.Context) (string, error) {
	// Instantiate a new EKS Resource detector
	eksResourceDetector := eks.NewResourceDetector()
	resource, err := eksResourceDetector.Detect(ctx)
	if err != nil {
		return "", err
	}
	for _, attr := range resource.Attributes() {
		if string(attr.Key) == string(attr2.K8sClusterName) {
			return attr.Value.Emit(), nil
		}
	}
	return "", fmt.Errorf("did not find any cluster attribute in %+v", resource.Attributes())
}

type openshiftInfrastructureResponse struct {
	Status struct {
		InfrastructureName string `json:"infrastructureName"`
	} `json:"status"`
}

func openshiftClusterNameFetcher(k8sInformer *kube.MetadataProvider) clusterNameFetcher {
	return func(ctx context.Context) (string, error) {
		cfg, err := k8sInformer.RestConfig()
		if err != nil {
			return "", fmt.Errorf("loading kube config: %w", err)
		}

		transport, err := rest.TransportFor(cfg)
		if err != nil {
			return "", fmt.Errorf("creating transport: %w", err)
		}

		client := &http.Client{Timeout: time.Second, Transport: transport}
		endpoint := strings.TrimRight(cfg.Host, "/") + openshiftInfraPath
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return "", fmt.Errorf("creating request: %w", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			return "", fmt.Errorf("requesting OpenShift infrastructure CR: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("OpenShift API returned %s", resp.Status)
		}

		var infra openshiftInfrastructureResponse
		if err := json.NewDecoder(resp.Body).Decode(&infra); err != nil {
			return "", fmt.Errorf("decoding infrastructure response: %w", err)
		}

		if infra.Status.InfrastructureName == "" {
			return "", errors.New("OpenShift Infrastructure CR has empty infrastructureName")
		}

		return infra.Status.InfrastructureName, nil
	}
}

func nodeLabelsClusterNameFetcher(k8sInformer *kube.MetadataProvider) func(ctx context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		return k8sInformer.ClusterName(ctx)
	}
}
