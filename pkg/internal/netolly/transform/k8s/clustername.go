// Few lines of code in this file are taken from
// https://github.com/DataDog/datadog-agent,
// published under Apache License 2.0

package k8s

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	gcpMetadataURL   = "http://metadata.google.internal/computeMetadata/v1/instance/attributes/cluster-name"
	azureMetadataURL = "http://169.254.169.254/metadata/instance/compute/vmId?api-version=2017-04-02&format=text"
	ec2MetadataURL   = "http://169.254.169.254/latest/meta-data/tags/instance"
)

var (
	gcpMetadataHeaders   = map[string]string{"Metadata-Flavor": "Google"}
	azureMetadataHeaders = map[string]string{"Metadata": "true"}
)

var metadataClient = http.Client{Timeout: time.Second}

type clusterNameFetcher func(context.Context) (string, error)

// fetchClusterName tries to automatically guess the cluster name from three major
// cloud providers: EC2, GCP, Azure.
// TODO: consider other providers (Alibaba, Oracle, etc...)
func fetchClusterName(ctx context.Context) string {
	log := log().With("func", "fetchClusterName")
	var clusterNameFetchers = map[string]clusterNameFetcher{
		"EC2":   ec2ClusterNameFetcher,
		"GCP":   gcpClusterNameFetcher,
		"Azure": azureClusterNameFetcher,
	}
	for provider, fetch := range clusterNameFetchers {
		log := log.With("provider", provider)
		log.Debug("trying to retrieve cluster name")
		if name, err := fetch(ctx); err != nil {
			log.Debug("didn't get cluster name", "error", err)
		} else if name != "" {
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

func ec2ClusterNameFetcher(ctx context.Context) (string, error) {
	// using IMDSv1 service
	tagsStr, err := httpGet(ctx, ec2MetadataURL, nil)
	if err != nil {
		return "", err
	}
	// tagsStr is a newline-separated list of strings containing tag keys
	for _, key := range strings.Split(tagsStr, "\n") {
		// tag key format: kubernetes.io/cluster/clustername"
		if strings.HasPrefix(key, "kubernetes.io/cluster/") {
			return strings.Split(key, "/")[2], nil
		}
	}
	return "", errors.New("did not find any kubernetes.io/cluster/... tag")
}
