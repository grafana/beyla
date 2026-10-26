// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package transform // import "go.opentelemetry.io/obi/pkg/transform"

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"google.golang.org/api/compute/v1"
	"google.golang.org/api/option"

	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"

	"go.opentelemetry.io/obi/pkg/cloud"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/metadata"
)

func gceInventoryRefresher(ctx context.Context, node *metadata.NodeMeta,
	settings GCENameResolverConfig, cloudCfg CloudMetadataConfig,
) (cloud.MetadataRefresher, error) {
	var platform string
	for _, entry := range node.Metadata {
		switch entry.Key {
		case attr.Name(semconv.CloudPlatformKey):
			platform = entry.Value
		case attr.Name(semconv.CloudAccountIDKey):
			if settings.ProjectID == "" {
				settings.ProjectID = entry.Value
			}
		case attr.Name(semconv.CloudAvailabilityZoneKey):
			if settings.Zone == "" {
				settings.Zone = entry.Value
			}
		}
	}
	if platform != semconv.CloudPlatformGCPComputeEngine.Value.AsString() {
		return nil, nil
	}
	if cloudCfg.RefreshInterval <= 0 {
		return nil, errors.New("initializing GCE name resolver: a positive refresh interval is required")
	}
	if settings.ProjectID == "" || settings.Zone == "" {
		return nil, errors.New("initializing GCE name resolver: configure extensions.obi.enrich.service_name.gce.project_id and extensions.obi.enrich.service_name.gce.zone when cloud metadata does not supply them")
	}

	options := []option.ClientOption{option.WithScopes(compute.ComputeReadonlyScope)}
	if settings.Endpoint != "" {
		endpoint, err := url.Parse(settings.Endpoint)
		if err != nil || endpoint.Host == "" || (endpoint.Scheme != "https" && endpoint.Scheme != "http") ||
			endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
			return nil, errors.New("initializing GCE name resolver: endpoint must be an HTTP(S) base URL without credentials, query or fragment")
		}
		options = append(options, option.WithEndpoint(strings.TrimRight(settings.Endpoint, "/")+"/"))
	}
	client, err := compute.NewService(ctx, options...)
	if err != nil {
		return nil, fmt.Errorf("creating GCE inventory client: %w", err)
	}
	return cloud.NewGCERefresher(client, settings.ProjectID, settings.Zone), nil
}

func gceLocalInstanceID(node metadata.NodeMeta, cfg GCENameResolverConfig) string {
	if node.Features.Has(metadata.ClusterK8s) {
		return ""
	}
	var project, zone string
	for _, entry := range node.Metadata {
		switch entry.Key {
		case attr.Name(semconv.CloudAccountIDKey):
			project = entry.Value
		case attr.Name(semconv.CloudAvailabilityZoneKey):
			zone = entry.Value
		}
	}
	// The inventory may target a different project or zone from this host.
	if project == "" || zone == "" ||
		(cfg.ProjectID != "" && cfg.ProjectID != project) ||
		(cfg.Zone != "" && cfg.Zone != zone) {
		return ""
	}
	return node.GCEInstanceID
}
