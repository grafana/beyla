// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package transform // import "go.opentelemetry.io/obi/pkg/transform"

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awsecs "github.com/aws/aws-sdk-go-v2/service/ecs"

	"go.opentelemetry.io/obi/pkg/cloud"
	"go.opentelemetry.io/obi/pkg/metadata"
)

func rlog() *slog.Logger {
	return slog.With("component", "CloudMetadataRefresher")
}

// CloudMetadataRefreshers returns enabled refreshers in order of increasing priority.
func CloudMetadataRefreshers(
	ctx context.Context,
	nodeMeta *metadata.NodeMeta,
	cfg *NameResolverConfig,
	cloudCfg CloudMetadataConfig,
) []cloud.MetadataRefresher {
	var refreshers []cloud.MetadataRefresher
	if cfg == nil {
		return refreshers
	}
	enabled := resolverSources(cfg.Sources)
	if nodeMeta.Features.Has(metadata.ClusterAzureVM) && !nodeMeta.Features.Has(metadata.ClusterK8s) &&
		enabled.Has(ResolverAzure) {
		if refresher, err := azureInventoryRefresher(nodeMeta, cfg.Azure, cloudCfg); err != nil {
			rlog().Warn("cloud metadata not available", "source", SourceAzure, "error", err)
		} else {
			refreshers = append(refreshers, refresher)
		}
	}
	if nodeMeta.Features.Has(metadata.ClusterEC2) && enabled.Has(ResolverRoute53) {
		if refresher, err := route53InventoryRefresher(ctx, nodeMeta, cloudCfg); err != nil {
			rlog().Warn("cloud metadata not available", "source", SourceRoute53, "error", err)
		} else {
			refreshers = append(refreshers, refresher)
		}
	}
	if nodeMeta.Features.Has(metadata.ClusterGCP) && enabled.Has(ResolverGCE) {
		if refresher, err := gceInventoryRefresher(ctx, nodeMeta, cfg.GCE, cloudCfg); err != nil {
			rlog().Warn("cloud metadata not available", "source", SourceGCE, "error", err)
		} else if refresher != nil {
			refreshers = append(refreshers, refresher)
		}
	}
	if nodeMeta.Features.Has(metadata.ClusterECS) && enabled.Has(ResolverECS) {
		// TODO (later PR in this stack): return error and implement mechanism
		if refresher, err := ecsInventoryRefresher(ctx, nodeMeta, cloudCfg); err != nil {
			rlog().Warn("cloud metadata not available", "source", SourceECS, "error", err)
		} else {
			refreshers = append(refreshers, refresher)
		}
	}
	return refreshers
}

func ecsInventoryRefresher(
	ctx context.Context,
	nodeMeta *metadata.NodeMeta,
	cloudCfg CloudMetadataConfig,
) (cloud.MetadataRefresher, error) {
	if cloudCfg.RefreshInterval <= 0 {
		return nil, errors.New("initializing ECS name resolver: a positive refresh interval is required")
	}
	cluster, region := cloudCfg.ClusterName, cloudCfg.Region
	if cluster == "" {
		cluster = nodeMeta.Cluster
	}
	if region == "" {
		region = nodeMeta.Region
	}
	if cluster == "" || region == "" {
		return nil, errors.New("initializing ECS name resolver: configure cloud_metadata.cluster_name and cloud_metadata.region when cloud metadata does not supply them")
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("loading AWS configuration for ECS name resolver: %w", err)
	}
	return cloud.NewECSRefresher(awsecs.NewFromConfig(awsCfg), cluster), nil
}
