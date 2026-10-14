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

	"go.opentelemetry.io/obi/pkg/internal/ecs"
	"go.opentelemetry.io/obi/pkg/metadata"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

func eclog() *slog.Logger {
	return slog.With("component", "ECSInventoryProvider")
}

// ECSInventoryProvider initializes the shared inventory before its consumers and
// runs periodic refreshes for the lifetime of the application pipeline.
func ECSInventoryProvider(ctxInfo *global.ContextInfo, cfg *NameResolverConfig, cloudCfg CloudMetadataConfig) swarm.InstanceFunc {
	return func(ctx context.Context) (swarm.RunFunc, error) {
		if cfg == nil || !resolverSources(cfg.Sources).Has(ResolverECS) {
			return swarm.EmptyRunFunc()
		}
		if !ctxInfo.NodeMeta.Features.Has(metadata.ClusterECS) {
			eclog().Debug("could not detect ECS Metadata. Deactivating")
			return swarm.EmptyRunFunc()
		}
		if cfg.ECS.RefreshInterval <= 0 {
			return nil, errors.New("initializing ECS name resolver: a positive refresh interval is required")
		}
		cluster, region := cloudCfg.ClusterName, cloudCfg.Region
		if cluster == "" {
			cluster = ctxInfo.NodeMeta.Cluster
		}
		if region == "" {
			region = ctxInfo.NodeMeta.Region
		}
		if cluster == "" || region == "" {
			return nil, errors.New("initializing ECS name resolver: configure cloud_metadata.cluster_name and cloud_metadata.region when cloud metadata does not supply them")
		}
		awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
		if err != nil {
			return nil, fmt.Errorf("loading AWS configuration for ECS name resolver: %w", err)
		}
		inventory := ecs.NewInventory(awsecs.NewFromConfig(awsCfg), cluster)
		if err := inventory.Refresh(ctx); err != nil {
			nrlog().Warn("can't load initial ECS task inventory; will retry", "error", err)
		}
		ctxInfo.ECSInventory = inventory
		return func(ctx context.Context) {
			inventory.Run(ctx, cfg.ECS.RefreshInterval)
		}, nil
	}
}
