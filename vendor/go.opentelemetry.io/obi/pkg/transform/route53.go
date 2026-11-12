// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package transform // import "go.opentelemetry.io/obi/pkg/transform"

import (
	"context"
	"fmt"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/route53"

	"go.opentelemetry.io/obi/pkg/cloud"
	"go.opentelemetry.io/obi/pkg/metadata"
)

// route53DefaultRegion is used only when neither the configuration, the cloud
// metadata, nor the AWS SDK environment provide a region.
const route53DefaultRegion = "us-east-1"

type Route53MetadataConfig = metadata.Route53MetadataConfig

func route53InventoryRefresher(
	ctx context.Context,
	nodeMeta *metadata.NodeMeta,
	cloudCfg CloudMetadataConfig,
) (cloud.MetadataRefresher, error) {
	if err := cloudCfg.Route53.Validate(); err != nil {
		return nil, fmt.Errorf("initializing Route53 name resolver: %w", err)
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, route53RegionOption(nodeMeta, cloudCfg))
	if err != nil {
		return nil, fmt.Errorf("loading AWS configuration for Route53 name resolver: %w", err)
	}
	inventory := cloud.NewRoute53Inventory(route53.NewFromConfig(awsCfg), cloudCfg.Route53.HostedZoneIDs)
	inventory.VPCID = nodeMeta.EC2VPCID
	inventory.VPCRegion = nodeMeta.Region
	inventory.RefreshInterval = cloudCfg.Route53.RefreshInterval
	return inventory, nil
}

// route53RegionOption selects the region, and therefore the AWS partition, of the Route53 client.
func route53RegionOption(nodeMeta *metadata.NodeMeta, cloudCfg CloudMetadataConfig) func(*awsconfig.LoadOptions) error {
	region := cloudCfg.Region
	if region == "" {
		region = nodeMeta.Region
	}
	if region == "" {
		return awsconfig.WithDefaultRegion(route53DefaultRegion)
	}
	return awsconfig.WithRegion(region)
}
