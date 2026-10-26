// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package transform // import "go.opentelemetry.io/obi/pkg/transform"

import (
	"errors"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v9"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"

	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"

	"go.opentelemetry.io/obi/pkg/cloud"
	"go.opentelemetry.io/obi/pkg/metadata"
)

// detectedAzureScope reads the ARM resource ID retained by the Azure detector.
// The VM UUID used for local naming is stored separately from this discovery scope.
func detectedAzureScope(node *metadata.NodeMeta) AzureNameResolverConfig {
	for _, entry := range node.Metadata {
		if string(entry.Key) != string(semconv.CloudResourceIDKey) {
			continue
		}
		id, err := arm.ParseResourceID(entry.Value)
		if err == nil {
			return AzureNameResolverConfig{SubscriptionID: id.SubscriptionID, ResourceGroup: id.ResourceGroupName}
		}
	}
	return AzureNameResolverConfig{}
}

func azureScope(node *metadata.NodeMeta, cfg AzureNameResolverConfig) AzureNameResolverConfig {
	detected := detectedAzureScope(node)
	cfg.SubscriptionID = strings.TrimSpace(cfg.SubscriptionID)
	cfg.ResourceGroup = strings.TrimSpace(cfg.ResourceGroup)
	if cfg.SubscriptionID == "" {
		cfg.SubscriptionID = detected.SubscriptionID
	}
	if cfg.ResourceGroup == "" {
		cfg.ResourceGroup = detected.ResourceGroup
	}
	return cfg
}

// localAzureInstanceID requires detected identity and a matching discovery scope.
// An override can discover remote peers without renaming this host's processes.
func localAzureInstanceID(node *metadata.NodeMeta, cfg *NameResolverConfig) string {
	if cfg == nil || !resolverSources(cfg.Sources).Has(ResolverAzure) ||
		!node.Features.Has(metadata.ClusterAzureVM) || node.Features.Has(metadata.ClusterK8s) || node.AzureInstanceID == "" {
		return ""
	}
	detected := detectedAzureScope(node)
	scope := azureScope(node, cfg.Azure)
	if detected.SubscriptionID == "" || detected.ResourceGroup == "" ||
		!strings.EqualFold(scope.SubscriptionID, detected.SubscriptionID) || !strings.EqualFold(scope.ResourceGroup, detected.ResourceGroup) {
		return ""
	}
	return cloud.AzureInstanceID(detected.SubscriptionID, node.AzureInstanceID)
}

func azureInventoryRefresher(node *metadata.NodeMeta, cfg AzureNameResolverConfig, cloudCfg CloudMetadataConfig) (cloud.MetadataRefresher, error) {
	if cloudCfg.RefreshInterval <= 0 {
		return nil, errors.New("initializing Azure name resolver: a positive refresh interval is required")
	}
	scope := azureScope(node, cfg)
	if scope.SubscriptionID == "" || scope.ResourceGroup == "" {
		return nil, errors.New("initializing Azure name resolver: configure service_name.azure.subscription_id and resource_group when cloud metadata does not supply them")
	}
	credential, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("loading Azure credentials: %w", err)
	}
	// Inventory discovery requires read access only, including on first use.
	opts := &arm.ClientOptions{DisableRPRegistration: true}
	compute, err := armcompute.NewClientFactory(scope.SubscriptionID, credential, opts)
	if err != nil {
		return nil, err
	}
	network, err := armnetwork.NewInterfacesClient(scope.SubscriptionID, credential, opts)
	if err != nil {
		return nil, err
	}
	return cloud.NewAzureRefresher(compute, network, scope.SubscriptionID, scope.ResourceGroup), nil
}
