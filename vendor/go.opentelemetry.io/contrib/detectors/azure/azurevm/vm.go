// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package azurevm // import "go.opentelemetry.io/contrib/detectors/azure/azurevm"

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

const defaultAzureVMMetadataEndpoint = "http://169.254.169.254/metadata/instance/compute?api-version=2021-12-13&format=json"

// ResourceDetector collects resource information of Azure VMs.
type ResourceDetector struct {
	endpoint string
}

type vmMetadata struct {
	VMId       *string `json:"vmId"`
	Location   *string `json:"location"`
	ResourceId *string `json:"resourceId"`
	Name       *string `json:"name"`
	VMSize     *string `json:"vmSize"`
	OsType     *string `json:"osType"`
	Version    *string `json:"version"`
}

// New returns a [ResourceDetector] that will detect Azure VM resources.
func New() *ResourceDetector {
	return &ResourceDetector{defaultAzureVMMetadataEndpoint}
}

// Detect detects associated resources when running on an Azure VM.
func (detector *ResourceDetector) Detect(ctx context.Context) (*resource.Resource, error) {
	jsonMetadata, runningInAzure, err := detector.getJSONMetadata(ctx)
	if err != nil {
		if !runningInAzure {
			return resource.Empty(), nil
		}

		return nil, err
	}

	var metadata vmMetadata
	err = json.Unmarshal(jsonMetadata, &metadata)
	if err != nil {
		return nil, err
	}

	attributes := []attribute.KeyValue{
		semconv.CloudProviderAzure,
		semconv.CloudPlatformAzureVM,
	}

	if metadata.VMId != nil {
		attributes = append(attributes, semconv.HostID(*metadata.VMId))
	}
	if metadata.Location != nil {
		attributes = append(attributes, semconv.CloudRegion(*metadata.Location))
	}
	if metadata.ResourceId != nil {
		attributes = append(attributes, semconv.CloudResourceID(*metadata.ResourceId))
	}
	if metadata.Name != nil {
		attributes = append(attributes, semconv.HostName(*metadata.Name))
	}
	if metadata.VMSize != nil {
		attributes = append(attributes, semconv.HostType(*metadata.VMSize))
	}
	if metadata.OsType != nil {
		attributes = append(attributes, semconv.OSTypeKey.String(*metadata.OsType))
	}
	if metadata.Version != nil {
		attributes = append(attributes, semconv.OSVersion(*metadata.Version))
	}

	return resource.NewWithAttributes(semconv.SchemaURL, attributes...), nil
}

func (detector *ResourceDetector) getJSONMetadata(ctx context.Context) ([]byte, bool, error) {
	pTransport := &http.Transport{Proxy: nil}

	client := http.Client{Transport: pTransport}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, detector.endpoint, nil)
	if err != nil {
		return nil, false, err
	}

	req.Header.Add("Metadata", "True")

	resp, err := client.Do(req) // nolint:bodyclose  // False-positive.
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		bytes, err := io.ReadAll(resp.Body)
		return bytes, true, err
	}

	runningInAzure := resp.StatusCode < 400 || resp.StatusCode > 499

	return nil, runningInAzure, errors.New(http.StatusText(resp.StatusCode))
}
