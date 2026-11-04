// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert // import "go.opentelemetry.io/obi/internal/config/convert"

import "go.opentelemetry.io/obi/internal/config/schema"

func validateUnsupportedV2Enrichment(src *schema.Extension) error {
	if src.Enrich == nil {
		return nil
	}

	for _, properties := range []struct {
		path   string
		values map[string]any
	}{
		{path: "enrich", values: src.Enrich.AdditionalProperties},
		{path: "enrich.enrichers", values: src.Enrich.Enrichers.AdditionalProperties},
		{path: "enrich.enrichers.peer_metadata", values: src.Enrich.Enrichers.PeerMetadata.AdditionalProperties},
		{path: "enrich.enrichers.peer_metadata.tls", values: src.Enrich.Enrichers.PeerMetadata.TLS.AdditionalProperties},
		{path: "enrich.enrichers.kubernetes", values: src.Enrich.Enrichers.Kubernetes.AdditionalProperties},
		{path: "enrich.enrichers.cloud", values: src.Enrich.Enrichers.Cloud.AdditionalProperties},
		{path: "enrich.enrichers.cloud.route53", values: src.Enrich.Enrichers.Cloud.Route53.AdditionalProperties},
		{path: "enrich.service_name", values: src.Enrich.ServiceName.AdditionalProperties},
		{path: "enrich.service_name.azure", values: src.Enrich.ServiceName.Azure.AdditionalProperties},
		{path: "enrich.attributes", values: src.Enrich.Attributes.AdditionalProperties},
	} {
		if err := rejectAdditionalProperties(properties.path, properties.values); err != nil {
			return err
		}
	}

	return nil
}
