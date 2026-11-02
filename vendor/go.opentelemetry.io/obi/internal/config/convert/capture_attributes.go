// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert // import "go.opentelemetry.io/obi/internal/config/convert"

import (
	"errors"

	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/obi"
)

func applyV2CaptureAttributes(cfg *obi.Config, src *schema.Extension) error {
	if src.Capture.Attributes == nil || src.Capture.Attributes.Select == nil {
		return nil
	}
	selection := cloneAttributeSelection(src.Capture.Attributes.Select)
	selection.Normalize()
	if _, exists := selection[attributes.Resource.Section]; exists {
		return errors.New("capture.attributes.select.resource is not supported: use enrich.attributes.select.resource in standalone mode or a Collector processor in receiver mode")
	}
	legacy := cloneAttributeSelection(cfg.Attributes.Select)
	legacy.Normalize()
	for key := range legacy {
		if key != attributes.Resource.Section {
			return errors.New("capture.attributes.select and the legacy enrich.attributes.select generation settings cannot both be configured; put trace and metric selections together in capture.attributes.select")
		}
	}
	if resource, exists := legacy[attributes.Resource.Section]; exists {
		selection[attributes.Resource.Section] = resource
	}
	cfg.Attributes.Select = selection
	return nil
}

func captureAttributes(cfg *obi.Config) *schema.CaptureAttributes {
	selection := cloneAttributeSelection(cfg.Attributes.Select)
	delete(selection, attributes.Resource.Section)
	if len(selection) == 0 {
		return nil
	}
	return &schema.CaptureAttributes{Select: selection}
}

func resourceAttributeSelection(selection attributes.Selection) attributes.Selection {
	if resource, exists := selection[attributes.Resource.Section]; exists {
		return attributes.Selection{attributes.Resource.Section: {
			Include: cloneStrings(resource.Include),
			Exclude: cloneStrings(resource.Exclude),
		}}
	}
	return nil
}
