// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracetransform // import "github.com/grafana/opentelemetry-go/exporters/otlp/otlptrace/internal/tracetransform"

import (
	"github.com/grafana/opentelemetry-go/sdk/resource"

	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
)

// Resource transforms a Resource into an OTLP Resource.
func Resource(r *resource.Resource) *resourcepb.Resource {
	if r == nil {
		return nil
	}
	return &resourcepb.Resource{Attributes: ResourceAttributes(r)}
}
