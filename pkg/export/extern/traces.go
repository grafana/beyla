// Package extern provides trace exporting capabilities for inter-cluster connection spans.
package extern

import (
	"fmt"

	"go.opentelemetry.io/obi/pkg/app/request"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/otel/attribute"
)
