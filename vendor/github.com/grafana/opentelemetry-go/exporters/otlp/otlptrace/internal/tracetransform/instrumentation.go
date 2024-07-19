// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracetransform // import "github.com/grafana/opentelemetry-go/exporters/otlp/otlptrace/internal/tracetransform"

import (
	"github.com/grafana/opentelemetry-go/sdk/instrumentation"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
)

func InstrumentationScope(il instrumentation.Scope) *commonpb.InstrumentationScope {
	if il == (instrumentation.Scope{}) {
		return nil
	}
	return &commonpb.InstrumentationScope{
		Name:    il.Name,
		Version: il.Version,
	}
}
