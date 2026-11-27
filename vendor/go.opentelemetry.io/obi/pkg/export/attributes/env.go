// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package attributes // import "go.opentelemetry.io/obi/pkg/export/attributes"

import "go.opentelemetry.io/obi/pkg/internal/otelenv"

type VarHandler func(k string, v string)

// ParseOTELResourceVariable passes percent-decoded values to the handler.
func ParseOTELResourceVariable(envVar string, handler VarHandler) {
	otelenv.ParseKeyValues(envVar, func(k, v string) { handler(k, otelenv.DecodeValue(v)) })
}
