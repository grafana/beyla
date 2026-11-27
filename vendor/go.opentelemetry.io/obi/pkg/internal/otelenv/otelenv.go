// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package otelenv parses the key=value lists used by OTEL_RESOURCE_ATTRIBUTES
// and the OTLP headers environment variables.
package otelenv // import "go.opentelemetry.io/obi/pkg/internal/otelenv"

import (
	"net/url"
	"strings"

	"go.opentelemetry.io/obi/pkg/internal/split"
)

// ParseKeyValues passes each key=value pair to the handler, with the value as written.
func ParseKeyValues(envVar string, handler func(k, v string)) {
	variables := split.NewStringIterator(envVar, ",")

	for {
		variable, eof := variables.Next()

		if eof {
			break
		}

		variable = strings.TrimSuffix(variable, ",")

		key, value, found := strings.Cut(variable, "=")

		if !found {
			continue
		}

		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		if key == "" || value == "" {
			continue
		}

		handler(key, value)
	}
}

// DecodeValue percent-decodes a value, keeping it raw if the escapes are
// malformed, like the Go SDK.
func DecodeValue(value string) string {
	if decoded, err := url.PathUnescape(value); err == nil {
		return decoded
	}

	return value
}
