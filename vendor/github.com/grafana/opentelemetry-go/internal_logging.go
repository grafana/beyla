// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel // import "github.com/grafana/opentelemetry-go"

import (
	"github.com/go-logr/logr"

	"github.com/grafana/opentelemetry-go/internal/global"
)

// SetLogger configures the logger used internally to opentelemetry.
func SetLogger(logger logr.Logger) {
	global.SetLogger(logger)
}
