// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

/*
Package otel provides global access to the OpenTelemetry API. The subpackages of
the otel package provide an implementation of the OpenTelemetry API.

The provided API is used to instrument code and measure data about that code's
performance and operation. The measured data, by default, is not processed or
transmitted anywhere. An implementation of the OpenTelemetry SDK, like the
default SDK implementation (github.com/grafana/opentelemetry-go/sdk), and associated
exporters are used to process and transport this data.

To read the getting started guide, see https://opentelemetry.io/docs/languages/go/getting-started/.

To read more about tracing, see github.com/grafana/opentelemetry-go/trace.

To read more about metrics, see github.com/grafana/opentelemetry-go/metric.

To read more about propagation, see github.com/grafana/opentelemetry-go/propagation and
github.com/grafana/opentelemetry-go/baggage.
*/
package otel // import "github.com/grafana/opentelemetry-go"
