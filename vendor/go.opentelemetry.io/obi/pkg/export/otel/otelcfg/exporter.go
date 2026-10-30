// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otelcfg // import "go.opentelemetry.io/obi/pkg/export/otel/otelcfg"

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

func meilog() *slog.Logger {
	return slog.With("component", "otelcommon.MetricsExporterInstancer")
}

// MetricsExporterInstancer provides a common instance for the OTEL metrics exporter,
// so all the OTEL metric families (RED, Network, Service Graph, Internal...) would go through
// the same connection/instance
type MetricsExporterInstancer struct {
	mutex    sync.Mutex
	instance sdkmetric.Exporter
	Cfg      *MetricsConfig
}

// Instantiate the OTLP HTTP or GRPC metrics exporter, or a consumer-based exporter
func (i *MetricsExporterInstancer) Instantiate(ctx context.Context) (sdkmetric.Exporter, error) {
	i.mutex.Lock()
	defer i.mutex.Unlock()
	if i.instance != nil {
		return i.instance, nil
	}

	// If a metrics export callback is configured, use the OTLP exporter.
	if i.Cfg.MetricsExport != nil {
		meilog().Debug("instantiating OTLP MetricsReporter")
		i.instance = NewOTLPConsumerExporter(i.Cfg.MetricsExport)
		return i.instance, nil
	}

	var err error
	switch proto := i.Cfg.GetProtocol(); proto {
	case ProtocolHTTPJSON, ProtocolHTTPProtobuf, "": // zero value defaults to HTTP for backwards-compatibility
		meilog().Debug("instantiating HTTP MetricsReporter", "protocol", proto)
		if proto == ProtocolHTTPJSON {
			// http/json is optional for SDKs: https://github.com/open-telemetry/opentelemetry-specification/blob/v1.49.0/specification/protocol/exporter.md#specify-protocol
			// Remove this fallback once otlpmetrichttp supports it: https://github.com/open-telemetry/opentelemetry-go/issues/7803
			meilog().Warn("OTLP metrics exporter does not support JSON encoding, sending metrics as http/protobuf", "protocol", proto)
		}
		if i.instance, err = i.httpMetricsExporter(ctx); err != nil {
			return nil, fmt.Errorf("can't instantiate OTEL HTTP metrics exporter: %w", err)
		}
	case ProtocolGRPC:
		meilog().Debug("instantiating GRPC MetricsReporter", "protocol", proto)
		if i.instance, err = i.grpcMetricsExporter(ctx); err != nil {
			return nil, fmt.Errorf("can't instantiate OTEL GRPC metrics exporter: %w", err)
		}
	default:
		return nil, fmt.Errorf("invalid protocol value: %q. Accepted values are: %s, %s, %s",
			proto, ProtocolGRPC, ProtocolHTTPJSON, ProtocolHTTPProtobuf)
	}
	return i.instance, nil
}

func (i *MetricsExporterInstancer) httpMetricsExporter(ctx context.Context) (sdkmetric.Exporter, error) {
	opts, err := httpMetricEndpointOptions(i.Cfg)
	if err != nil {
		return nil, err
	}
	mexp, err := otlpmetrichttp.New(ctx, opts.AsMetricHTTP()...)
	if err != nil {
		return nil, fmt.Errorf("creating HTTP metric exporter: %w", err)
	}
	return mexp, nil
}

func (i *MetricsExporterInstancer) grpcMetricsExporter(ctx context.Context) (sdkmetric.Exporter, error) {
	opts, err := grpcMetricEndpointOptions(i.Cfg)
	if err != nil {
		return nil, err
	}
	mexp, err := otlpmetricgrpc.New(ctx, opts.AsMetricGRPC()...)
	if err != nil {
		return nil, fmt.Errorf("creating GRPC metric exporter: %w", err)
	}
	return mexp, nil
}
