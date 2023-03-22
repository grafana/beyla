package otel

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"golang.org/x/exp/slog"

	"github.com/grafana/http-autoinstrument/pkg/spanner"
	"github.com/mariomac/pipes/pkg/node"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/metric/instrument"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
)

type MetricsConfig struct {
	ServiceName     string        `yaml:"service_name" env:"SERVICE_NAME"`
	Interval        time.Duration `yaml:"interval" env:"METRICS_INTERVAL"`
	Endpoint        string        `yaml:"endpoint" env:"OTEL_EXPORTER_OTLP_ENDPOINT"`
	MetricsEndpoint string        `yaml:"-" env:"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"`
}

// Enabled specifies that the OTEL metrics node is enabled if and only if
// either the OTEL endpoint and OTEL metrics endpoint is defined.
// If not enabled, this node won't be instantiated
func (m MetricsConfig) Enabled() bool {
	return m.Endpoint != "" || m.MetricsEndpoint != ""
}

type MetricsReporter struct {
	exporter metric.Exporter
	provider *metric.MeterProvider
	duration instrument.Float64Histogram
}

func MetricsReporterProvider(cfg MetricsConfig) node.TerminalFunc[spanner.HTTPRequestSpan] {
	endpoint := cfg.MetricsEndpoint
	if endpoint == "" {
		endpoint = cfg.Endpoint
	}
	mr, err := newMetricsReporter(cfg.ServiceName, endpoint, cfg.Interval)
	if err != nil {
		slog.Error("can't instantiate OTEL metrics reporter", err)
		os.Exit(-1)
	}
	return mr.reportMetrics
}

func newMetricsReporter(svcName, endpoint string, interval time.Duration) (*MetricsReporter, error) {
	ctx := context.TODO()

	mr := MetricsReporter{}

	// TODO: make configurable
	resources := resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceNameKey.String(svcName),
	)
	var err error
	// TODO: allow configuring auth headers and secure/insecure connections
	mr.exporter, err = otlpmetrichttp.New(ctx,
		otlpmetrichttp.WithEndpoint(endpoint),
		otlpmetrichttp.WithInsecure(),
	)
	if err != nil {
		return nil, fmt.Errorf("creating metric exporter: %w", err)
	}
	mr.provider = metric.NewMeterProvider(
		metric.WithResource(resources),
		metric.WithReader(metric.NewPeriodicReader(mr.exporter,
			metric.WithInterval(interval))),
	)
	mr.duration, err = mr.provider.Meter(reporterName).
		Float64Histogram("duration", instrument.WithUnit("ms"))
	if err != nil {
		return nil, fmt.Errorf("creating duration histogram metric: %w", err)
	}
	return &mr, nil
}

func (r *MetricsReporter) close() {
	if err := r.provider.Shutdown(context.TODO()); err != nil {
		slog.With("component", "MetricsReporter").Error("closing metrics provider", err)
	}
	if err := r.exporter.Shutdown(context.TODO()); err != nil {
		slog.With("component", "MetricsReporter").Error("closing metrics exporter", err)
	}
}

func (r *MetricsReporter) reportMetrics(spans <-chan spanner.HTTPRequestSpan) {
	defer r.close()
	for span := range spans {
		ip, port, err := net.SplitHostPort(span.RemoteAddr)
		peer := ""
		peerPort := 0

		if err != nil {
			peer = span.RemoteAddr
		} else {
			peer = ip
			peerPort, _ = strconv.Atoi(port)
		}

		// TODO: for more accuracy, there must be a way to set the metric time from the actual span end time
		r.duration.Record(context.TODO(),
			span.End.Sub(span.Start).Seconds()*1000,
			semconv.HTTPMethod(span.Method),
			semconv.HTTPStatusCode(span.Status),
			semconv.HTTPTarget(span.Path),
			semconv.NetPeerName(peer),
			semconv.NetPeerPort(peerPort),
		)
	}
}
