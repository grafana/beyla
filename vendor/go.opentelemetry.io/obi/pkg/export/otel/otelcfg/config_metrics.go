// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otelcfg

import (
	"fmt"
	"log/slog"
	"maps"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"
)

func mlog() *slog.Logger {
	return slog.With("component", "otelcfg.MetricsConfig")
}

type MetricsConfig struct {
	Interval time.Duration `yaml:"interval" env:"OTEL_EBPF_METRICS_INTERVAL"`
	// OTELIntervalMS supports metric intervals as specified by the standard OTEL definition.
	// OTEL_EBPF_METRICS_INTERVAL takes precedence over it.
	OTELIntervalMS int `env:"OTEL_METRIC_EXPORT_INTERVAL"`

	CommonEndpoint  string `yaml:"-" env:"OTEL_EXPORTER_OTLP_ENDPOINT"`
	MetricsEndpoint string `yaml:"endpoint" env:"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"`

	Protocol        Protocol `yaml:"protocol" env:"OTEL_EXPORTER_OTLP_PROTOCOL"`
	MetricsProtocol Protocol `yaml:"-" env:"OTEL_EXPORTER_OTLP_METRICS_PROTOCOL"`

	// InsecureSkipVerify is not standard, so we don't follow the same naming convention
	InsecureSkipVerify bool `yaml:"insecure_skip_verify" env:"OTEL_EBPF_INSECURE_SKIP_VERIFY"`

	Buckets              Buckets `yaml:"buckets"`
	HistogramAggregation string  `yaml:"histogram_aggregation" env:"OTEL_EXPORTER_OTLP_METRICS_DEFAULT_HISTOGRAM_AGGREGATION"`

	ReportersCacheLen int `yaml:"reporters_cache_len" env:"OTEL_EBPF_METRICS_REPORT_CACHE_LEN"`

	// SDKLogLevel works independently from the global LogLevel because it prints GBs of logs in Debug mode
	// and the Info messages leak internal details that are not usually valuable for the final user.
	SDKLogLevel string `yaml:"otel_sdk_log_level" env:"OTEL_EBPF_SDK_LOG_LEVEL"`

	// Features of metrics that are can be exported. Accepted values are "application" and "network".
	// envDefault is provided to avoid breaking changes
	Features []string `yaml:"features" env:"OTEL_EBPF_METRICS_FEATURES,expand" envDefault:"${OTEL_EBPF_METRIC_FEATURES}"  envSeparator:","`

	// Allows configuration of which instrumentations should be enabled, e.g. http, grpc, sql...
	Instrumentations []string `yaml:"instrumentations" env:"OTEL_EBPF_METRICS_INSTRUMENTATIONS" envSeparator:","`

	// TTL is the time since a metric was updated for the last time until it is
	// removed from the metrics set.
	TTL time.Duration `yaml:"ttl" env:"OTEL_EBPF_METRICS_TTL"`

	AllowServiceGraphSelfReferences bool `yaml:"allow_service_graph_self_references" env:"OTEL_EBPF_ALLOW_SERVICE_GRAPH_SELF_REFERENCES"`

	// DropUnresolvedIPs drops metrics that contain unresolved IP addresses to reduce cardinality
	DropUnresolvedIPs bool `yaml:"drop_unresolved_ips" env:"OTEL_EBPF_DROP_UNRESOLVED_IPS"`

	// OTLPEndpointProvider allows overriding the OTLP Endpoint. It needs to return an endpoint and
	// a boolean indicating if the endpoint is common for both traces and metrics
	OTLPEndpointProvider func() (string, bool) `yaml:"-" env:"-"`

	// InjectHeaders allows injecting custom headers to the HTTP OTLP exporter
	InjectHeaders func(dst map[string]string) `yaml:"-" env:"-"`
}

func (m MetricsConfig) MarshalYAML() (any, error) {
	omit := map[string]struct{}{
		"endpoint": {},
	}
	return omitFieldsForYAML(m, omit), nil
}

func (m *MetricsConfig) GetProtocol() Protocol {
	if m.MetricsProtocol != "" {
		return m.MetricsProtocol
	}
	if m.Protocol != "" {
		return m.Protocol
	}
	return m.GuessProtocol()
}

func (m *MetricsConfig) GetInterval() time.Duration {
	if m.Interval == 0 {
		return time.Duration(m.OTELIntervalMS) * time.Millisecond
	}
	return m.Interval
}

func (m *MetricsConfig) GuessProtocol() Protocol {
	// If no explicit protocol is set, we guess it from the metrics endpoint port
	// (assuming it uses a standard port or a development-like form like 14317, 24317, 14318...)
	ep, _, err := parseMetricsEndpoint(m)
	if err == nil {
		if strings.HasSuffix(ep.Port(), UsualPortGRPC) {
			return ProtocolGRPC
		} else if strings.HasSuffix(ep.Port(), UsualPortHTTP) {
			return ProtocolHTTPProtobuf
		}
	}
	// Otherwise we return default protocol according to the latest specification:
	// https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/protocol/exporter.md?plain=1#L53
	return ProtocolHTTPProtobuf
}

func (m *MetricsConfig) OTLPMetricsEndpoint() (string, bool) {
	if m.OTLPEndpointProvider != nil {
		return m.OTLPEndpointProvider()
	}
	return ResolveOTLPEndpoint(m.MetricsEndpoint, m.CommonEndpoint)
}

// EndpointEnabled specifies that the OTEL metrics node is enabled if and only if
// either the OTEL endpoint and OTEL metrics endpoint is defined.
// If not enabled, this node won't be instantiated
// Reason to disable linting: it requires to be a value despite it is considered a "heavy struct".
// This method is invoked only once during startup time so it doesn't have a noticeable performance impact.
func (m *MetricsConfig) EndpointEnabled() bool {
	ep, _ := m.OTLPMetricsEndpoint()
	return ep != ""
}

func (m *MetricsConfig) AnySpanMetricsEnabled() bool {
	return m.SpanMetricsEnabled() || m.SpanMetricsSizesEnabled() || m.ServiceGraphMetricsEnabled()
}

func (m *MetricsConfig) SpanMetricsSizesEnabled() bool {
	return slices.Contains(m.Features, FeatureSpanSizes)
}

func (m *MetricsConfig) SpanMetricsEnabled() bool {
	return slices.Contains(m.Features, FeatureSpan) || slices.Contains(m.Features, FeatureSpanOTel)
}

func (m *MetricsConfig) InvalidSpanMetricsConfig() bool {
	return slices.Contains(m.Features, FeatureSpan) && slices.Contains(m.Features, FeatureSpanOTel)
}

func (m *MetricsConfig) HostMetricsEnabled() bool {
	return slices.Contains(m.Features, FeatureApplicationHost)
}

func (m *MetricsConfig) ServiceGraphMetricsEnabled() bool {
	return slices.Contains(m.Features, FeatureGraph)
}

func (m *MetricsConfig) OTelMetricsEnabled() bool {
	return slices.Contains(m.Features, FeatureApplication)
}

func (m *MetricsConfig) NetworkMetricsEnabled() bool {
	return m.NetworkFlowBytesEnabled() || m.NetworkInterzoneMetricsEnabled()
}

func (m *MetricsConfig) NetworkFlowBytesEnabled() bool {
	return slices.Contains(m.Features, FeatureNetwork)
}

func (m *MetricsConfig) NetworkInterzoneMetricsEnabled() bool {
	return slices.Contains(m.Features, FeatureNetworkInterZone)
}

func (m *MetricsConfig) Enabled() bool {
	return m.EndpointEnabled() && (m.OTelMetricsEnabled() || m.AnySpanMetricsEnabled() || m.NetworkMetricsEnabled())
}

func httpMetricEndpointOptions(cfg *MetricsConfig) (OTLPOptions, error) {
	opts := OTLPOptions{Headers: map[string]string{}}
	log := mlog().With("transport", "http")
	murl, isCommon, err := parseMetricsEndpoint(cfg)
	if err != nil {
		return opts, err
	}
	log.Debug("Configuring exporter",
		"protocol", cfg.Protocol, "metricsProtocol", cfg.MetricsProtocol, "endpoint", murl.Host)

	setMetricsProtocol(cfg)
	opts.Endpoint = murl.Host
	if murl.Scheme == "http" || murl.Scheme == "unix" {
		log.Debug("Specifying insecure connection", "scheme", murl.Scheme)
		opts.Insecure = true
	}
	// If the value is set from the OTEL_EXPORTER_OTLP_ENDPOINT common property, we need to add /v1/metrics to the path
	// otherwise, we leave the path that is explicitly set by the user
	opts.URLPath = murl.Path
	if isCommon {
		if strings.HasSuffix(opts.URLPath, "/") {
			opts.URLPath += "v1/metrics"
		} else {
			opts.URLPath += "/v1/metrics"
		}
	}
	log.Debug("Specifying path", "path", opts.URLPath)

	if cfg.InsecureSkipVerify {
		log.Debug("Setting InsecureSkipVerify")
		opts.SkipTLSVerify = cfg.InsecureSkipVerify
	}

	if cfg.InjectHeaders != nil {
		cfg.InjectHeaders(opts.Headers)
	}
	maps.Copy(opts.Headers, HeadersFromEnv(envHeaders))
	maps.Copy(opts.Headers, HeadersFromEnv(envMetricsHeaders))

	return opts, nil
}

func grpcMetricEndpointOptions(cfg *MetricsConfig) (OTLPOptions, error) {
	opts := OTLPOptions{Headers: map[string]string{}}
	log := mlog().With("transport", "grpc")
	murl, _, err := parseMetricsEndpoint(cfg)
	if err != nil {
		return opts, err
	}
	log.Debug("Configuring exporter",
		"protocol", cfg.Protocol, "metricsProtocol", cfg.MetricsProtocol, "endpoint", murl.Host)

	setMetricsProtocol(cfg)
	opts.Endpoint = murl.Host
	if murl.Scheme == "http" || murl.Scheme == "unix" {
		log.Debug("Specifying insecure connection", "scheme", murl.Scheme)
		opts.Insecure = true
	}
	if cfg.InsecureSkipVerify {
		log.Debug("Setting InsecureSkipVerify")
		opts.SkipTLSVerify = true
	}

	if cfg.InjectHeaders != nil {
		cfg.InjectHeaders(opts.Headers)
	}
	maps.Copy(opts.Headers, HeadersFromEnv(envHeaders))
	maps.Copy(opts.Headers, HeadersFromEnv(envMetricsHeaders))

	return opts, nil
}

// the HTTP path will be defined from one of the following sources, from highest to lowest priority
// - the result from any overridden OTLP Provider function
// - OTEL_EXPORTER_OTLP_METRICS_ENDPOINT, if defined
// - OTEL_EXPORTER_OTLP_ENDPOINT, if defined
func parseMetricsEndpoint(cfg *MetricsConfig) (*url.URL, bool, error) {
	endpoint, isCommon := cfg.OTLPMetricsEndpoint()

	murl, err := url.Parse(endpoint)
	if err != nil {
		return nil, isCommon, fmt.Errorf("parsing endpoint URL %s: %w", endpoint, err)
	}
	if murl.Scheme == "" || murl.Host == "" {
		return nil, isCommon, fmt.Errorf("URL %q must have a scheme and a host", endpoint)
	}
	return murl, isCommon, nil
}

// HACK: at the time of writing this, the otelpmetrichttp API does not support explicitly
// setting the protocol. They should be properly set via environment variables, but
// if the user supplied the value via configuration file (and not via env vars), we override the environment.
// To be as least intrusive as possible, we will change the variables if strictly needed
// TODO: remove this once otelpmetrichttp.WithProtocol is supported
func setMetricsProtocol(cfg *MetricsConfig) {
	if _, ok := os.LookupEnv(envMetricsProtocol); ok {
		return
	}
	if _, ok := os.LookupEnv(envProtocol); ok {
		return
	}
	if cfg.MetricsProtocol != "" {
		os.Setenv(envMetricsProtocol, string(cfg.MetricsProtocol))
		return
	}
	if cfg.Protocol != "" {
		os.Setenv(envProtocol, string(cfg.Protocol))
		return
	}
	// unset. Guessing it
	os.Setenv(envMetricsProtocol, string(cfg.GuessProtocol()))
}
