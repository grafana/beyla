// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otelcfg

import (
	"fmt"
	"log/slog"
	"maps"
	"net/url"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/services"
)

func tlog() *slog.Logger {
	return slog.With("component", "otelcfg.TracesConfig")
}

type TracesConfig struct {
	CommonEndpoint string `yaml:"-" env:"OTEL_EXPORTER_OTLP_ENDPOINT"`
	TracesEndpoint string `yaml:"endpoint" env:"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"`

	Protocol       Protocol `yaml:"protocol" env:"OTEL_EXPORTER_OTLP_PROTOCOL"`
	TracesProtocol Protocol `yaml:"-" env:"OTEL_EXPORTER_OTLP_TRACES_PROTOCOL"`

	// Allows configuration of which instrumentations should be enabled, e.g. http, grpc, sql...
	Instrumentations []string `yaml:"instrumentations" env:"OTEL_EBPF_TRACES_INSTRUMENTATIONS" envSeparator:","`

	// InsecureSkipVerify is not standard, so we don't follow the same naming convention
	InsecureSkipVerify bool `yaml:"insecure_skip_verify" env:"OTEL_EBPF_INSECURE_SKIP_VERIFY"`

	SamplerConfig services.SamplerConfig `yaml:"sampler"`

	// Configuration options below this line will remain undocumented at the moment,
	// but can be useful for performance-tuning of some customers.
	MaxQueueSize int           `yaml:"max_queue_size" env:"OTEL_EBPF_OTLP_TRACES_MAX_QUEUE_SIZE"`
	BatchTimeout time.Duration `yaml:"batch_timeout" env:"OTEL_EBPF_OTLP_TRACES_BATCH_TIMEOUT"`

	// Configuration options for BackOffConfig of the traces exporter.
	// See https://github.com/open-telemetry/opentelemetry-collector/blob/main/config/configretry/backoff.go
	// BackOffInitialInterval the time to wait after the first failure before retrying.
	BackOffInitialInterval time.Duration `yaml:"backoff_initial_interval" env:"OTEL_EBPF_BACKOFF_INITIAL_INTERVAL"`
	// BackOffMaxInterval is the upper bound on backoff interval.
	BackOffMaxInterval time.Duration `yaml:"backoff_max_interval" env:"OTEL_EBPF_BACKOFF_MAX_INTERVAL"`
	// BackOffMaxElapsedTime is the maximum amount of time (including retries) spent trying to send a request/batch.
	BackOffMaxElapsedTime time.Duration `yaml:"backoff_max_elapsed_time" env:"OTEL_EBPF_BACKOFF_MAX_ELAPSED_TIME"`
	ReportersCacheLen     int           `yaml:"reporters_cache_len" env:"OTEL_EBPF_TRACES_REPORT_CACHE_LEN"`

	// SDKLogLevel works independently from the global LogLevel because it prints GBs of logs in Debug mode
	// and the Info messages leak internal details that are not usually valuable for the final user.
	SDKLogLevel string `yaml:"otel_sdk_log_level" env:"OTEL_EBPF_SDK_LOG_LEVEL"`

	// OTLPEndpointProvider allows overriding the OTLP Endpoint. It needs to return an endpoint and
	// a boolean indicating if the endpoint is common for both traces and metrics
	OTLPEndpointProvider func() (string, bool) `yaml:"-" env:"-"`

	// InjectHeaders allows injecting custom headers to the HTTP OTLP exporter
	InjectHeaders func(dst map[string]string) `yaml:"-" env:"-"`
}

func (m TracesConfig) MarshalYAML() (any, error) {
	omit := map[string]struct{}{
		"endpoint": {},
	}
	return omitFieldsForYAML(m, omit), nil
}

// Enabled specifies that the OTEL traces node is enabled if and only if
// either the OTEL endpoint and OTEL traces endpoint is defined.
// If not enabled, this node won't be instantiated
func (m *TracesConfig) Enabled() bool {
	return m.CommonEndpoint != "" || m.TracesEndpoint != ""
}

func (m *TracesConfig) GetProtocol() Protocol {
	if m.TracesProtocol != "" {
		return m.TracesProtocol
	}
	if m.Protocol != "" {
		return m.Protocol
	}
	return m.guessProtocol()
}

func (m *TracesConfig) OTLPTracesEndpoint() (string, bool) {
	if m.OTLPEndpointProvider != nil {
		return m.OTLPEndpointProvider()
	}
	return ResolveOTLPEndpoint(m.TracesEndpoint, m.CommonEndpoint)
}

func (m *TracesConfig) guessProtocol() Protocol {
	// If no explicit protocol is set, we guess it it from the metrics enpdoint port
	// (assuming it uses a standard port or a development-like form like 14317, 24317, 14318...)
	ep, _, err := ParseTracesEndpoint(m)
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

// ParseTracesEndpoint defines the HTTP path of the traces collector.
// The HTTP path will be defined from one of the following sources, from highest to lowest priority
// - OTEL_EXPORTER_OTLP_TRACES_ENDPOINT, if defined
// - OTEL_EXPORTER_OTLP_ENDPOINT, if defined
// - https://otlp-gateway-${GRAFANA_CLOUD_ZONE}.grafana.net/otlp, if GRAFANA_CLOUD_ZONE is defined
// If, by some reason, Grafana changes its OTLP Gateway URL in a distant future, you can still point to the
// correct URL with the OTLP_EXPORTER_... variables.
func ParseTracesEndpoint(cfg *TracesConfig) (*url.URL, bool, error) {
	endpoint, isCommon := cfg.OTLPTracesEndpoint()

	murl, err := url.Parse(endpoint)
	if err != nil {
		return nil, isCommon, fmt.Errorf("parsing endpoint URL %s: %w", endpoint, err)
	}
	if murl.Scheme == "" || murl.Host == "" {
		return nil, isCommon, fmt.Errorf("URL %q must have a scheme and a host", endpoint)
	}
	return murl, isCommon, nil
}

func HTTPTracesEndpointOptions(cfg *TracesConfig) (OTLPOptions, error) {
	opts := OTLPOptions{Headers: map[string]string{}}
	log := tlog().With("transport", "http")

	murl, isCommon, err := ParseTracesEndpoint(cfg)
	if err != nil {
		return opts, err
	}

	log.Debug("Configuring exporter", "protocol",
		cfg.Protocol, "tracesProtocol", cfg.TracesProtocol, "endpoint", murl.Host)
	setTracesProtocol(cfg)
	opts.Scheme = murl.Scheme
	opts.Endpoint = murl.Host
	if murl.Scheme == "http" || murl.Scheme == "unix" {
		log.Debug("Specifying insecure connection", "scheme", murl.Scheme)
		opts.Insecure = true
	}
	// If the value is set from the OTEL_EXPORTER_OTLP_ENDPOINT common property, we need to add /v1/traces to the path
	// otherwise, we leave the path that is explicitly set by the user
	opts.URLPath = strings.TrimSuffix(murl.Path, "/")
	opts.BaseURLPath = strings.TrimSuffix(opts.URLPath, "/v1/traces")
	if isCommon {
		opts.URLPath += "/v1/traces"
		log.Debug("Specifying path", "path", opts.URLPath)
	}

	if cfg.InsecureSkipVerify {
		log.Debug("Setting InsecureSkipVerify")
		opts.SkipTLSVerify = true
	}

	if cfg.InjectHeaders != nil {
		cfg.InjectHeaders(opts.Headers)
	}
	maps.Copy(opts.Headers, HeadersFromEnv(envHeaders))
	maps.Copy(opts.Headers, HeadersFromEnv(envTracesHeaders))

	return opts, nil
}

func GRPCTracesEndpointOptions(cfg *TracesConfig) (OTLPOptions, error) {
	opts := OTLPOptions{Headers: map[string]string{}}
	log := tlog().With("transport", "grpc")
	murl, _, err := ParseTracesEndpoint(cfg)
	if err != nil {
		return opts, err
	}

	log.Debug("Configuring exporter", "protocol",
		cfg.Protocol, "tracesProtocol", cfg.TracesProtocol, "endpoint", murl.Host)
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
	maps.Copy(opts.Headers, HeadersFromEnv(envTracesHeaders))
	return opts, nil
}

// HACK: at the time of writing this, the otelptracehttp API does not support explicitly
// setting the protocol. They should be properly set via environment variables, but
// if the user supplied the value via configuration file (and not via env vars), we override the environment.
// To be as least intrusive as possible, we will change the variables if strictly needed
// TODO: remove this once otelptracehttp.WithProtocol is supported
func setTracesProtocol(cfg *TracesConfig) {
	if _, ok := os.LookupEnv(envTracesProtocol); ok {
		return
	}
	if _, ok := os.LookupEnv(envProtocol); ok {
		return
	}
	if cfg.TracesProtocol != "" {
		os.Setenv(envTracesProtocol, string(cfg.TracesProtocol))
		return
	}
	if cfg.Protocol != "" {
		os.Setenv(envProtocol, string(cfg.Protocol))
		return
	}
	// unset. Guessing it
	os.Setenv(envTracesProtocol, string(cfg.guessProtocol()))
}
