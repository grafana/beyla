// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert // import "go.opentelemetry.io/obi/internal/config/convert"

import (
	"errors"
	"fmt"
	"maps"
	"strconv"
	"strings"
	"time"

	otelconfx "go.opentelemetry.io/contrib/otelconf/x"
	"go.opentelemetry.io/otel/baggage"

	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/obi"
)

const (
	defaultOTLPGRPCEndpoint     = "http://localhost:4317"
	defaultOTLPHTTPTraceURL     = "http://localhost:4318/v1/traces"
	defaultOTLPHTTPMetricsURL   = "http://localhost:4318/v1/metrics"
	defaultPrometheusPort       = 9464
	defaultMetricExportInterval = time.Minute
)

// DocumentToRuntime converts a standalone v2 document into an OBI runtime
// configuration. It imports the OBI extension plus the document-level
// OpenTelemetry sections emitted by RuntimeToV2.
func DocumentToRuntime(src *schema.Document) (*obi.Config, error) {
	if src == nil {
		return nil, errors.New("missing OBI document")
	}
	if err := validateV2Document(src); err != nil {
		return nil, err
	}

	cfg, err := V2ToRuntime(src.Extensions.OBI)
	if err != nil {
		return nil, err
	}

	if err := applyV2Resource(cfg, src.Resource); err != nil {
		return nil, err
	}
	if err := applyV2TracerProvider(cfg, src.TracerProvider); err != nil {
		return nil, err
	}
	if err := applyV2MeterProvider(cfg, src.MeterProvider); err != nil {
		return nil, err
	}
	if err := applyV2LoggerProvider(cfg, src.LoggerProvider); err != nil {
		return nil, err
	}
	if err := applyV2LogLevel(cfg, src); err != nil {
		return nil, err
	}

	return cfg, nil
}

func validateV2Document(src *schema.Document) error {
	if fields := src.OpenTelemetryExtensionFields(); len(fields) != 0 {
		return fmt.Errorf(
			"OpenTelemetry extension fields are not supported: %s",
			strings.Join(fields, ", "),
		)
	}

	switch {
	case src.AttributeLimits != nil:
		return unsupportedV2Field("attribute_limits")
	case src.Disabled != nil && *src.Disabled:
		return unsupportedV2Field("disabled")
	case len(src.Distribution) != 0:
		return unsupportedV2Field("distribution")
	case src.InstrumentationDevelopment != nil:
		return unsupportedV2Field("instrumentation/development")
	case !zeroValue(src.AdditionalProperties):
		return unsupportedV2Field("additional declarative properties")
	}

	if src.Propagator != nil &&
		(len(src.Propagator.Composite) != 0 || src.Propagator.CompositeList != nil) {
		return unsupportedV2Field("propagator")
	}

	return nil
}

func unsupportedV2Field(path string) error {
	return fmt.Errorf("%s is not supported by the OBI runtime converter", path)
}

func applyV2LogLevel(cfg *obi.Config, src *schema.Document) error {
	if !src.HasLogLevel() || src.LogLevel == nil {
		return nil
	}

	level, err := logLevelFromSeverityNumber(*src.LogLevel)
	if err != nil {
		return err
	}
	cfg.LogLevel = level
	return nil
}

func logLevelFromSeverityNumber(severity otelconfx.SeverityNumber) (obi.LogLevel, error) {
	switch strings.ToLower(string(severity)) {
	case "trace", "trace2", "trace3", "trace4",
		"debug", "debug2", "debug3", "debug4":
		return obi.LogLevelDebug, nil
	case "info", "info2", "info3", "info4":
		return obi.LogLevelInfo, nil
	case "warn", "warn2", "warn3", "warn4":
		return obi.LogLevelWarn, nil
	case "error", "error2", "error3", "error4",
		"fatal", "fatal2", "fatal3", "fatal4":
		return obi.LogLevelError, nil
	default:
		return "", fmt.Errorf("unsupported log_level %q", severity)
	}
}

func applyV2Resource(cfg *obi.Config, resource *otelconfx.Resource) error {
	if resource == nil {
		return nil
	}
	if resource.DetectionDevelopment != nil {
		return unsupportedV2Field("resource.detection/development")
	}
	if resource.SchemaUrl != nil {
		return unsupportedV2Field("resource.schema_url")
	}

	values := map[string]string{}
	if resource.AttributesList != nil {
		if err := parseKeyValueList(*resource.AttributesList, values); err != nil {
			return fmt.Errorf("resource.attributes_list: %w", err)
		}
	}

	for i, attr := range resource.Attributes {
		path := fmt.Sprintf("resource.attributes[%d]", i)
		if attr.Type != nil && *attr.Type != otelconfx.AttributeTypeString {
			return unsupportedV2Field(path + ".type")
		}

		value, ok := attr.Value.(string)
		if !ok {
			return fmt.Errorf("%s.value must be a string", path)
		}
		values[attr.Name] = value
	}

	for name, value := range values {
		switch name {
		case "service.name":
			cfg.ServiceName = value
		case "service.namespace":
			cfg.ServiceNamespace = value
		case "host.name":
			cfg.Attributes.InstanceID.OverrideHostname = value
		case "host.id":
			cfg.Attributes.HostID.Override = value
		default:
			return unsupportedV2Field("resource attribute " + strconv.Quote(name))
		}
	}

	return nil
}

func applyV2TracerProvider(cfg *obi.Config, provider *otelconfx.TracerProvider) error {
	if provider == nil {
		return nil
	}
	if provider.Limits != nil {
		return unsupportedV2Field("tracer_provider.limits")
	}
	if provider.TracerConfiguratorDevelopment != nil {
		return unsupportedV2Field("tracer_provider.tracer_configurator/development")
	}

	if provider.Sampler != nil {
		sampler, ok := samplerConfigFromV2(provider.Sampler)
		if !ok {
			return unsupportedV2Field("tracer_provider.sampler")
		}
		cfg.Traces.SamplerConfig = sampler
	}

	if len(provider.Processors) == 0 {
		return nil
	}
	if len(provider.Processors) != 1 {
		return errors.New("tracer_provider.processors must contain at most one batch processor")
	}

	processor := provider.Processors[0]
	if processor.Batch == nil || processor.Simple != nil || !zeroValue(processor.AdditionalProperties) {
		return unsupportedV2Field("tracer_provider.processors[0]")
	}

	batch := processor.Batch
	if batch.ExportTimeout != nil {
		return unsupportedV2Field("tracer_provider.processors[0].batch.export_timeout")
	}
	if err := applyV2SpanExporter(cfg, &batch.Exporter); err != nil {
		return err
	}

	if batch.MaxQueueSize != nil {
		cfg.Traces.QueueSize = *batch.MaxQueueSize
	}
	if batch.MaxExportBatchSize != nil {
		cfg.Traces.BatchMaxSize = *batch.MaxExportBatchSize
	}
	if batch.ScheduleDelay != nil {
		cfg.Traces.BatchTimeout = time.Duration(*batch.ScheduleDelay) * time.Millisecond
	}

	return nil
}

func applyV2SpanExporter(cfg *obi.Config, exporter *otelconfx.SpanExporter) error {
	if exporter.OTLPFileDevelopment != nil || !zeroValue(exporter.Console) ||
		!zeroValue(exporter.AdditionalProperties) {
		return unsupportedV2Field("tracer_provider.processors[0].batch.exporter")
	}
	if countTrue(exporter.OTLPGrpc != nil, exporter.OTLPHttp != nil) != 1 {
		return errors.New("tracer_provider.processors[0].batch.exporter must contain exactly one OTLP exporter")
	}

	if exporter.OTLPGrpc != nil {
		return applyV2TraceGRPCExporter(cfg, exporter.OTLPGrpc)
	}
	return applyV2TraceHTTPExporter(cfg, exporter.OTLPHttp)
}

func applyV2TraceGRPCExporter(cfg *obi.Config, exporter *otelconfx.OTLPGrpcExporter) error {
	const path = "tracer_provider.processors[0].batch.exporter.otlp_grpc"
	if exporter.Compression != nil {
		return unsupportedV2Field(path + ".compression")
	}
	if exporter.Timeout != nil {
		return unsupportedV2Field(path + ".timeout")
	}
	if err := validateGrpcTLS(exporter.Tls, path+".tls"); err != nil {
		return err
	}

	inject, err := headerInjector(exporter.Headers, exporter.HeadersList, path)
	if err != nil {
		return err
	}
	cfg.Traces.TracesEndpoint = grpcEndpoint(exporter.Endpoint, exporter.Tls, defaultOTLPGRPCEndpoint)
	cfg.Traces.TracesProtocol = otelcfg.ProtocolGRPC
	cfg.Traces.InjectHeaders = inject
	return nil
}

func applyV2TraceHTTPExporter(cfg *obi.Config, exporter *otelconfx.OTLPHttpExporter) error {
	const path = "tracer_provider.processors[0].batch.exporter.otlp_http"
	if exporter.Compression != nil {
		return unsupportedV2Field(path + ".compression")
	}
	if exporter.Timeout != nil {
		return unsupportedV2Field(path + ".timeout")
	}
	if err := validateHTTPTLS(exporter.Tls, path+".tls"); err != nil {
		return err
	}

	protocol, err := httpProtocol(exporter.Encoding, path+".encoding")
	if err != nil {
		return err
	}
	inject, err := headerInjector(exporter.Headers, exporter.HeadersList, path)
	if err != nil {
		return err
	}

	cfg.Traces.TracesEndpoint = optionalEndpoint(exporter.Endpoint, defaultOTLPHTTPTraceURL)
	cfg.Traces.TracesProtocol = protocol
	cfg.Traces.InjectHeaders = inject
	return nil
}

func samplerConfigFromV2(sampler *otelconfx.Sampler) (services.SamplerConfig, bool) {
	if sampler == nil {
		return services.SamplerConfig{}, false
	}
	if sampler.CompositeDevelopment != nil ||
		sampler.JaegerRemoteDevelopment != nil ||
		sampler.ProbabilityDevelopment != nil ||
		sampler.AdditionalProperties != nil {
		return services.SamplerConfig{}, false
	}

	alwaysOff := !zeroValue(sampler.AlwaysOff)
	alwaysOn := !zeroValue(sampler.AlwaysOn)
	traceIDRatio := sampler.TraceIDRatioBased != nil
	parentBased := sampler.ParentBased != nil
	if countTrue(alwaysOff, alwaysOn, traceIDRatio, parentBased) != 1 {
		return services.SamplerConfig{}, false
	}

	switch {
	case alwaysOn:
		return services.SamplerConfig{Name: services.SamplerAlwaysOn}, true
	case alwaysOff:
		return services.SamplerConfig{Name: services.SamplerAlwaysOff}, true
	case traceIDRatio:
		return traceIDRatioSamplerConfig(sampler.TraceIDRatioBased, services.SamplerTraceIDRatio)
	default:
		return parentBasedSamplerConfig(sampler.ParentBased)
	}
}

func parentBasedSamplerConfig(sampler *otelconfx.ParentBasedSampler) (services.SamplerConfig, bool) {
	if sampler == nil ||
		!matchesSampler(sampler.LocalParentSampled, services.SamplerAlwaysOn) ||
		!matchesSampler(sampler.LocalParentNotSampled, services.SamplerAlwaysOff) ||
		!matchesSampler(sampler.RemoteParentSampled, services.SamplerAlwaysOn) ||
		!matchesSampler(sampler.RemoteParentNotSampled, services.SamplerAlwaysOff) {
		return services.SamplerConfig{}, false
	}

	root := services.SamplerConfig{Name: services.SamplerAlwaysOn}
	if sampler.Root != nil {
		var ok bool
		root, ok = samplerConfigFromV2(sampler.Root)
		if !ok {
			return services.SamplerConfig{}, false
		}
	}

	switch root.Name {
	case services.SamplerAlwaysOn:
		return services.SamplerConfig{Name: services.SamplerParentBasedAlwaysOn}, true
	case services.SamplerAlwaysOff:
		return services.SamplerConfig{Name: services.SamplerParentBasedAlwaysOff}, true
	case services.SamplerTraceIDRatio:
		return services.SamplerConfig{
			Name: services.SamplerParentBasedTraceIDRatio,
			Arg:  root.Arg,
		}, true
	default:
		return services.SamplerConfig{}, false
	}
}

func matchesSampler(sampler *otelconfx.Sampler, expected services.SamplerName) bool {
	if sampler == nil {
		return true
	}

	actual, ok := samplerConfigFromV2(sampler)
	return ok && actual.Name == expected && actual.Arg == ""
}

func traceIDRatioSamplerConfig(
	sampler *otelconfx.TraceIDRatioBasedSampler,
	name services.SamplerName,
) (services.SamplerConfig, bool) {
	if sampler == nil {
		return services.SamplerConfig{}, false
	}
	ratio := 1.0
	if sampler.Ratio != nil {
		ratio = *sampler.Ratio
	}
	if ratio < 0 || ratio > 1 {
		return services.SamplerConfig{}, false
	}

	return services.SamplerConfig{
		Name: name,
		Arg:  strconv.FormatFloat(ratio, 'f', -1, 64),
	}, true
}

func applyV2MeterProvider(cfg *obi.Config, provider *otelconfx.MeterProvider) error {
	if provider == nil {
		return nil
	}
	if provider.ExemplarFilter != nil {
		return unsupportedV2Field("meter_provider.exemplar_filter")
	}
	if provider.MeterConfiguratorDevelopment != nil {
		return unsupportedV2Field("meter_provider.meter_configurator/development")
	}
	if len(provider.Views) != 0 {
		return unsupportedV2Field("meter_provider.views")
	}
	if len(provider.Readers) > 2 {
		return errors.New("meter_provider.readers must contain at most one periodic and one pull reader")
	}

	periodicSeen := false
	pullSeen := false
	for i := range provider.Readers {
		reader := &provider.Readers[i]
		path := fmt.Sprintf("meter_provider.readers[%d]", i)
		switch {
		case reader.Periodic != nil && reader.Pull == nil:
			if periodicSeen {
				return fmt.Errorf("%s duplicates the periodic metric reader", path)
			}
			periodicSeen = true
			if err := applyV2PeriodicMetricReader(cfg, reader.Periodic, path+".periodic"); err != nil {
				return err
			}
		case reader.Pull != nil && reader.Periodic == nil:
			if pullSeen {
				return fmt.Errorf("%s duplicates the pull metric reader", path)
			}
			pullSeen = true
			if err := applyV2PullMetricReader(cfg, reader.Pull, path+".pull"); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%s must configure exactly one periodic or pull reader", path)
		}
	}

	return nil
}

func applyV2PeriodicMetricReader(
	cfg *obi.Config,
	reader *otelconfx.PeriodicMetricReader,
	path string,
) error {
	if reader.CardinalityLimits != nil {
		return unsupportedV2Field(path + ".cardinality_limits")
	}
	if len(reader.Producers) != 0 {
		return unsupportedV2Field(path + ".producers")
	}
	if reader.Timeout != nil {
		return unsupportedV2Field(path + ".timeout")
	}

	exporter := &reader.Exporter
	if exporter.OTLPFileDevelopment != nil || exporter.Console != nil ||
		!zeroValue(exporter.AdditionalProperties) {
		return unsupportedV2Field(path + ".exporter")
	}
	if countTrue(exporter.OTLPGrpc != nil, exporter.OTLPHttp != nil) != 1 {
		return fmt.Errorf("%s.exporter must contain exactly one OTLP exporter", path)
	}

	if reader.Interval == nil {
		cfg.OTELMetrics.Interval = defaultMetricExportInterval
	} else {
		cfg.OTELMetrics.Interval = time.Duration(*reader.Interval) * time.Millisecond
	}

	if exporter.OTLPGrpc != nil {
		return applyV2MetricGRPCExporter(cfg, exporter.OTLPGrpc, path+".exporter.otlp_grpc")
	}
	return applyV2MetricHTTPExporter(cfg, exporter.OTLPHttp, path+".exporter.otlp_http")
}

func applyV2MetricGRPCExporter(
	cfg *obi.Config,
	exporter *otelconfx.OTLPGrpcMetricExporter,
	path string,
) error {
	if exporter.Compression != nil {
		return unsupportedV2Field(path + ".compression")
	}
	if exporter.TemporalityPreference != nil {
		return unsupportedV2Field(path + ".temporality_preference")
	}
	if exporter.Timeout != nil {
		return unsupportedV2Field(path + ".timeout")
	}
	if err := validateGrpcTLS(exporter.Tls, path+".tls"); err != nil {
		return err
	}

	inject, err := headerInjector(exporter.Headers, exporter.HeadersList, path)
	if err != nil {
		return err
	}
	applyV2HistogramAggregation(cfg, exporter.DefaultHistogramAggregation)
	cfg.OTELMetrics.MetricsEndpoint = grpcEndpoint(exporter.Endpoint, exporter.Tls, defaultOTLPGRPCEndpoint)
	cfg.OTELMetrics.MetricsProtocol = otelcfg.ProtocolGRPC
	cfg.OTELMetrics.InjectHeaders = inject
	return nil
}

func applyV2MetricHTTPExporter(
	cfg *obi.Config,
	exporter *otelconfx.OTLPHttpMetricExporter,
	path string,
) error {
	if exporter.Compression != nil {
		return unsupportedV2Field(path + ".compression")
	}
	if exporter.TemporalityPreference != nil {
		return unsupportedV2Field(path + ".temporality_preference")
	}
	if exporter.Timeout != nil {
		return unsupportedV2Field(path + ".timeout")
	}
	if exporter.Encoding != nil && *exporter.Encoding == otelconfx.OTLPHttpEncodingJson {
		return fmt.Errorf("%s has unsupported value %q", path+".encoding", *exporter.Encoding)
	}
	if err := validateHTTPTLS(exporter.Tls, path+".tls"); err != nil {
		return err
	}

	protocol, err := httpProtocol(exporter.Encoding, path+".encoding")
	if err != nil {
		return err
	}
	inject, err := headerInjector(exporter.Headers, exporter.HeadersList, path)
	if err != nil {
		return err
	}

	applyV2HistogramAggregation(cfg, exporter.DefaultHistogramAggregation)
	cfg.OTELMetrics.MetricsEndpoint = optionalEndpoint(exporter.Endpoint, defaultOTLPHTTPMetricsURL)
	cfg.OTELMetrics.MetricsProtocol = protocol
	cfg.OTELMetrics.InjectHeaders = inject
	return nil
}

func applyV2HistogramAggregation(
	cfg *obi.Config,
	aggregation *otelconfx.ExporterDefaultHistogramAggregation,
) {
	if aggregation != nil {
		cfg.OTELMetrics.HistogramAggregation = otelcfg.HistogramAggregation(*aggregation)
	}
}

func applyV2PullMetricReader(
	cfg *obi.Config,
	reader *otelconfx.PullMetricReader,
	path string,
) error {
	if reader.CardinalityLimits != nil {
		return unsupportedV2Field(path + ".cardinality_limits")
	}
	if len(reader.Producers) != 0 {
		return unsupportedV2Field(path + ".producers")
	}

	exporter := &reader.Exporter
	if exporter.PrometheusDevelopment == nil || !zeroValue(exporter.AdditionalProperties) {
		return unsupportedV2Field(path + ".exporter")
	}
	prometheus := exporter.PrometheusDevelopment
	if prometheus.Host != nil {
		return unsupportedV2Field(path + ".exporter.prometheus/development.host")
	}
	if prometheus.TranslationStrategy != nil {
		return unsupportedV2Field(path + ".exporter.prometheus/development.translation_strategy")
	}
	if prometheus.WithResourceConstantLabels != nil {
		return unsupportedV2Field(path + ".exporter.prometheus/development.with_resource_constant_labels")
	}
	if prometheus.WithoutScopeInfo != nil {
		return unsupportedV2Field(path + ".exporter.prometheus/development.without_scope_info")
	}
	if prometheus.WithoutTargetInfo != nil {
		return unsupportedV2Field(path + ".exporter.prometheus/development.without_target_info")
	}

	cfg.Prometheus.Port = defaultPrometheusPort
	if prometheus.Port != nil {
		cfg.Prometheus.Port = *prometheus.Port
	}
	return nil
}

func validateGrpcTLS(tls *otelconfx.GrpcTls, path string) error {
	if tls == nil {
		return nil
	}
	if tls.CaFile != nil {
		return unsupportedV2Field(path + ".ca_file")
	}
	if tls.CertFile != nil {
		return unsupportedV2Field(path + ".cert_file")
	}
	if tls.KeyFile != nil {
		return unsupportedV2Field(path + ".key_file")
	}
	return nil
}

func validateHTTPTLS(tls *otelconfx.HttpTls, path string) error {
	if tls == nil {
		return nil
	}
	if tls.CaFile != nil {
		return unsupportedV2Field(path + ".ca_file")
	}
	if tls.CertFile != nil {
		return unsupportedV2Field(path + ".cert_file")
	}
	if tls.KeyFile != nil {
		return unsupportedV2Field(path + ".key_file")
	}
	return nil
}

func grpcEndpoint[T ~*string](endpoint T, tls *otelconfx.GrpcTls, defaultValue string) string {
	if endpoint == nil {
		return defaultValue
	}
	if *endpoint == "" || strings.Contains(*endpoint, "://") {
		return *endpoint
	}

	scheme := "https"
	if tls != nil && tls.Insecure != nil && *tls.Insecure {
		scheme = "http"
	}
	return scheme + "://" + *endpoint
}

func optionalEndpoint[T ~*string](endpoint T, defaultValue string) string {
	if endpoint == nil {
		return defaultValue
	}
	return *endpoint
}

func httpProtocol(
	encoding *otelconfx.OTLPHttpEncoding,
	path string,
) (otelcfg.Protocol, error) {
	if encoding == nil || *encoding == otelconfx.OTLPHttpEncodingProtobuf {
		return otelcfg.ProtocolHTTPProtobuf, nil
	}
	if *encoding == otelconfx.OTLPHttpEncodingJson {
		return otelcfg.ProtocolHTTPJSON, nil
	}
	return "", fmt.Errorf("%s has unsupported value %q", path, *encoding)
}

func headerInjector[T ~*string](
	headers []otelconfx.NameStringValuePair,
	headersList T,
	path string,
) (func(map[string]string), error) {
	values := map[string]string{}
	if headersList != nil {
		parsed, err := baggage.Parse(*headersList)
		if err != nil {
			return nil, fmt.Errorf("%s.headers_list: %w", path, err)
		}
		for _, header := range parsed.Members() {
			values[header.Key()] = header.Value()
		}
	}

	for i, header := range headers {
		if header.Name == "" {
			return nil, fmt.Errorf("%s.headers[%d].name must not be empty", path, i)
		}
		if header.Value != nil {
			values[header.Name] = *header.Value
		}
	}
	if len(values) == 0 {
		return nil, nil
	}

	return func(dst map[string]string) {
		maps.Copy(dst, values)
	}, nil
}

func parseKeyValueList(raw string, dst map[string]string) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	for item := range strings.SplitSeq(raw, ",") {
		key, value, found := strings.Cut(item, "=")
		if !found || strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
			return fmt.Errorf("invalid key-value pair %q", strings.TrimSpace(item))
		}
	}

	attributes.ParseOTELResourceVariable(raw, func(key, value string) {
		dst[key] = value
	})
	return nil
}

func countTrue(values ...bool) int {
	var count int
	for _, value := range values {
		if value {
			count++
		}
	}
	return count
}
