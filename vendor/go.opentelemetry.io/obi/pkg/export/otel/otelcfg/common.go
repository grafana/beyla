// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otelcfg

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"path"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/hashicorp/golang-lru/v2/simplelru"
	"google.golang.org/grpc/credentials"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	semconv "go.opentelemetry.io/otel/semconv/v1.19.0"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/buildinfo"
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/expire"
)

// Protocol values for the OTEL_EXPORTER_OTLP_PROTOCOL, OTEL_EXPORTER_OTLP_TRACES_PROTOCOL and
// OTEL_EXPORTER_OTLP_METRICS_PROTOCOL standard configuration values
// More info: https://opentelemetry.io/docs/concepts/sdk-configuration/otlp-exporter-configuration/
type Protocol string

const (
	ProtocolUnset        Protocol = ""
	ProtocolGRPC         Protocol = "grpc"
	ProtocolHTTPProtobuf Protocol = "http/protobuf"
	ProtocolHTTPJSON     Protocol = "http/json"
)

const (
	envTracesProtocol  = "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL"
	envMetricsProtocol = "OTEL_EXPORTER_OTLP_METRICS_PROTOCOL"
	envProtocol        = "OTEL_EXPORTER_OTLP_PROTOCOL"
	envHeaders         = "OTEL_EXPORTER_OTLP_HEADERS"
	envTracesHeaders   = "OTEL_EXPORTER_OTLP_TRACES_HEADERS"
	envMetricsHeaders  = "OTEL_EXPORTER_OTLP_METRICS_HEADERS"
	envResourceAttrs   = "OTEL_RESOURCE_ATTRIBUTES"
)

const (
	UsualPortGRPC = "4317"
	UsualPortHTTP = "4318"

	FeatureNetwork          = "network"
	FeatureNetworkInterZone = "network_inter_zone"
	FeatureApplication      = "application"
	FeatureSpan             = "application_span"
	FeatureSpanOTel         = "application_span_otel"
	FeatureSpanSizes        = "application_span_sizes"
	FeatureGraph            = "application_service_graph"
	FeatureProcess          = "application_process"
	FeatureApplicationHost  = "application_host"
	FeatureEBPF             = "ebpf"
)

func omitFieldsForYAML(input any, omitFields map[string]struct{}) map[string]any {
	result := make(map[string]any)

	val := reflect.ValueOf(input)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	typ := val.Type()

	for i := 0; i < val.NumField(); i++ {
		field := typ.Field(i)
		yamlTag := field.Tag.Get("yaml")
		if yamlTag == "" || yamlTag == "-" {
			continue
		}
		yamlKey := yamlTag
		if commaIdx := len(yamlTag); commaIdx != -1 {
			yamlKey = yamlTag[:commaIdx]
		}

		if _, omit := omitFields[yamlKey]; !omit {
			result[yamlKey] = val.Field(i).Interface()
		} else {
			result[yamlKey] = "***" // Indicate that the field is omitted
		}
	}

	return result
}

// Buckets defines the histograms bucket boundaries, and allows users to
// redefine them
type Buckets struct {
	DurationHistogram     []float64 `yaml:"duration_histogram"`
	RequestSizeHistogram  []float64 `yaml:"request_size_histogram"`
	ResponseSizeHistogram []float64 `yaml:"response_size_histogram"`
}

var DefaultBuckets = Buckets{
	// Default values as specified in the OTEL specification
	// https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/metrics/semantic_conventions/http-metrics.md
	DurationHistogram: []float64{0, 0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10},

	RequestSizeHistogram:  []float64{0, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192},
	ResponseSizeHistogram: []float64{0, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192},
}

func GetAppResourceAttrs(hostID string, service *svc.Attrs) []attribute.KeyValue {
	return append(GetResourceAttrs(hostID, service),
		semconv.ServiceInstanceID(service.UID.Instance),
	)
}

func GetResourceAttrs(hostID string, service *svc.Attrs) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		semconv.ServiceName(service.UID.Name),
		// SpanMetrics requires an extra attribute besides service name
		// to generate the traces_target_info metric,
		// so the service is visible in the ServicesList
		// This attribute also allows that App O11y plugin shows this app as a Go application.
		semconv.TelemetrySDKLanguageKey.String(service.SDKLanguage.String()),
		// We set the SDK name as Beyla, so we can distinguish beyla generated metrics from other SDKs
		semconv.TelemetrySDKNameKey.String("opentelemetry-ebpf-instrumentation"),
		semconv.TelemetrySDKVersion(buildinfo.Version),
		semconv.HostName(service.HostName),
		semconv.HostID(hostID),
		semconv.OSTypeLinux,
	}

	if service.UID.Namespace != "" {
		attrs = append(attrs, semconv.ServiceNamespace(service.UID.Namespace))
	}

	for k, v := range service.Metadata {
		attrs = append(attrs, k.OTEL().String(v))
	}
	return attrs
}

// GetFilteredAttributesByPrefix applies attribute filtering based on selector patterns.
func GetFilteredAttributesByPrefix(baseAttrs []attribute.KeyValue, attrSelector attributes.Selection,
	extraAttrs []attribute.KeyValue, prefixPatterns []string,
) []attribute.KeyValue {
	result := make([]attribute.KeyValue, len(baseAttrs))
	copy(result, baseAttrs)

	if len(extraAttrs) == 0 {
		return result
	}

	var matchingPatterns []attributes.InclusionLists
	for section, inclList := range attrSelector {
		sectionStr := string(section)
		for _, prefix := range prefixPatterns {
			if strings.HasPrefix(sectionStr, prefix) {
				matchingPatterns = append(matchingPatterns, inclList)
				break
			}
		}
	}

	if len(matchingPatterns) == 0 {
		return append(result, extraAttrs...)
	}

	filtered := filterAttributes(extraAttrs, matchingPatterns)
	return append(result, filtered...)
}

func filterAttributes(attrs []attribute.KeyValue, patterns []attributes.InclusionLists) []attribute.KeyValue {
	var filtered []attribute.KeyValue

	for _, attr := range attrs {
		attrName := string(attr.Key)
		normalizedAttrName := strings.ReplaceAll(attrName, ".", "_")

		if shouldIncludeAttribute(normalizedAttrName, patterns) {
			filtered = append(filtered, attr)
		}
	}

	return filtered
}

func shouldIncludeAttribute(normalizedAttrName string, patterns []attributes.InclusionLists) bool {
	for _, pattern := range patterns {
		// Check exclusions first - if any match, exclude the attribute
		for _, excl := range pattern.Exclude {
			normalizedPattern := strings.ReplaceAll(excl, ".", "_")
			if match, _ := path.Match(normalizedPattern, normalizedAttrName); match {
				return false
			}
		}

		// If no includes specified or wildcard present, continue to next pattern
		if len(pattern.Include) == 0 || slices.Contains(pattern.Include, "*") {
			continue
		}

		// Check if attribute matches any inclusion pattern
		matched := false
		for _, incl := range pattern.Include {
			normalizedPattern := strings.ReplaceAll(incl, ".", "_")
			if match, _ := path.Match(normalizedPattern, normalizedAttrName); match {
				matched = true
				break
			}
		}

		// If includes specified but none matched, exclude the attribute
		if !matched {
			return false
		}
	}

	return true
}

// ReporterPool keeps an LRU cache of different OTEL reporters given a service name.
type ReporterPool[K uidGetter, T any] struct {
	pool *simplelru.LRU[svc.UID, *expirable[T]]

	itemConstructor func(getter K) (T, error)

	lastReporter   *expirable[T]
	lastService    uidGetter
	lastServiceUID svc.UID

	// TODO: use cacheable clock for efficiency
	clock          expire.Clock
	ttl            time.Duration
	lastExpiration time.Time
}

// expirable.NewLRU implementation is pretty undeterministic, so
// we implement our own expiration mechanism on top of simplelru.LRU
type expirable[T any] struct {
	lastAccess time.Time
	value      T
}

type uidGetter interface {
	GetUID() svc.UID
}

// NewReporterPool creates a ReporterPool instance given a cache length,
// an eviction callback to be invoked each time an element is removed
// from the cache, and a constructor function that will specify how to
// instantiate the generic OTEL metrics/traces reporter.
func NewReporterPool[K uidGetter, T any](
	cacheLen int,
	ttl time.Duration,
	clock expire.Clock,
	callback simplelru.EvictCallback[svc.UID, T],
	itemConstructor func(id K) (T, error),
) ReporterPool[K, T] {
	pool, err := simplelru.NewLRU[svc.UID, *expirable[T]](cacheLen, func(key svc.UID, value *expirable[T]) {
		callback(key, value.value)
	})
	if err != nil {
		// should never happen: bug!
		panic(err)
	}
	return ReporterPool[K, T]{
		pool:            pool,
		itemConstructor: itemConstructor,
		ttl:             ttl,
		clock:           clock,
		lastExpiration:  clock(),
	}
}

var emptyUID = svc.UID{}

// For retrieves the associated item for the given service name, or
// creates a new one if it does not exist
func (rp *ReporterPool[K, T]) For(service K) (T, error) {
	rp.expireOldReporters()
	// optimization: do not query the resources' cache if the
	// previously processed span belongs to the same service name
	// as the current.
	// This will save querying OTEL resource reporters when there is
	// only a single instrumented process.
	// In multi-process tracing, this is likely to happen as most
	// tracers group traces belonging to the same service in the same slice.
	svcUID := service.GetUID()
	if rp.lastServiceUID == emptyUID || svcUID != rp.lastService.GetUID() {
		lm, err := rp.get(svcUID, service)
		if err != nil {
			var t T
			return t, err
		}
		rp.lastServiceUID = svcUID
		rp.lastService = service
		rp.lastReporter = lm
	}
	// we need to update the last access for that reporter, to avoid it
	// being expired after the TTL
	rp.lastReporter.lastAccess = rp.clock()
	return rp.lastReporter.value, nil
}

// expireOldReporters will remove the metrics reporters that haven't been accessed
// during the last TTL period
func (rp *ReporterPool[K, T]) expireOldReporters() {
	now := rp.clock()
	if now.Sub(rp.lastExpiration) < rp.ttl {
		return
	}
	rp.lastExpiration = now
	for {
		_, v, ok := rp.pool.GetOldest()
		if !ok || now.Sub(v.lastAccess) < rp.ttl {
			return
		}
		rp.pool.RemoveOldest()
	}
}

func (rp *ReporterPool[K, T]) get(uid svc.UID, service K) (*expirable[T], error) {
	if e, ok := rp.pool.Get(uid); ok {
		return e, nil
	}
	m, err := rp.itemConstructor(service)
	if err != nil {
		return nil, fmt.Errorf("creating resource for service %v: %w", service, err)
	}
	e := &expirable[T]{value: m}
	rp.pool.Add(uid, e)
	return e, nil
}

// Intermediate representation of option functions suitable for testing
type OTLPOptions struct {
	Scheme   string
	Endpoint string
	Insecure bool
	// BaseURLPath, only for traces export, excludes the /v1/traces suffix.
	// E.g. for a URLPath == "/otlp/v1/traces", BaseURLPath will be = "/otlp"
	BaseURLPath   string
	URLPath       string
	SkipTLSVerify bool
	Headers       map[string]string
}

func (o *OTLPOptions) AsMetricHTTP() []otlpmetrichttp.Option {
	opts := []otlpmetrichttp.Option{
		otlpmetrichttp.WithEndpoint(o.Endpoint),
	}
	if o.Insecure {
		opts = append(opts, otlpmetrichttp.WithInsecure())
	}
	if o.URLPath != "" {
		opts = append(opts, otlpmetrichttp.WithURLPath(o.URLPath))
	}
	if o.SkipTLSVerify {
		opts = append(opts, otlpmetrichttp.WithTLSClientConfig(&tls.Config{InsecureSkipVerify: true}))
	}
	if len(o.Headers) > 0 {
		opts = append(opts, otlpmetrichttp.WithHeaders(o.Headers))
	}
	return opts
}

func (o *OTLPOptions) AsMetricGRPC() []otlpmetricgrpc.Option {
	opts := []otlpmetricgrpc.Option{
		otlpmetricgrpc.WithEndpoint(o.Endpoint),
	}
	if o.Insecure {
		opts = append(opts, otlpmetricgrpc.WithInsecure())
	}
	if o.SkipTLSVerify {
		opts = append(opts, otlpmetricgrpc.WithTLSCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})))
	}
	if len(o.Headers) > 0 {
		opts = append(opts, otlpmetricgrpc.WithHeaders(o.Headers))
	}
	return opts
}

func (o *OTLPOptions) AsTraceHTTP() []otlptracehttp.Option {
	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(o.Endpoint),
	}
	if o.Insecure {
		opts = append(opts, otlptracehttp.WithInsecure())
	}
	if o.URLPath != "" {
		opts = append(opts, otlptracehttp.WithURLPath(o.URLPath))
	}
	if o.SkipTLSVerify {
		opts = append(opts, otlptracehttp.WithTLSClientConfig(&tls.Config{InsecureSkipVerify: true}))
	}
	if len(o.Headers) > 0 {
		opts = append(opts, otlptracehttp.WithHeaders(o.Headers))
	}
	return opts
}

func (o *OTLPOptions) AsTraceGRPC() []otlptracegrpc.Option {
	opts := []otlptracegrpc.Option{
		otlptracegrpc.WithEndpoint(o.Endpoint),
	}
	if o.Insecure {
		opts = append(opts, otlptracegrpc.WithInsecure())
	}
	if o.SkipTLSVerify {
		opts = append(opts, otlptracegrpc.WithTLSCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})))
	}
	if len(o.Headers) > 0 {
		opts = append(opts, otlptracegrpc.WithHeaders(o.Headers))
	}
	return opts
}

// LogrAdaptor allows using our on logger to peek any warning or error in the OTEL exporters
type LogrAdaptor struct {
	inner *slog.Logger
}

func SetupInternalOTELSDKLogger(levelStr string) {
	log := slog.With("component", "otel.BatchSpanProcessor")
	if levelStr != "" {
		var lvl slog.Level
		err := lvl.UnmarshalText([]byte(levelStr))
		if err != nil {
			log.Warn("can't setup internal SDK logger level value. Ignoring", "error", err)
			return
		}
		log = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: &lvl,
		})).With("component", "otel.BatchSpanProcessor")
		otel.SetLogger(logr.New(&LogrAdaptor{inner: log}))
	}
}

func (l *LogrAdaptor) Init(_ logr.RuntimeInfo) {}

// Enabled returns, according to OTEL internal description:
// To see Warn messages use a logger with `l.V(1).Enabled() == true`
// To see Info messages use a logger with `l.V(4).Enabled() == true`
// To see Debug messages use a logger with `l.V(8).Enabled() == true`.
// However, we will "degrade" their info messages to our log level,
// as they leak many internal information that is not interesting for the final user.
func (l *LogrAdaptor) Enabled(level int) bool {
	if level < 4 {
		return l.inner.Enabled(context.TODO(), slog.LevelWarn)
	}
	return l.inner.Enabled(context.TODO(), slog.LevelDebug)
}

func (l *LogrAdaptor) Info(level int, msg string, keysAndValues ...any) {
	if level > 1 {
		l.inner.Debug(msg, keysAndValues...)
	} else {
		l.inner.Warn(msg, keysAndValues...)
	}
}

func (l *LogrAdaptor) Error(err error, msg string, keysAndValues ...any) {
	l.inner.Error(msg, append(keysAndValues, "error", err)...)
}

func (l *LogrAdaptor) WithValues(keysAndValues ...any) logr.LogSink {
	return &LogrAdaptor{inner: l.inner.With(keysAndValues...)}
}

func (l *LogrAdaptor) WithName(name string) logr.LogSink {
	return &LogrAdaptor{inner: l.inner.With("name", name)}
}

func HeadersFromEnv(varName string) map[string]string {
	headers := map[string]string{}

	addToMap := func(k string, v string) {
		headers[k] = v
	}

	parseOTELEnvVar(nil, varName, addToMap)

	return headers
}

// parseOTELEnvVar parses a comma separated group of variables
// in the format specified by OTEL_EXPORTER_OTLP_*HEADERS or
// OTEL_RESOURCE_ATTRIBUTES, i.e. a comma-separated list of
// key=values. For example: api-key=key,other-config-value=value
// The values are passed as parameters to the handler function
func parseOTELEnvVar(svc *svc.Attrs, varName string, handler attributes.VarHandler) {
	var envVar string
	ok := false

	if svc != nil && svc.EnvVars != nil {
		envVar, ok = svc.EnvVars[varName]
	}

	if !ok {
		envVar, ok = os.LookupEnv(varName)
	}

	if !ok {
		return
	}

	expandedValue := string(config.ReplaceEnv([]byte(envVar)))
	attributes.ParseOTELResourceVariable(expandedValue, handler)
}

func ResourceAttrsFromEnv(svc *svc.Attrs) []attribute.KeyValue {
	var otelResourceAttrs []attribute.KeyValue
	apply := func(k string, v string) {
		otelResourceAttrs = append(otelResourceAttrs, attribute.String(k, v))
	}

	parseOTELEnvVar(svc, envResourceAttrs, apply)
	return otelResourceAttrs
}

func ResolveOTLPEndpoint(endpoint, common string) (string, bool) {
	if endpoint != "" {
		return endpoint, false
	}

	if common != "" {
		return common, true
	}

	return "", false
}
