package otel

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/go-logr/logr"
	"github.com/google/uuid"
	"github.com/hashicorp/golang-lru/v2/simplelru"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.19.0"
	"google.golang.org/grpc/credentials"

	"github.com/grafana/beyla/v2/pkg/buildinfo"
	"github.com/grafana/beyla/v2/pkg/export/attributes"
	"github.com/grafana/beyla/v2/pkg/export/expire"
	"github.com/grafana/beyla/v2/pkg/internal/svc"
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

// Buckets defines the histograms bucket boundaries, and allows users to
// redefine them
type Buckets struct {
	DurationHistogram    []float64 `yaml:"duration_histogram"`
	RequestSizeHistogram []float64 `yaml:"request_size_histogram"`
}

var DefaultBuckets = Buckets{
	// Default values as specified in the OTEL specification
	// https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/metrics/semantic_conventions/http-metrics.md
	DurationHistogram: []float64{0, 0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10},

	RequestSizeHistogram: []float64{0, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192},
}

func getAppResourceAttrs(hostID string, service *svc.Attrs) []attribute.KeyValue {
	return append(getResourceAttrs(hostID, service),
		semconv.ServiceInstanceID(service.UID.Instance),
	)
}

func getResourceAttrs(hostID string, service *svc.Attrs) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		semconv.ServiceName(service.UID.Name),
		// SpanMetrics requires an extra attribute besides service name
		// to generate the traces_target_info metric,
		// so the service is visible in the ServicesList
		// This attribute also allows that App O11y plugin shows this app as a Go application.
		semconv.TelemetrySDKLanguageKey.String(service.SDKLanguage.String()),
		// We set the SDK name as Beyla, so we can distinguish beyla generated metrics from other SDKs
		semconv.TelemetrySDKNameKey.String("beyla"),
		semconv.TelemetrySDKVersion(buildinfo.Version),
		semconv.HostName(service.HostName),
		semconv.HostID(hostID),
	}

	if service.UID.Namespace != "" {
		attrs = append(attrs, semconv.ServiceNamespace(service.UID.Namespace))
	}

	for k, v := range service.Metadata {
		attrs = append(attrs, k.OTEL().String(v))
	}
	return attrs
}

func newResourceInternal(hostID string) *resource.Resource {
	attrs := []attribute.KeyValue{
		semconv.ServiceName("beyla"),
		semconv.ServiceInstanceID(uuid.New().String()),
		semconv.TelemetrySDKLanguageKey.String(semconv.TelemetrySDKLanguageGo.Value.AsString()),
		// We set the SDK name as Beyla, so we can distinguish beyla generated metrics from other SDKs
		semconv.TelemetrySDKNameKey.String("beyla"),
		semconv.HostID(hostID),
	}

	return resource.NewWithAttributes(semconv.SchemaURL, attrs...)
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
	callback simplelru.EvictCallback[svc.UID, *expirable[T]],
	itemConstructor func(id K) (T, error),
) ReporterPool[K, T] {
	pool, err := simplelru.NewLRU[svc.UID, *expirable[T]](cacheLen, callback)
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
type otlpOptions struct {
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

func (o *otlpOptions) AsMetricHTTP() []otlpmetrichttp.Option {
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

func (o *otlpOptions) AsMetricGRPC() []otlpmetricgrpc.Option {
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

func (o *otlpOptions) AsTraceHTTP() []otlptracehttp.Option {
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

func (o *otlpOptions) AsTraceGRPC() []otlptracegrpc.Option {
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

func (l *LogrAdaptor) Info(level int, msg string, keysAndValues ...interface{}) {
	if level > 1 {
		l.inner.Debug(msg, keysAndValues...)
	} else {
		l.inner.Warn(msg, keysAndValues...)
	}
}

func (l *LogrAdaptor) Error(err error, msg string, keysAndValues ...interface{}) {
	l.inner.Error(msg, append(keysAndValues, "error", err)...)
}

func (l *LogrAdaptor) WithValues(keysAndValues ...interface{}) logr.LogSink {
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

	attributes.ParseOTELResourceVariable(envVar, handler)
}

func ResourceAttrsFromEnv(svc *svc.Attrs) []attribute.KeyValue {
	var otelResourceAttrs []attribute.KeyValue
	apply := func(k string, v string) {
		otelResourceAttrs = append(otelResourceAttrs, attribute.String(k, v))
	}

	parseOTELEnvVar(svc, envResourceAttrs, apply)
	return otelResourceAttrs
}

func ResolveOTLPEndpoint(endpoint, common string, grafana *GrafanaOTLP) (string, bool) {
	if endpoint != "" {
		return endpoint, false
	}

	if common != "" {
		return common, true
	}

	if grafana != nil && grafana.CloudZone != "" && grafana.Endpoint() != "" {
		return grafana.Endpoint(), true
	}

	return "", false
}
