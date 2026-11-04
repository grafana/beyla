// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert // import "go.opentelemetry.io/obi/internal/config/convert"

import (
	"net/url"
	"slices"
	"strconv"
	"strings"

	otelconfx "go.opentelemetry.io/contrib/otelconf/x"

	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	obiconfig "go.opentelemetry.io/obi/pkg/config"
	featureexport "go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/transform"
)

// RuntimeToV2 converts an already-loaded v1 runtime configuration into the
// internal config v2 document shape.
func RuntimeToV2(cfg *obi.Config) (*schema.Document, *schema.Extension) {
	if cfg == nil {
		defaultConfig := obi.DefaultConfig
		cfg = &defaultConfig
	}

	ext := &schema.Extension{
		Version: schema.SupportedVersion,
		Capture: schema.Capture{
			Attributes:      captureAttributes(cfg),
			Policy:          capturePolicy(cfg),
			Instrumentation: captureInstrumentation(cfg),
			Runtimes:        captureRuntimes(cfg),
			Network:         captureNetwork(cfg),
			Metrics:         schema.CaptureMetrics{Features: cfg.Metrics.Features.Names()},
			Limits:          captureLimits(cfg),
			Engine:          captureEngine(cfg),
			Safety:          captureSafety(cfg),
			Channels:        captureChannels(cfg),
			Rules:           rulesFromRuntime(cfg),
			Telemetry:       captureTelemetry(cfg),
		},
		Enrich:      enrich(cfg),
		Correlation: correlation(cfg),
		Daemon:      daemon(cfg),
	}

	doc := &schema.Document{
		OpenTelemetryConfiguration: otelconfx.OpenTelemetryConfiguration{
			FileFormat:     "1.0",
			Resource:       resource(cfg),
			Propagator:     &otelconfx.Propagator{},
			TracerProvider: tracerProvider(cfg),
			MeterProvider:  meterProvider(cfg),
		},
		Extensions: schema.Extensions{OBI: ext},
	}
	doc.SetLogLevel(logLevel(cfg.LogLevel))

	return doc, ext
}

func capturePolicy(cfg *obi.Config) schema.CapturePolicy {
	return schema.CapturePolicy{
		DefaultAction: defaultPolicyAction(cfg),
		MatchOrder:    schema.MatchOrderFirstMatchWins,
		PollInterval:  schema.Duration(cfg.Discovery.PollInterval),
		MinProcessAge: schema.Duration(cfg.Discovery.MinProcessAge),
	}
}

func defaultPolicyAction(cfg *obi.Config) schema.CaptureAction {
	if cfg.Enabled(obi.FeatureAppO11y) {
		return schema.CaptureActionExclude
	}
	return schema.CaptureActionInclude
}

func captureInstrumentation(cfg *obi.Config) schema.Instrumentation {
	tracesInstrumentations := cfg.Traces.Instrumentations
	metricsInstrs := metricsInstrumentations(cfg)
	appMetricsEnabled := cfg.Metrics.Features.AnyAppO11yMetric()

	protocols := make(map[protocolName]schema.ProtocolInstrumentation, len(protocolMappings))
	for _, mapping := range protocolMappings {
		protocols[mapping.name] = protocolInstrumentation(
			tracesInstrumentations,
			metricsInstrs,
			appMetricsEnabled,
			mapping,
			cfg,
		)
	}

	http := protocols[protocolHTTP]
	httpInstrumentation := schema.HTTPInstrumentation{
		Enabled: schema.HTTPProtocolEnablement{
			ProtocolEnablement: http.Enabled,
			BodySizeMetrics:    cfg.Metrics.Features.AppSizes(),
		},
		Filters:                   http.Filters,
		TrackRequestHeaders:       cfg.EBPF.TrackRequestHeaders,
		RequestTimeout:            schema.Duration(cfg.EBPF.HTTPRequestTimeout),
		GoHTTPClientBufferTimeout: schema.Duration(cfg.EBPF.GoHTTPClientBufferTimeout),
		BufferSize:                cfg.EBPF.BufferSizes.HTTP,
		Routes:                    httpRoutes(cfg),
		PayloadExtraction:         payloadExtraction(cfg),
	}

	sql := protocols[protocolSQL]
	sqlInstrumentation := schema.SQLInstrumentation{
		Enabled:           sql.Enabled,
		Filters:           sql.Filters,
		HeuristicDetect:   cfg.EBPF.HeuristicSQLDetect,
		SanitizeQueryText: cfg.Attributes.SanitizeSQLQueryText,
		MySQL: schema.SQLDatabaseInstrumentation{
			BufferSize:                  cfg.EBPF.BufferSizes.MySQL,
			PreparedStatementsCacheSize: cfg.EBPF.MySQLPreparedStatementsCacheSize,
		},
		Postgres: schema.SQLDatabaseInstrumentation{
			BufferSize:                  cfg.EBPF.BufferSizes.Postgres,
			PreparedStatementsCacheSize: cfg.EBPF.PostgresPreparedStatementsCacheSize,
		},
		MSSQL: schema.SQLDatabaseInstrumentation{
			BufferSize:                  cfg.EBPF.BufferSizes.MSSQL,
			PreparedStatementsCacheSize: cfg.EBPF.MSSQLPreparedStatementsCacheSize,
		},
	}

	redis := protocols[protocolRedis]
	redisInstrumentation := schema.RedisInstrumentation{
		Enabled: redis.Enabled,
		Filters: redis.Filters,
		DBCache: schema.RedisDBCache{
			Enabled: cfg.EBPF.RedisDBCache.Enabled,
			MaxSize: cfg.EBPF.RedisDBCache.MaxSize,
		},
	}

	kafka := protocols[protocolKafka]
	kafkaInstrumentation := schema.KafkaInstrumentation{
		Enabled:            kafka.Enabled,
		Filters:            kafka.Filters,
		BufferSize:         cfg.EBPF.BufferSizes.Kafka,
		TopicUUIDCacheSize: cfg.EBPF.KafkaTopicUUIDCacheSize,
	}

	mongo := protocols[protocolMongo]
	mongoInstrumentation := schema.MongoInstrumentation{
		Enabled:           mongo.Enabled,
		Filters:           mongo.Filters,
		RequestsCacheSize: cfg.EBPF.MongoRequestsCacheSize,
	}

	couchbase := protocols[protocolCouchbase]
	couchbaseInstrumentation := schema.CouchbaseInstrumentation{
		Enabled:     couchbase.Enabled,
		Filters:     couchbase.Filters,
		DBCacheSize: cfg.EBPF.CouchbaseDBCacheSize,
	}

	dns := protocols[protocolDNS]
	dnsInstrumentation := schema.DNSInstrumentation{
		Enabled:        dns.Enabled,
		Filters:        dns.Filters,
		RequestTimeout: schema.Duration(cfg.EBPF.DNSRequestTimeout),
	}

	gpu := protocols[protocolGPU]
	gpuInstrumentation := schema.GPUInstrumentation{
		Enabled:     gpu.Enabled,
		Filters:     gpu.Filters,
		EnabledMode: cfg.EBPF.InstrumentCuda,
	}

	aerospike := protocols[protocolAerospike]
	aerospikeInstrumentation := schema.AerospikeInstrumentation{
		Enabled:    aerospike.Enabled,
		Filters:    aerospike.Filters,
		BufferSize: cfg.EBPF.BufferSizes.Aerospike,
	}

	return schema.Instrumentation{
		HTTP:      httpInstrumentation,
		GRPC:      protocols[protocolGRPC],
		SQL:       sqlInstrumentation,
		Redis:     redisInstrumentation,
		Kafka:     kafkaInstrumentation,
		Mongo:     mongoInstrumentation,
		Couchbase: couchbaseInstrumentation,
		DNS:       dnsInstrumentation,
		GPU:       gpuInstrumentation,
		Aerospike: &aerospikeInstrumentation,
	}
}

func protocolInstrumentation(
	tracesInstrumentations []instrumentations.Instrumentation,
	metricsInstrumentations []instrumentations.Instrumentation,
	appMetricsEnabled bool,
	mapping protocolMapping,
	cfg *obi.Config,
) schema.ProtocolInstrumentation {
	return schema.ProtocolInstrumentation{
		Enabled: protocolEnabled(tracesInstrumentations, metricsInstrumentations, appMetricsEnabled, mapping),
		Filters: applicationSignalFilters(cfg.Filters, mapping.instr),
	}
}

func metricsInstrumentations(cfg *obi.Config) []instrumentations.Instrumentation {
	var combined []instrumentations.Instrumentation
	if cfg.OTELMetrics.EndpointEnabled() {
		combined = appendMetricInstrumentations(combined, cfg.OTELMetrics.Instrumentations)
	}
	if cfg.Prometheus.EndpointEnabled() {
		combined = appendMetricInstrumentations(combined, cfg.Prometheus.Instrumentations)
	}
	if len(combined) != 0 {
		return combined
	}

	combined = appendMetricInstrumentations(combined, cfg.OTELMetrics.Instrumentations)
	return appendMetricInstrumentations(combined, cfg.Prometheus.Instrumentations)
}

func appendMetricInstrumentations(
	dst []instrumentations.Instrumentation,
	src []instrumentations.Instrumentation,
) []instrumentations.Instrumentation {
	for _, instr := range src {
		if !containsInstrumentation(dst, instr) {
			dst = append(dst, instr)
		}
	}
	return dst
}

func containsInstrumentation(list []instrumentations.Instrumentation, needle instrumentations.Instrumentation) bool {
	return slices.Contains(list, needle)
}

func protocolEnabled(
	tracesInstrumentations []instrumentations.Instrumentation,
	metricsInstrumentations []instrumentations.Instrumentation,
	appMetricsEnabled bool,
	mapping protocolMapping,
) schema.ProtocolEnablement {
	metricsEnabled := protocolSelected(metricsInstrumentations, mapping, mapping.metricWildcard)
	if mapping.appMetrics {
		metricsEnabled = metricsEnabled && appMetricsEnabled
	}

	return schema.ProtocolEnablement{
		Traces:  protocolSelected(tracesInstrumentations, mapping, true),
		Metrics: metricsEnabled,
	}
}

func protocolSelected(list []instrumentations.Instrumentation, mapping protocolMapping, wildcard bool) bool {
	for _, instr := range list {
		if instr == mapping.instr {
			return true
		}
		if instr == instrumentations.InstrumentationALL && wildcard {
			return true
		}
	}
	return false
}

func captureRuntimes(cfg *obi.Config) schema.CaptureRuntimes {
	return schema.CaptureRuntimes{
		Go: schema.Runtime{
			Enabled: !cfg.Discovery.SkipGoSpecificTracers,
		},
		NodeJS: schema.Runtime{
			Enabled: cfg.NodeJS.Enabled,
		},
		Java: schema.JavaRuntime{
			Enabled: cfg.Java.Enabled,
			Debug: schema.JavaDebug{
				Enabled:                 cfg.Java.Debug,
				BytecodeInstrumentation: cfg.Java.DebugInstrumentation,
			},
			AttachTimeout: schema.Duration(cfg.Java.Timeout),
		},
	}
}

func captureNetwork(cfg *obi.Config) schema.CaptureNetwork {
	return schema.CaptureNetwork{
		Capture: schema.NetworkCapture{
			Enabled:    cfg.Enabled(obi.FeatureNetO11y),
			Source:     schema.NetworkSource(cfg.NetworkFlows.Source),
			BufferSize: cfg.EBPF.BufferSizes.TCP,
			EndpointIdentity: schema.EndpointIdentity{
				AgentIP:          cfg.NetworkFlows.AgentIP,
				AgentIPInterface: schema.AgentIPInterface(cfg.NetworkFlows.AgentIPIface),
				AgentIPFamily:    schema.AgentIPFamily(cfg.NetworkFlows.AgentIPType),
			},
			Selection: schema.NetworkSelection{
				Interfaces: schema.IncludeExclude{
					Include: cfg.NetworkFlows.Interfaces,
					Exclude: cfg.NetworkFlows.ExcludeInterfaces,
				},
				Protocols: schema.IncludeExclude{
					Include: cfg.NetworkFlows.Protocols,
					Exclude: cfg.NetworkFlows.ExcludeProtocols,
				},
				Direction: schema.NetworkDirection(cfg.NetworkFlows.Direction),
				CIDRs:     networkCIDRDefinitions(cfg),
			},
			Filters: signalFilters(cfg.Filters.Network),
			FlowLifecycle: schema.FlowLifecycle{
				MaxTrackedFlows: cfg.NetworkFlows.CacheMaxFlows,
				ActiveTimeout:   schema.Duration(cfg.NetworkFlows.CacheActiveTimeout),
				Deduplication: schema.Deduplication{
					Strategy:     schema.DeduplicationStrategy(cfg.NetworkFlows.Deduper),
					FirstComeTTL: schema.Duration(cfg.NetworkFlows.DeduperFCTTL),
				},
				Sampling:   cfg.NetworkFlows.Sampling,
				GuessPorts: cfg.NetworkFlows.GuessPorts,
			},
			InterfaceDiscovery: schema.InterfaceDiscovery{
				Mode:         schema.InterfaceDiscoveryMode(cfg.NetworkFlows.ListenInterfaces),
				PollInterval: schema.Duration(cfg.NetworkFlows.ListenPollPeriod),
			},
			Enrichment: networkFlowEnrichment(cfg),
			Diagnostics: schema.FlowDiagnostics{
				PrintFlows: cfg.NetworkFlows.Print,
			},
		},
		Stats: schema.NetworkStats{
			Enabled:  cfg.Enabled(obi.FeatureStatsO11y),
			Features: statsFeatures(cfg.Metrics.Features),
			EndpointIdentity: schema.EndpointIdentity{
				AgentIP:          cfg.Stats.AgentIP,
				AgentIPInterface: schema.AgentIPInterface(cfg.Stats.AgentIPIface),
				AgentIPFamily:    schema.AgentIPFamily(cfg.Stats.AgentIPType),
			},
			Selection: schema.StatsSelection{
				CIDRs: statsCIDRDefinitions(cfg),
			},
			Filters:    signalFilters(cfg.Filters.Stats),
			Enrichment: statsEnrichment(cfg),
			Diagnostics: schema.StatsDiagnostics{
				PrintStats: cfg.Stats.Print,
			},
		},
	}
}

func networkCIDRDefinitions(cfg *obi.Config) schema.CIDRDefinitions {
	definitions := make(schema.CIDRDefinitions, 0, len(cfg.NetworkFlows.CIDRs))
	for _, definition := range cfg.NetworkFlows.CIDRs {
		definitions = append(definitions, schema.CIDRDefinition{
			CIDR: definition.CIDR,
			Name: definition.Name,
		})
	}
	return definitions
}

func statsCIDRDefinitions(cfg *obi.Config) schema.CIDRDefinitions {
	definitions := make(schema.CIDRDefinitions, 0, len(cfg.Stats.CIDRs))
	for _, definition := range cfg.Stats.CIDRs {
		definitions = append(definitions, schema.CIDRDefinition{
			CIDR: definition.CIDR,
			Name: definition.Name,
		})
	}
	return definitions
}

const (
	statsFeatureTCPRtt                   = "tcp_rtt"
	statsFeatureTCPFailedConnections     = "tcp_failed_connections"
	statsFeatureTCPSuccessfulConnections = "tcp_successful_connections"
	statsFeatureTCPRetransmits           = "tcp_retransmits"
	statsFeatureTCPIo                    = "tcp_io"
)

func statsFeatures(features featureexport.Features) []string {
	out := []string{}
	if features.StatsTCPRtt() {
		out = append(out, statsFeatureTCPRtt)
	}
	if features.StatsTCPFailedConnections() {
		out = append(out, statsFeatureTCPFailedConnections)
	}
	if features.StatsTCPSuccessfulConnections() {
		out = append(out, statsFeatureTCPSuccessfulConnections)
	}
	if features.StatsTCPRetransmits() {
		out = append(out, statsFeatureTCPRetransmits)
	}
	if features.StatsTCPIo() {
		out = append(out, statsFeatureTCPIo)
	}
	return out
}

func captureLimits(cfg *obi.Config) schema.CaptureLimits {
	return schema.CaptureLimits{
		NetworkPackets:  cfg.NetworkFlows.CacheMaxFlows,
		MetricSpanNames: cfg.Attributes.MetricSpanNameAggregationLimit,
	}
}

func captureEngine(cfg *obi.Config) schema.CaptureEngine {
	return schema.CaptureEngine{
		Debug: schema.EngineDebug{
			BPF:           cfg.EBPF.BpfDebug,
			ProtocolPrint: cfg.EBPF.ProtocolDebug,
		},
		PIDFilter: schema.PIDFilter{
			Disabled: cfg.Discovery.BPFPidFilterOff,
		},
		Batching: schema.Batching{
			WakeupLen:    cfg.EBPF.WakeupLen,
			BatchLength:  cfg.EBPF.BatchLength,
			BatchTimeout: schema.Duration(cfg.EBPF.BatchTimeout),
		},
		Propagation: schema.Propagation{
			ContextPropagation:     cfg.EBPF.ContextPropagation,
			OverrideBPFLoopEnabled: cfg.EBPF.OverrideBPFLoopEnabled,
			DisableBlackBoxCP:      cfg.EBPF.DisableBlackBoxCP,
			PopulateTraceContext:   cfg.EBPF.PopulateTraceContext,
		},
		Traffic: schema.Traffic{
			ControlBackend:    cfg.EBPF.TCBackend,
			HighRequestVolume: cfg.EBPF.HighRequestVolume,
			ForceMapReader:    cfg.EBPF.ForceBPFMapReader,
		},
		Transactions: schema.Transactions{
			MaxDuration: schema.Duration(cfg.EBPF.MaxTransactionTime),
		},
		Maps: schema.Maps{
			GlobalScaleFactor: cfg.EBPF.MapsConfig.GlobalScaleFactor,
		},
		BPFFileSystem: schema.BPFFileSystem{
			Path: cfg.EBPF.BPFFSPath,
		},
		CgroupFileSystem: schema.CgroupFileSystem{
			Path: cfg.EBPF.CgroupFSPath,
		},
	}
}

func captureSafety(cfg *obi.Config) schema.CaptureSafety {
	return schema.CaptureSafety{
		EnforceSystemCapabilities: cfg.EnforceSysCaps,
	}
}

func captureChannels(cfg *obi.Config) schema.CaptureChannels {
	return schema.CaptureChannels{
		BufferLen:          cfg.ChannelBufferLen,
		SendTimeout:        schema.Duration(cfg.ChannelSendTimeout),
		PanicOnSendTimeout: cfg.ChannelSendTimeoutPanic,
	}
}

func captureTelemetry(cfg *obi.Config) schema.CaptureTelemetry {
	return schema.CaptureTelemetry{
		Traces: schema.TracesTelemetry{
			ReportersCacheLen: cfg.Traces.ReportersCacheLen,
		},
		Metrics: schema.MetricsTelemetry{
			ReportersCacheLen: cfg.OTELMetrics.ReportersCacheLen,
			TTL:               schema.Duration(cfg.OTELMetrics.TTL),
			ConnectionInfoTTL: schema.Duration(cfg.OTELMetrics.ConnectionInfoTTL),
		},
	}
}

func resource(cfg *obi.Config) *otelconfx.Resource {
	var attributes []otelconfx.AttributeNameValue
	if cfg.Attributes.InstanceID.OverrideHostname != "" {
		attributes = append(attributes, stringAttribute("host.name", cfg.Attributes.InstanceID.OverrideHostname))
	}
	if cfg.Attributes.HostID.Override != "" {
		attributes = append(attributes, stringAttribute("host.id", cfg.Attributes.HostID.Override))
	}
	return &otelconfx.Resource{Attributes: attributes}
}

func stringAttribute(name, value string) otelconfx.AttributeNameValue {
	return otelconfx.AttributeNameValue{
		Name:  name,
		Value: value,
	}
}

func tracerProvider(cfg *obi.Config) *otelconfx.TracerProvider {
	endpoint, _ := cfg.Traces.OTLPTracesEndpoint()
	insecure := insecureOTLPTransport(endpoint)
	maxQueueSize := cfg.Traces.QueueSize
	maxExportBatchSize := cfg.Traces.BatchMaxSize
	scheduleDelay := int(cfg.Traces.BatchTimeout.Milliseconds())
	return &otelconfx.TracerProvider{
		Processors: []otelconfx.SpanProcessor{
			{
				Batch: &otelconfx.BatchSpanProcessor{
					MaxQueueSize:       &maxQueueSize,
					MaxExportBatchSize: &maxExportBatchSize,
					ScheduleDelay:      &scheduleDelay,
					Exporter: otelconfx.SpanExporter{
						OTLPGrpc: &otelconfx.OTLPGrpcExporter{
							Endpoint: &endpoint,
							Tls: &otelconfx.GrpcTls{
								Insecure: &insecure,
							},
						},
					},
				},
			},
		},
		Sampler: sampler(cfg),
	}
}

func sampler(cfg *obi.Config) *otelconfx.Sampler {
	if cfg.Traces.SamplerConfig.Name == "" && cfg.Traces.SamplerConfig.Arg == "" {
		return nil
	}
	return declarativeSampler(cfg.Traces.SamplerConfig)
}

func declarativeSampler(cfg services.SamplerConfig) *otelconfx.Sampler {
	switch cfg.Name {
	case services.SamplerAlwaysOn:
		return &otelconfx.Sampler{AlwaysOn: otelconfx.AlwaysOnSampler{}}
	case services.SamplerAlwaysOff:
		return &otelconfx.Sampler{AlwaysOff: otelconfx.AlwaysOffSampler{}}
	case services.SamplerTraceIDRatio:
		return traceIDRatioSampler(cfg.Arg)
	case services.SamplerParentBasedAlwaysOff:
		return parentBasedSampler(&otelconfx.Sampler{AlwaysOff: otelconfx.AlwaysOffSampler{}})
	case services.SamplerParentBasedTraceIDRatio:
		return parentBasedSampler(traceIDRatioSampler(cfg.Arg))
	case services.SamplerParentBasedAlwaysOn, "":
		return parentBasedSampler(&otelconfx.Sampler{AlwaysOn: otelconfx.AlwaysOnSampler{}})
	default:
		return nil
	}
}

func parentBasedSampler(root *otelconfx.Sampler) *otelconfx.Sampler {
	return &otelconfx.Sampler{
		ParentBased: &otelconfx.ParentBasedSampler{
			Root: root,
		},
	}
}

func traceIDRatioSampler(raw string) *otelconfx.Sampler {
	ratio, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return nil
	}
	return &otelconfx.Sampler{
		TraceIDRatioBased: &otelconfx.TraceIDRatioBasedSampler{
			Ratio: &ratio,
		},
	}
}

func meterProvider(cfg *obi.Config) *otelconfx.MeterProvider {
	endpoint, _ := cfg.OTELMetrics.OTLPMetricsEndpoint()
	insecure := insecureOTLPTransport(endpoint)
	interval := int(cfg.OTELMetrics.GetInterval().Milliseconds())
	prometheusPort := cfg.Prometheus.Port
	return &otelconfx.MeterProvider{
		Readers: []otelconfx.MetricReader{
			{
				Periodic: &otelconfx.PeriodicMetricReader{
					Interval: &interval,
					Exporter: otelconfx.PushMetricExporter{
						OTLPGrpc: &otelconfx.OTLPGrpcMetricExporter{
							Endpoint:                    &endpoint,
							DefaultHistogramAggregation: defaultHistogramAggregation(cfg.OTELMetrics.HistogramAggregation),
							Tls: &otelconfx.GrpcTls{
								Insecure: &insecure,
							},
						},
					},
				},
			},
			{
				Pull: &otelconfx.PullMetricReader{
					Exporter: otelconfx.PullMetricExporter{
						PrometheusDevelopment: &otelconfx.ExperimentalPrometheusMetricExporter{
							Port: &prometheusPort,
						},
					},
				},
			},
		},
	}
}

func defaultHistogramAggregation(aggregation otelcfg.HistogramAggregation) *otelconfx.ExporterDefaultHistogramAggregation {
	if aggregation == "" {
		return nil
	}
	out := otelconfx.ExporterDefaultHistogramAggregation(aggregation)
	return &out
}

func insecureOTLPTransport(endpoint string) bool {
	parsed, err := url.Parse(endpoint)
	return err == nil && parsed.Scheme == "http"
}

func enrich(cfg *obi.Config) *schema.Enrich {
	return &schema.Enrich{
		Enrichers: schema.Enrichers{
			PeerMetadata: peerMetadataEnrichment(cfg.PeerMetadata),
			Kubernetes: schema.KubernetesEnricher{
				Mode:                v2KubernetesMode(cfg.Attributes.Kubernetes.Enable),
				ClusterName:         cfg.Attributes.Kubernetes.ClusterName,
				ServiceNameTemplate: cfg.Attributes.Kubernetes.ServiceNameTemplate,
				Auth: schema.KubernetesAuth{
					KubeconfigPath: cfg.Attributes.Kubernetes.KubeconfigPath,
				},
				Informers: schema.KubernetesInformers{
					InitialSyncTimeout:       schema.Duration(cfg.Attributes.Kubernetes.InformersSyncTimeout),
					ReconnectInitialInterval: schema.Duration(cfg.Attributes.Kubernetes.ReconnectInitialInterval),
					ResyncPeriod:             schema.Duration(cfg.Attributes.Kubernetes.InformersResyncPeriod),
					Disabled:                 cfg.Attributes.Kubernetes.DisableInformers,
				},
				DropExternal:   cfg.Attributes.Kubernetes.DropExternal,
				ResourceLabels: schema.ResourceLabels(cfg.Attributes.Kubernetes.ResourceLabels),
				MetadataCache: schema.KubernetesMetadataCache{
					Address:           cfg.Attributes.Kubernetes.MetaCacheAddress,
					RestrictLocalNode: cfg.Attributes.Kubernetes.MetaRestrictLocalNode,
					SourceLabels: schema.KubernetesSourceLabels{
						ServiceName:      cfg.Attributes.Kubernetes.MetaSourceLabels.ServiceName,
						ServiceNamespace: cfg.Attributes.Kubernetes.MetaSourceLabels.ServiceNamespace,
					},
				},
			},
			Cloud: schema.CloudEnricher{
				ClusterName:     cfg.CloudMetadata.ClusterName,
				Region:          cfg.CloudMetadata.Region,
				RefreshInterval: schema.Duration(cfg.CloudMetadata.RefreshInterval),
				Route53: schema.Route53{
					RefreshInterval: schema.Duration(cfg.CloudMetadata.Route53.RefreshInterval),
					HostedZoneIDs:   cfg.CloudMetadata.Route53.HostedZoneIDs,
				},
			},
		},
		ServiceName: serviceNameEnrichment(cfg),
		Attributes: schema.EnrichmentAttributes{
			Select:               resourceAttributeSelection(cfg.Attributes.Select),
			ExtraGroupAttributes: schema.ExtraGroupAttributes(cfg.Attributes.ExtraGroupAttributes),
			MetadataRetry: schema.MetadataRetry{
				Timeout:       schema.Duration(cfg.Attributes.MetadataRetry.Timeout),
				StartInterval: schema.Duration(cfg.Attributes.MetadataRetry.StartInterval),
				MaxInterval:   schema.Duration(cfg.Attributes.MetadataRetry.MaxInterval),
			},
		},
	}
}

func serviceNameEnrichment(cfg *obi.Config) schema.ServiceName {
	out := schema.ServiceName{
		UnresolvedHosts: schema.UnresolvedHosts{
			Names: schema.UnresolvedHostNames{
				Default:  cfg.Attributes.RenameUnresolvedHosts,
				Outgoing: cfg.Attributes.RenameUnresolvedHostsOutgoing,
				Incoming: cfg.Attributes.RenameUnresolvedHostsIncoming,
			},
		},
	}
	if cfg.NameResolver == nil {
		out.Sources = []transform.Source{}
		out.Cache = schema.Cache{TTL: schema.Duration(0)}
		return out
	}

	out.Sources = cfg.NameResolver.Sources
	if !zeroValue(cfg.NameResolver.GCE) {
		gce := cfg.NameResolver.GCE
		out.GCE = &gce
	}
	out.Azure = schema.AzureServiceName{
		SubscriptionID: cfg.NameResolver.Azure.SubscriptionID,
		ResourceGroup:  cfg.NameResolver.Azure.ResourceGroup,
	}
	out.Cache = schema.Cache{
		Size: cfg.NameResolver.CacheLen,
		TTL:  schema.Duration(cfg.NameResolver.CacheTTL),
	}
	return out
}

func correlation(cfg *obi.Config) *schema.Correlation {
	return &schema.Correlation{
		LogTraceAnnotation: schema.LogTraceAnnotation{
			Enabled: cfg.EBPF.LogEnricher.Enabled(),
			Match:   logEnricherMatches(cfg.EBPF.LogEnricher.Services),
			FieldNames: schema.FieldNames{
				TraceID: &cfg.EBPF.LogEnricher.FieldNames.TraceID,
				SpanID:  &cfg.EBPF.LogEnricher.FieldNames.SpanID,
			},
			PlainText: schema.PlainText{
				Enabled:   &cfg.EBPF.LogEnricher.PlainText.Enabled,
				Placement: &cfg.EBPF.LogEnricher.PlainText.Placement,
				Multiline: &cfg.EBPF.LogEnricher.PlainText.Multiline,
			},
			Cache: schema.Cache{
				TTL:  schema.Duration(cfg.EBPF.LogEnricher.CacheTTL),
				Size: cfg.EBPF.LogEnricher.CacheSize,
			},
			AsyncWriter: schema.AsyncWriter{
				Workers:    cfg.EBPF.LogEnricher.AsyncWriterWorkers,
				ChannelLen: cfg.EBPF.LogEnricher.AsyncWriterChannelLen,
			},
		},
	}
}

func logEnricherMatches(svcs []obiconfig.LogEnricherServiceConfig) []schema.RuleMatch {
	var matches []schema.RuleMatch
	for _, svc := range svcs {
		for i := range svc.Service {
			matches = append(matches, globSelectorMatch(&svc.Service[i]))
		}
	}
	return matches
}

func daemon(cfg *obi.Config) *schema.Daemon {
	return &schema.Daemon{
		Logging: schema.Logging{
			Format:           logFormat(cfg.LogFormat),
			ConfigFormat:     configFormat(cfg.LogConfig),
			DebugTraceOutput: cfg.TracePrinter,
		},
		Profiling: schema.Profiling{
			Port: cfg.ProfilePort,
		},
		Shutdown: schema.Shutdown{
			Timeout: schema.Duration(cfg.ShutdownTimeout),
		},
		InternalMetrics: schema.InternalMetrics{
			Exporter: cfg.InternalMetrics.Exporter,
			Prometheus: schema.InternalPrometheus{
				Port: cfg.InternalMetrics.Prometheus.Port,
				Path: cfg.InternalMetrics.Prometheus.Path,
			},
			BPF: schema.BPFInternalMetrics{
				ScrapeInterval: schema.Duration(cfg.InternalMetrics.BpfMetricScrapeInterval),
			},
		},
		Telemetry: schema.DaemonTelemetry{
			Metrics: schema.DaemonTelemetryMetrics{
				Prometheus: schema.DaemonPrometheusTelemetry{
					AllowServiceGraphSelfReferences: cfg.Prometheus.AllowServiceGraphSelfReferences,
					SpanMetricsServiceCacheSize:     cfg.Prometheus.SpanMetricsServiceCacheSize,
					ExtraResourceAttributes:         cfg.Prometheus.ExtraResourceLabels,
					ExtraSpanResourceAttributes:     mergedStrings(cfg.Prometheus.ExtraSpanResourceLabels, cfg.OTELMetrics.ExtraSpanResourceLabels),
				},
			},
		},
	}
}

func logLevel(level obi.LogLevel) otelconfx.SeverityNumber {
	switch strings.ToUpper(string(level)) {
	case string(obi.LogLevelDebug):
		return otelconfx.SeverityNumberDebug
	case string(obi.LogLevelWarn):
		return otelconfx.SeverityNumberWarn
	case string(obi.LogLevelError):
		return otelconfx.SeverityNumberError
	default:
		return otelconfx.SeverityNumberInfo
	}
}

func logFormat(format obi.LogFormat) schema.LogFormat {
	switch strings.ToLower(string(format)) {
	case string(schema.LogFormatJSON):
		return schema.LogFormatJSON
	case string(schema.LogFormatText):
		return schema.LogFormatText
	default:
		return schema.LogFormatText
	}
}

func configFormat(format obi.LogConfigOption) schema.ConfigFormat {
	switch format {
	case obi.LogConfigOptionJSON:
		return schema.ConfigFormatJSON
	case obi.LogConfigOptionYAML:
		return schema.ConfigFormatYAML
	default:
		return schema.ConfigFormatUnset
	}
}

func mergedStrings(values ...[]string) []string {
	var out []string
	seen := map[string]struct{}{}
	for _, list := range values {
		for _, value := range list {
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			out = append(out, value)
		}
	}
	return out
}
