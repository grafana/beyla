package services

import (
	"reflect"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/services"
)

const (
	k8sGKEDefaultNamespacesRegex = "|^gke-connect$|^gke-gmp-system$|^gke-managed-cim$|^gke-managed-filestorecsi$|^gke-managed-metrics-server$|^gke-managed-system$|^gke-system$|^gke-managed-volumepopulator$"
	k8sGKEDefaultNamespacesGlob  = ",gke-connect,gke-gmp-system,gke-managed-cim,gke-managed-filestorecsi,gke-managed-metrics-server,gke-managed-system,gke-system,gke-managed-volumepopulator"
)

const (
	k8sAKSDefaultNamespacesRegex = "|^gatekeeper-system"
	k8sAKSDefaultNamespacesGlob  = ",gatekeeper-system"
)

var K8sDefaultNamespacesRegex = services.NewRegexp("^kube-system$|^kube-node-lease$|^local-path-storage$|^grafana-alloy$|^cert-manager$|^monitoring$" + k8sGKEDefaultNamespacesRegex + k8sAKSDefaultNamespacesRegex)
var K8sDefaultNamespacesGlob = services.NewGlob("{kube-system,kube-node-lease,local-path-storage,grafana-alloy,cert-manager,monitoring" + k8sGKEDefaultNamespacesGlob + k8sAKSDefaultNamespacesGlob + "}")

var K8sDefaultNamespacesWithSurveyRegex = services.NewRegexp("^kube-system$|^kube-node-lease$|^local-path-storage$|^cert-manager$" + k8sGKEDefaultNamespacesRegex + k8sAKSDefaultNamespacesRegex)
var K8sDefaultNamespacesWithSurveyGlob = services.NewGlob("{kube-system,kube-node-lease,local-path-storage,cert-manager" + k8sGKEDefaultNamespacesGlob + k8sAKSDefaultNamespacesGlob + "}")
var K8sDefaultExcludeContainerNamesGlob = services.NewGlob("{beyla,ebpf-instrument,alloy,prometheus-config-reloader,otelcol,otelcol-contrib}")

var DefaultExcludeServices = services.RegexDefinitionCriteria{
	services.RegexSelector{
		Path: services.NewRegexp("(?:^|/)(beyla$|alloy$|prometheus-config-reloader$|otelcol[^/]*$)"),
	},
	services.RegexSelector{
		Metadata: map[string]*services.RegexpAttr{"k8s_namespace": &K8sDefaultNamespacesRegex},
	},
}
var DefaultExcludeServicesWithSurvey = services.RegexDefinitionCriteria{
	services.RegexSelector{
		Path: services.NewRegexp("(?:^|/)(beyla$|alloy$|prometheus-config-reloader$|otelcol[^/]*$)"),
	},
	services.RegexSelector{
		Metadata: map[string]*services.RegexpAttr{"k8s_namespace": &K8sDefaultNamespacesWithSurveyRegex},
	},
}

var DefaultExcludeInstrument = services.GlobDefinitionCriteria{
	services.GlobAttributes{
		Path: services.NewGlob("{*beyla,*alloy,*prometheus-config-reloader,*ebpf-instrument,*otelcol,*otelcol-contrib,*otelcol-contrib[!/]*}"),
	},
	services.GlobAttributes{
		Metadata: map[string]*services.GlobAttr{"k8s_namespace": &K8sDefaultNamespacesGlob},
	},
	services.GlobAttributes{
		Metadata: map[string]*services.GlobAttr{"k8s_container_name": &K8sDefaultExcludeContainerNamesGlob},
	},
}
var DefaultExcludeInstrumentWithSurvey = services.GlobDefinitionCriteria{
	services.GlobAttributes{
		Path: services.NewGlob("{*beyla,*alloy,*prometheus-config-reloader,*ebpf-instrument,*otelcol,*otelcol-contrib,*otelcol-contrib[!/]*}"),
	},
	services.GlobAttributes{
		Metadata: map[string]*services.GlobAttr{"k8s_namespace": &K8sDefaultNamespacesWithSurveyGlob},
	},
	services.GlobAttributes{
		Metadata: map[string]*services.GlobAttr{"k8s_container_name": &K8sDefaultExcludeContainerNamesGlob},
	},
}

// DiscoveryConfig for the discover.ProcessFinder pipeline
type BeylaDiscoveryConfig struct {
	// Services selection. If the user defined the BEYLA_EXECUTABLE_NAME or BEYLA_OPEN_PORT variables, they will be automatically
	// added to the services definition criteria, with the lowest preference.
	// Deprecated: Use Instrument instead
	//nolint:undoc
	Services services.RegexDefinitionCriteria `yaml:"services"`

	// Survey selection. Same as services selection, however, it generates only the target info (survey_info) instead of instrumenting the services
	Survey services.GlobDefinitionCriteria `yaml:"survey"`

	// ExcludeServices works analogously to Services, but the applications matching this section won't be instrumented
	// even if they match the Services selection.
	// Deprecated: Use ExcludeInstrument instead
	//nolint:undoc
	ExcludeServices services.RegexDefinitionCriteria `yaml:"exclude_services"`

	// DefaultExcludeServices by default prevents self-instrumentation of Beyla as well as related services (Alloy and OpenTelemetry collector)
	// It must be set to an empty string or a different value if self-instrumentation is desired.
	// Deprecated: Use DefaultExcludeInstrument instead
	//nolint:undoc
	DefaultExcludeServices services.RegexDefinitionCriteria `yaml:"default_exclude_services"`

	// Instrument selects the services to instrument via Globs. If this section is set,
	// both the Services and ExcludeServices section is ignored.
	// If the user defined the BEYLA_AUTO_TARGET_EXE or BEYLA_OPEN_PORT variables, they will be
	// automatically added to the instrument criteria, with the lowest preference.
	Instrument services.GlobDefinitionCriteria `yaml:"instrument"`

	// ExcludeInstrument works analogously to Instrument, but the applications matching this section won't be instrumented
	// even if they match the Instrument selection.
	ExcludeInstrument services.GlobDefinitionCriteria `yaml:"exclude_instrument"`

	// DefaultExcludeInstrument by default prevents self-instrumentation of OBI as well as related services (Beyla, Alloy and OpenTelemetry collector)
	// It must be set to an empty string or a different value if self-instrumentation is desired.
	DefaultExcludeInstrument services.GlobDefinitionCriteria `yaml:"default_exclude_instrument"`

	// PollInterval specifies, for the poll service watcher, the interval time between
	// process inspections
	// nolint:undoc
	PollInterval time.Duration `yaml:"poll_interval" env:"BEYLA_DISCOVERY_POLL_INTERVAL"`

	// This can be enabled to use generic HTTP tracers only, no Go-specifics will be used:
	SkipGoSpecificTracers bool `yaml:"skip_go_specific_tracers" env:"BEYLA_SKIP_GO_SPECIFIC_TRACERS"`

	// Debugging only option. Make sure the kernel side doesn't filter any PIDs, force user space filtering.
	// nolint:undoc
	BPFPidFilterOff bool `yaml:"bpf_pid_filter_off" env:"BEYLA_BPF_PID_FILTER_OFF"`

	// Disables instrumentation of services which are already instrumented
	ExcludeOTelInstrumentedServices bool `yaml:"exclude_otel_instrumented_services" env:"BEYLA_EXCLUDE_OTEL_INSTRUMENTED_SERVICES"`

	// DefaultOtlpGRPCPort specifies the default OTLP gRPC port (4317) to fallback on when missing environment variables on service, for
	// checking for grpc export requests, defaults to 4317
	// nolint:undoc
	DefaultOtlpGRPCPort int `yaml:"default_otlp_grpc_port" env:"BEYLA_DEFAULT_OTLP_GRPC_PORT"`

	// Min process age to be considered for discovery.
	// nolint:undoc
	MinProcessAge time.Duration `yaml:"min_process_age" env:"BEYLA_MIN_PROCESS_AGE"`

	// Disables generation of span metrics of services which are already instrumented
	ExcludeOTelInstrumentedServicesSpanMetrics bool `yaml:"exclude_otel_instrumented_services_span_metrics" env:"BEYLA_EXCLUDE_OTEL_INSTRUMENTED_SERVICES_SPAN_METRICS"`

	// nolint:undoc
	RouteHarvesterTimeout time.Duration `yaml:"route_harvester_timeout" env:"OTEL_EBPF_ROUTE_HARVESTER_TIMEOUT"`

	// nolint:undoc
	DisabledRouteHarvesters []string `yaml:"disabled_route_harvesters"`

	// nolint:undoc
	RouteHarvestConfig RouteHarvestingConfig `yaml:"route_harvester_advanced"`
}

type RouteHarvestingConfig struct {
	// nolint:undoc
	JavaHarvestDelay time.Duration `yaml:"java_harvest_delay" env:"OTEL_EBPF_JAVA_ROUTE_HARVEST_DELAY"`
}

func (d *BeylaDiscoveryConfig) SurveyEnabled() bool {
	return len(d.Survey) > 0
}

func (d *BeylaDiscoveryConfig) OverrideDefaultExcludeForSurvey() {
	if reflect.DeepEqual(d.DefaultExcludeServices, DefaultExcludeServices) &&
		reflect.DeepEqual(d.DefaultExcludeInstrument, DefaultExcludeInstrument) {
		d.DefaultExcludeServices = DefaultExcludeServicesWithSurvey
		d.DefaultExcludeInstrument = DefaultExcludeInstrumentWithSurvey
	}
}

func (d *BeylaDiscoveryConfig) AppDiscoveryEnabled() bool {
	return len(d.Services) > 0 || len(d.Instrument) > 0
}
