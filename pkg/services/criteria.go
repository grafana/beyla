package services

import (
	"time"

	"go.opentelemetry.io/obi/pkg/services"
)

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

	// Disables generation of span metrics of services which are already instrumented
	ExcludeOTelInstrumentedServicesSpanMetrics bool `yaml:"exclude_otel_instrumented_services_span_metrics" env:"BEYLA_EXCLUDE_OTEL_INSTRUMENTED_SERVICES_SPAN_METRICS"`
}

func (d *BeylaDiscoveryConfig) SurveyEnabled() bool {
	return len(d.Survey) > 0
}

func (d *BeylaDiscoveryConfig) AppDiscoveryEnabled() bool {
	return len(d.Services) > 0 || len(d.Instrument) > 0
}
