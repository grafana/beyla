// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package services // import "go.opentelemetry.io/obi/pkg/appolly/services"

import (
	"bytes"
	"fmt"
	"iter"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/invopop/jsonschema"
	"gopkg.in/yaml.v3"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
)

const (
	AttrNamespace       = "k8s_namespace"
	AttrPodName         = "k8s_pod_name"
	AttrDeploymentName  = "k8s_deployment_name"
	AttrReplicaSetName  = "k8s_replicaset_name"
	AttrDaemonSetName   = "k8s_daemonset_name"
	AttrStatefulSetName = "k8s_statefulset_name"
	AttrJobName         = "k8s_job_name"
	AttrCronJobName     = "k8s_cronjob_name"
	// AttrOwnerName would be a generic search criteria that would
	// match against deployment, replicaset, daemonset and statefulset names
	AttrOwnerName        = "k8s_owner_name"
	AttrContainerName    = "k8s_container_name"
	AttrOCIContainerName = "container_name"
)

// AllowedAttributeNames contains the set of attribute names that can be used as metadata
// in service discovery criteria. Any attribute name not in this set will cause an error
// during the YAML unmarshalling.
var AllowedAttributeNames = map[string]struct{}{
	AttrNamespace:        {},
	AttrPodName:          {},
	AttrDeploymentName:   {},
	AttrReplicaSetName:   {},
	AttrDaemonSetName:    {},
	AttrStatefulSetName:  {},
	AttrJobName:          {},
	AttrCronJobName:      {},
	AttrOwnerName:        {},
	AttrContainerName:    {},
	AttrOCIContainerName: {},
}

// ProcessInfo stores some relevant information about a running process
type ProcessInfo struct {
	Pid       app.PID
	PPid      app.PID
	ExePath   string
	OpenPorts []uint32
}

type RouteHarvesterLanguage string

const (
	RouteHarvesterLanguageJava   RouteHarvesterLanguage = "java"
	RouteHarvesterLanguageNodejs RouteHarvesterLanguage = "nodejs"
	RouteHarvesterLanguageGo     RouteHarvesterLanguage = "go"
)

// DiscoveryConfig for the discover.ProcessFinder pipeline
type DiscoveryConfig struct {
	// Services selection. If the user defined the OTEL_EBPF_EXECUTABLE_PATH or OTEL_EBPF_OPEN_PORT variables, they will be automatically
	// added to the services definition criteria, with the lowest preference.
	//
	// Deprecated: Use Instrument instead
	Services RegexDefinitionCriteria `yaml:"services"`

	// ExcludeServices works analogously to Services, but the applications matching this section won't be instrumented
	// even if they match the Services selection.
	//
	// Deprecated: Use ExcludeInstrument instead
	ExcludeServices RegexDefinitionCriteria `yaml:"exclude_services"`

	// DefaultExcludeServices by default prevents self-instrumentation of OBI as well as related observability tools
	// It must be set to an empty string or a different value if self-instrumentation is desired.
	//
	// Deprecated: Use DefaultExcludeInstrument instead
	DefaultExcludeServices RegexDefinitionCriteria `yaml:"default_exclude_services"`

	// Instrument selects the services to instrument via Globs. If this section is set,
	// both the Services and ExcludeServices section is ignored.
	// If the user defined the OTEL_EBPF_INSTRUMENT_COMMAND or OTEL_EBPF_INSTRUMENT_PORTS variables, they will be
	// automatically added to the instrument criteria, with the lowest preference.
	Instrument GlobDefinitionCriteria `yaml:"instrument"`

	// ExcludeInstrument works analogously to Instrument, but the applications matching this section won't be instrumented
	// even if they match the Instrument selection.
	ExcludeInstrument GlobDefinitionCriteria `yaml:"exclude_instrument"`

	// DefaultExcludeInstrument by default prevents self-instrumentation of OBI as well as related observability tools
	// It must be set to an empty string or a different value if self-instrumentation is desired.
	DefaultExcludeInstrument GlobDefinitionCriteria `yaml:"default_exclude_instrument"`

	// PollInterval specifies, for the poll service watcher, the interval time between
	// process inspections
	PollInterval time.Duration `yaml:"poll_interval" env:"OTEL_EBPF_DISCOVERY_POLL_INTERVAL"`

	// This can be enabled to use generic HTTP tracers only, no Go-specifics will be used:
	SkipGoSpecificTracers bool `yaml:"skip_go_specific_tracers" env:"OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS"`

	// Debugging only option. Make sure the kernel side doesn't filter any PIDs, force user space filtering.
	BPFPidFilterOff bool `yaml:"bpf_pid_filter_off" env:"OTEL_EBPF_BPF_PID_FILTER_OFF"`

	// Disables instrumentation of services which are already instrumented
	ExcludeOTelInstrumentedServices bool `yaml:"exclude_otel_instrumented_services" env:"OTEL_EBPF_EXCLUDE_OTEL_INSTRUMENTED_SERVICES"`

	// DefaultOtlpGRPCPort specifies the default OTLP gRPC port (4317) to fallback on when missing environment variables on service, for
	// checking for grpc export requests, defaults to 4317
	DefaultOtlpGRPCPort int `yaml:"default_otlp_grpc_port" env:"OTEL_EBPF_DEFAULT_OTLP_GRPC_PORT"`

	// Min process age to be considered for discovery.
	//nolint:undoc
	MinProcessAge time.Duration `yaml:"min_process_age" env:"OTEL_EBPF_MIN_PROCESS_AGE"`

	// Disables generation of span metrics of services which are already instrumented
	ExcludeOTelInstrumentedServicesSpanMetrics bool `yaml:"exclude_otel_instrumented_services_span_metrics" env:"OTEL_EBPF_EXCLUDE_OTEL_INSTRUMENTED_SERVICES_SPAN_METRICS"`

	RouteHarvesterTimeout time.Duration `yaml:"route_harvester_timeout" env:"OTEL_EBPF_ROUTE_HARVESTER_TIMEOUT"`

	DisabledRouteHarvesters []RouteHarvesterLanguage `yaml:"disabled_route_harvesters"`

	RouteHarvestConfig RouteHarvestingConfig `yaml:"route_harvester_advanced"`

	// Executable paths for which we don't run language detection and cannot be
	// selected using the path or language selection criteria
	//nolint:undoc
	ExcludedLinuxSystemPaths []string `yaml:"excluded_linux_system_paths"`
}

type RouteHarvestingConfig struct {
	JavaHarvestDelay time.Duration `yaml:"java_harvest_delay" env:"OTEL_EBPF_JAVA_ROUTE_HARVEST_DELAY"`
}

func (c *DiscoveryConfig) Validate() error {
	if err := c.Services.Validate(); err != nil {
		return fmt.Errorf("error in services YAML property: %w", err)
	}
	if err := c.ExcludeServices.Validate(); err != nil {
		return fmt.Errorf("error in exclude_services YAML property: %w", err)
	}
	if err := c.Instrument.Validate(); err != nil {
		return fmt.Errorf("error in instrument YAML property: %w", err)
	}
	if err := c.ExcludeInstrument.Validate(); err != nil {
		return fmt.Errorf("error in exclude_instrument YAML property: %w", err)
	}
	return nil
}

// Selector defines a generic interface for selecting service processes based on different criteria.
type Selector interface {
	// Deprecated: Name should be set in the instrumentation target via kube metadata or standard env vars
	GetName() string
	// Deprecated: Namespace should be set in the instrumentation target via kube metadata or standard env vars
	GetNamespace() string
	GetPath() StringMatcher
	GetPathRegexp() StringMatcher
	GetOpenPorts() *IntEnum
	GetLanguages() StringMatcher
	// GetPIDs returns the list of target PIDs and true when this selector has PID criteria (analogous to OpenPorts).
	GetPIDs() ([]app.PID, bool)
	IsContainersOnly() bool
	RangeMetadata() iter.Seq2[string, StringMatcher]
	RangePodLabels() iter.Seq2[string, StringMatcher]
	RangePodAnnotations() iter.Seq2[string, StringMatcher]
	GetExportModes() ExportModes
	GetSamplerConfig() *SamplerConfig
	GetRoutesConfig() *CustomRoutesConfig
	MetricsConfig() perapp.SvcMetricsConfig
}

// StringMatcher provides a generic interface to match string values against some matcher types: regex and glob
type StringMatcher interface {
	IsSet() bool
	MatchString(input string) bool
}

// IntEnum defines an enumeration of integers (e.g. ports or PIDs). It allows a set of single
// values or ranges. When unmarshalled from text, it accepts a comma-separated list (e.g. 80,443,8000-8999).
// When unmarshalled from YAML, it accepts either a scalar (same as text) or a sequence (e.g. [1234, 5678]).
type IntEnum struct {
	Ranges []IntRange
}

// IntRange represents a single value (End == 0) or an inclusive range (Start to End).
type IntRange struct {
	Start int
	// if End == 0, this entry is a single value; otherwise it's an inclusive range
	End int
}

func (IntRange) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type:        "string",
		Pattern:     validIntEnum.String(),
		Description: "A comma-separated list of numerics or numeric ranges",
		Examples:    []any{"1", "1000", "8080-8090", "80,443,8000-8999"},
	}
}

func (p *IntEnum) Len() int {
	return len(p.Ranges)
}

// Valid int enum (printer pages-like notation): 8080 | 8000-8999 | 80,443 | 80,443,8000-8999
var validIntEnum = regexp.MustCompile(`^\s*\d+\s*(-\s*\d+\s*)?(,\s*\d+\s*(-\s*\d+\s*)?)*$`)

func (p *IntEnum) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.SequenceNode {
		p.Ranges = make([]IntRange, 0, len(value.Content))
		for _, n := range value.Content {
			var v int
			if err := n.Decode(&v); err != nil {
				return fmt.Errorf("IntEnum: invalid integer in list: %w", err)
			}
			p.Ranges = append(p.Ranges, IntRange{Start: v})
		}
		return nil
	}
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("IntEnum: unexpected YAML node kind %d", value.Kind)
	}
	return p.UnmarshalText([]byte(value.Value))
}

func (p IntEnum) MarshalYAML() (any, error) {
	sb := bytes.Buffer{}
	for i, r := range p.Ranges {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(strconv.Itoa(r.Start))
		if r.End > 0 {
			sb.WriteByte('-')
			sb.WriteString(strconv.Itoa(r.End))
		}
	}
	return sb.String(), nil
}

func (p *IntEnum) UnmarshalText(text []byte) error {
	val := strings.TrimSpace(string(text))
	if val == "" {
		p.Ranges = nil
		return nil
	}
	if !validIntEnum.MatchString(val) {
		return fmt.Errorf("invalid int enum %q. Must be a comma-separated list of integers or ranges (e.g. 8000-8999)", val)
	}
	for entry := range strings.SplitSeq(val, ",") {
		e := IntRange{}
		parts := strings.Split(entry, "-")
		e.Start, _ = strconv.Atoi(strings.TrimSpace(parts[0]))
		if len(parts) > 1 {
			e.End, _ = strconv.Atoi(strings.TrimSpace(parts[1]))
		}
		p.Ranges = append(p.Ranges, e)
	}
	return nil
}

// Matches returns true if n is contained in any range (or equals any single value).
func (p *IntEnum) Matches(n int) bool {
	for _, pr := range p.Ranges {
		if pr.End == 0 && pr.Start == n ||
			pr.End != 0 && pr.Start <= n && n <= pr.End {
			return true
		}
	}
	return false
}

// AllValues returns all integers represented by this enum (expanding ranges to discrete values).
func (p *IntEnum) AllValues() []int {
	if len(p.Ranges) == 0 {
		return nil
	}
	var out []int
	for _, r := range p.Ranges {
		if r.End == 0 {
			out = append(out, r.Start)
		} else {
			for i := r.Start; i <= r.End; i++ {
				out = append(out, i)
			}
		}
	}
	return out
}
