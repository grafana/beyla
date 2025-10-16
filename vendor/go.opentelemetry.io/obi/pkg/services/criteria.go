// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package services

import (
	"bytes"
	"fmt"
	"iter"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
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
	AttrOwnerName     = "k8s_owner_name"
	AttrContainerName = "k8s_container_name"
)

// any attribute name not in this set will cause an error during the YAML unmarshalling
var allowedAttributeNames = map[string]struct{}{
	AttrNamespace:       {},
	AttrPodName:         {},
	AttrDeploymentName:  {},
	AttrReplicaSetName:  {},
	AttrDaemonSetName:   {},
	AttrStatefulSetName: {},
	AttrJobName:         {},
	AttrCronJobName:     {},
	AttrOwnerName:       {},
	AttrContainerName:   {},
}

// ProcessInfo stores some relevant information about a running process
type ProcessInfo struct {
	Pid       int32
	PPid      int32
	ExePath   string
	OpenPorts []uint32
}

// DiscoveryConfig for the discover.ProcessFinder pipeline
type DiscoveryConfig struct {
	// Services selection. If the user defined the OTEL_EBPF_EXECUTABLE_PATH or OTEL_EBPF_OPEN_PORT variables, they will be automatically
	// added to the services definition criteria, with the lowest preference.
	// Deprecated: Use Instrument instead
	Services RegexDefinitionCriteria `yaml:"services"`

	// ExcludeServices works analogously to Services, but the applications matching this section won't be instrumented
	// even if they match the Services selection.
	// Deprecated: Use ExcludeInstrument instead
	ExcludeServices RegexDefinitionCriteria `yaml:"exclude_services"`

	// DefaultExcludeServices by default prevents self-instrumentation of Beyla as well as related services (Alloy and OpenTelemetry collector)
	// It must be set to an empty string or a different value if self-instrumentation is desired.
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

	// DefaultExcludeInstrument by default prevents self-instrumentation of OBI as well as related services (Beyla, Alloy and OpenTelemetry collector)
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

	DisabledRouteHarvesters []string `yaml:"disabled_route_harvesters"`
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
	GetOpenPorts() *PortEnum
	IsContainersOnly() bool
	RangeMetadata() iter.Seq2[string, StringMatcher]
	RangePodLabels() iter.Seq2[string, StringMatcher]
	RangePodAnnotations() iter.Seq2[string, StringMatcher]
	GetExportModes() ExportModes
	GetSamplerConfig() *SamplerConfig
	GetRoutesConfig() *CustomRoutesConfig
}

// StringMatcher provides a generic interface to match string values against some matcher types: regex and glob
type StringMatcher interface {
	IsSet() bool
	MatchString(input string) bool
}

// PortEnum defines an enumeration of ports. It allows defining a set of single ports as well a set of
// port ranges. When unmarshalled from text, it accepts a comma-separated
// list of port numbers (e.g. 80) and port ranges (e.g. 8080-8089). For example, this would be a valid
// port range: 80,443,8000-8999
type PortEnum struct {
	Ranges []PortRange
}

type PortRange struct {
	Start int
	// if End == 0, it means this entry is not a port range but a single port
	End int
}

func (p *PortEnum) Len() int {
	return len(p.Ranges)
}

// Valid port Enums (printer pages-like notation)
// 8080
// 8000-8999
// 80,443
// 80,443,8000-8999
var validPortEnum = regexp.MustCompile(`^\s*\d+\s*(-\s*\d+\s*)?(,\s*\d+\s*(-\s*\d+\s*)?)*$`)

func (p *PortEnum) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("PortEnum: unexpected YAML node kind %d", value.Kind)
	}
	return p.UnmarshalText([]byte(value.Value))
}

func (p PortEnum) MarshalYAML() (any, error) {
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

func (p *PortEnum) UnmarshalText(text []byte) error {
	val := string(text)
	if !validPortEnum.MatchString(val) {
		return fmt.Errorf("invalid port range %q. Must be a comma-separated list of numeric ports or port ranges (e.g. 8000-8999)", val)
	}
	for entry := range strings.SplitSeq(val, ",") {
		e := PortRange{}
		ports := strings.Split(entry, "-")
		// don't need to check integer parsing, as we already did it via regular expression
		e.Start, _ = strconv.Atoi(strings.TrimSpace(ports[0]))
		if len(ports) > 1 {
			e.End, _ = strconv.Atoi(strings.TrimSpace(ports[1]))
		}
		p.Ranges = append(p.Ranges, e)
	}
	return nil
}

func (p *PortEnum) Matches(port int) bool {
	for _, pr := range p.Ranges {
		if pr.End == 0 && pr.Start == port ||
			pr.End != 0 && pr.Start <= port && port <= pr.End {
			return true
		}
	}
	return false
}
