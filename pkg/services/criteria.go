package services

import (
	"fmt"
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
	// AttrOwnerName would be a generic search criteria that would
	// match against deployment, replicaset, daemonset and statefulset names
	AttrOwnerName = "k8s_owner_name"
)

// any attribute name not in this set will cause an error during the YAML unmarshalling
var allowedAttributeNames = map[string]struct{}{
	AttrNamespace:       {},
	AttrPodName:         {},
	AttrDeploymentName:  {},
	AttrReplicaSetName:  {},
	AttrDaemonSetName:   {},
	AttrStatefulSetName: {},
	AttrOwnerName:       {},
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
	// Services selection. If the user defined the BEYLA_EXECUTABLE_NAME or BEYLA_OPEN_PORT variables, they will be automatically
	// added to the services definition criteria, with the lowest preference.
	Services DefinitionCriteria `yaml:"services"`

	// ExcludeServices works analogously to Services, but the applications matching this section won't be instrumented
	// even if they match the Services selection.
	ExcludeServices DefinitionCriteria `yaml:"exclude_services"`

	// DefaultExcludeServices by default prevents self-instrumentation of Beyla as well as related services (Alloy and OpenTelemetry collector)
	// It must be set to an empty string or a different value if self-instrumentation is desired.
	DefaultExcludeServices DefinitionCriteria `yaml:"default_exclude_services"`

	// PollInterval specifies, for the poll service watcher, the interval time between
	// process inspections
	// nolint:undoc
	PollInterval time.Duration `yaml:"poll_interval" env:"BEYLA_DISCOVERY_POLL_INTERVAL"`

	// SystemWide allows instrumentation of all HTTP (no gRPC) calls, incoming and outgoing at a system wide scale.
	// No filtering per application will be done. Using this option may result in reduced quality of information
	// gathered for certain languages, such as Golang.
	// nolint:undoc
	SystemWide bool `yaml:"system_wide" env:"BEYLA_SYSTEM_WIDE"`

	// This can be enabled to use generic HTTP tracers only, no Go-specifics will be used:
	SkipGoSpecificTracers bool `yaml:"skip_go_specific_tracers" env:"BEYLA_SKIP_GO_SPECIFIC_TRACERS"`

	// Debugging only option. Make sure the kernel side doesn't filter any PIDs, force user space filtering.
	// nolint:undoc
	BPFPidFilterOff bool `yaml:"bpf_pid_filter_off" env:"BEYLA_BPF_PID_FILTER_OFF"`

	// Disables instrumentation of services which are already instrumented
	ExcludeOTelInstrumentedServices bool `yaml:"exclude_otel_instrumented_services" env:"BEYLA_EXCLUDE_OTEL_INSTRUMENTED_SERVICES"`
}

// DefinitionCriteria allows defining a group of services to be instrumented according to a set
// of attributes. If a given executable/service matches multiple of the attributes, the
// earliest defined service will take precedence.
type DefinitionCriteria []Attributes

func (dc DefinitionCriteria) Validate() error {
	// an empty definition criteria is valid
	for i := range dc {
		if dc[i].OpenPorts.Len() == 0 &&
			!dc[i].Path.IsSet() &&
			!dc[i].PathRegexp.IsSet() &&
			len(dc[i].Metadata) == 0 &&
			len(dc[i].PodLabels) == 0 &&
			len(dc[i].PodAnnotations) == 0 {
			return fmt.Errorf("discovery.services[%d] should define at least one selection criteria", i)
		}
		for k := range dc[i].Metadata {
			if _, ok := allowedAttributeNames[k]; !ok {
				return fmt.Errorf("unknown attribute in discovery.services[%d]: %s", i, k)
			}
		}
	}
	return nil
}

func (dc DefinitionCriteria) PortOfInterest(port int) bool {
	for i := range dc {
		if dc[i].OpenPorts.Matches(port) {
			return true
		}
	}
	return false
}

// Attributes that specify a given instrumented service.
// Each instance has to define either the OpenPorts or Path property, or both. These are used to match
// a given executable. If both OpenPorts and Path are defined, the inspected executable must fulfill both
// properties.
type Attributes struct {
	// Name will define a name for the matching service. If unset, it will take the name of the executable process
	Name string `yaml:"name"`
	// Namespace will define a namespace for the matching service. If unset, it will be left empty.
	Namespace string `yaml:"namespace"`
	// OpenPorts allows defining a group of ports that this service could open. It accepts a comma-separated
	// list of port numbers (e.g. 80) and port ranges (e.g. 8080-8089)
	OpenPorts PortEnum `yaml:"open_ports"`
	// Path allows defining the regular expression matching the full executable path.
	Path RegexpAttr `yaml:"exe_path"`
	// PathRegexp is deprecated but kept here for backwards compatibility with Beyla 1.0.x.
	// Deprecated. Please use Path (exe_path YAML attribute)
	PathRegexp RegexpAttr `yaml:"exe_path_regexp"`

	// Metadata stores other attributes, such as Kubernetes object metadata
	Metadata map[string]*RegexpAttr `yaml:",inline"`

	// PodLabels allows matching against the labels of a pod
	PodLabels map[string]*RegexpAttr `yaml:"k8s_pod_labels"`

	// PodAnnotations allows matching against the annotations of a pod
	PodAnnotations map[string]*RegexpAttr `yaml:"k8s_pod_annotations"`
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

func (p *PortEnum) UnmarshalText(text []byte) error {
	val := string(text)
	if !validPortEnum.MatchString(val) {
		return fmt.Errorf("invalid port range %q. Must be a comma-separated list of numeric ports or port ranges (e.g. 8000-8999)", val)
	}
	for _, entry := range strings.Split(val, ",") {
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

// RegexpAttr stores a regular expression representing an executable file path.
type RegexpAttr struct {
	re *regexp.Regexp
}

func NewPathRegexp(re *regexp.Regexp) RegexpAttr {
	return RegexpAttr{re: re}
}

func (p *RegexpAttr) IsSet() bool {
	return p.re != nil
}

func (p *RegexpAttr) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("RegexpAttr: unexpected YAML node kind %d", value.Kind)
	}
	if len(value.Value) == 0 {
		p.re = nil
		return nil
	}
	re, err := regexp.Compile(value.Value)
	if err != nil {
		return fmt.Errorf("invalid regular expression in node %s: %w", value.Tag, err)
	}
	p.re = re
	return nil
}

func (p *RegexpAttr) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		p.re = nil
		return nil
	}
	re, err := regexp.Compile(string(text))
	if err != nil {
		return fmt.Errorf("invalid regular expression %q: %w", string(text), err)
	}
	p.re = re
	return nil
}

func (p *RegexpAttr) MatchString(input string) bool {
	// no regexp means "empty regexp", so anything will match it
	if p.re == nil {
		return true
	}
	return p.re.MatchString(input)
}
