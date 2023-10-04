package services

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// DefinitionCriteria allows defining a group of services to be instrumented according to a set
// of attributes. If a given executable/service matches multiple of the attributes, the
// earliest defined service will take precedence.
type DefinitionCriteria []Attributes

func (dc DefinitionCriteria) Validate() error {
	// an empty definition criteria is valid
	for i := range dc {
		if len(dc[i].OpenPorts.ranges) == 0 || dc[i].Path.re == nil {
			return fmt.Errorf("attribute [%d] should define at least the open_ports or exe_path_regexp property", i)
		}
	}
	return nil
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
	Path PathRegexp `yaml:"exe_path_regexp"`
}

// PortEnum defines an enumeration of ports. It allows defining a set of single ports as well a set of
// port ranges. When unmarshalled from text, it accepts a comma-separated
// list of port numbers (e.g. 80) and port ranges (e.g. 8080-8089). For example, this would be a valid
// port range: 80,443,8000-8999
type PortEnum struct {
	ranges []portRange
}

type portRange struct {
	start int
	// if end == 0, it means this entry is not a port range but a single port
	end int
}

func (p *PortEnum) Len() int {
	return len(p.ranges)
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
		e := portRange{}
		ports := strings.Split(entry, "-")
		// don't need to check integer parsing, as we already did it via regular expression
		e.start, _ = strconv.Atoi(strings.TrimSpace(ports[0]))
		if len(ports) > 1 {
			e.end, _ = strconv.Atoi(strings.TrimSpace(ports[1]))
		}
		p.ranges = append(p.ranges, e)
	}
	return nil
}

func (p *PortEnum) Matches(port int) bool {
	for _, pr := range p.ranges {
		if pr.end == 0 && pr.start == port ||
			pr.end != 0 && pr.start <= port && port <= pr.end {
			return true
		}
	}
	return false
}

// PathRegexp stores a regular expression representing an executable file path.
type PathRegexp struct {
	re *regexp.Regexp
}

func NewPathRegexp(re *regexp.Regexp) PathRegexp {
	return PathRegexp{re: re}
}

func (p *PathRegexp) IsSet() bool {
	return p.re != nil
}

func (p *PathRegexp) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("PathRegexp: unexpected YAML node kind %d", value.Kind)
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

func (p *PathRegexp) UnmarshalText(text []byte) error {
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

func (p *PathRegexp) MatchString(input string) bool {
	// no regexp means "empty regexp", so anything will match it
	if p.re == nil {
		return true
	}
	return p.re.MatchString(input)
}
