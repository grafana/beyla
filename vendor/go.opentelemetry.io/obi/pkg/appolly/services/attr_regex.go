// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package services

import (
	"fmt"
	"iter"
	"regexp"

	"gopkg.in/yaml.v3"
)

// RegexDefinitionCriteria allows defining a group of services to be instrumented according to a set
// of attributes. If a given executable/service matches multiple of the attributes, the
// earliest defined service will take precedence.
type RegexDefinitionCriteria []RegexSelector

func (dc RegexDefinitionCriteria) Validate() error {
	// an empty definition criteria is valid
	for i := range dc {
		if dc[i].OpenPorts.Len() == 0 &&
			!dc[i].Path.IsSet() &&
			!dc[i].PathRegexp.IsSet() &&
			len(dc[i].Metadata) == 0 &&
			len(dc[i].PodLabels) == 0 &&
			len(dc[i].PodAnnotations) == 0 {
			return fmt.Errorf("index [%d] should define at least one selection criteria", i)
		}
		for k := range dc[i].Metadata {
			if _, ok := allowedAttributeNames[k]; !ok {
				return fmt.Errorf("unknown attribute in index [%d]: %s", i, k)
			}
		}
	}
	return nil
}

func (dc RegexDefinitionCriteria) PortOfInterest(port int) bool {
	for i := range dc {
		if dc[i].OpenPorts.Matches(port) {
			return true
		}
	}
	return false
}

// RegexSelector that specify a given instrumented service.
// Each instance has to define either the OpenPorts or Path property, or both. These are used to match
// a given executable. If both OpenPorts and Path are defined, the inspected executable must fulfill both
// properties.
type RegexSelector struct {
	// Name will define a name for the matching service. If unset, it will take the name of the executable process,
	// from the OTEL_SERVICE_NAME env var of the instrumented process, or from other metadata like Kubernetes annotations.
	// Deprecated: Name should be set in the instrumentation target via kube metadata or standard env vars.
	// To be kept undocumented until we remove it.
	Name string `yaml:"name"`
	// Namespace will define a namespace for the matching service. If unset, it will be left empty.
	// Deprecated: Namespace should be set in the instrumentation target via kube metadata or standard env vars.
	// To be kept undocumented until we remove it.
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

	// Restrict the discovery to processes which are running inside a container
	ContainersOnly bool `yaml:"containers_only"`

	// Configures what to export. Allowed values are 'metrics', 'traces',
	// or an empty array (disabled). An unspecified value (nil) will use the
	// default configuration value
	ExportModes ExportModes `yaml:"exports"`

	SamplerConfig *SamplerConfig `yaml:"sampler"`

	Routes *CustomRoutesConfig `yaml:"routes"`
}

// RegexpAttr stores a regular expression representing an executable file path.
type RegexpAttr struct {
	re *regexp.Regexp
}

func NewRegexp(pattern string) RegexpAttr {
	return RegexpAttr{re: regexp.MustCompile(pattern)}
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

func (p RegexpAttr) MarshalYAML() (any, error) {
	if p.re != nil {
		return p.re.String(), nil
	}
	return "", nil
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

func (a *RegexSelector) GetName() string              { return a.Name }
func (a *RegexSelector) GetNamespace() string         { return a.Namespace }
func (a *RegexSelector) GetPath() StringMatcher       { return &a.Path }
func (a *RegexSelector) GetPathRegexp() StringMatcher { return &a.PathRegexp }
func (a *RegexSelector) GetOpenPorts() *PortEnum      { return &a.OpenPorts }
func (a *RegexSelector) IsContainersOnly() bool       { return a.ContainersOnly }
func (a *RegexSelector) RangeMetadata() iter.Seq2[string, StringMatcher] {
	return func(yield func(string, StringMatcher) bool) {
		for k, v := range a.Metadata {
			if !yield(k, v) {
				return
			}
		}
	}
}

func (a *RegexSelector) RangePodLabels() iter.Seq2[string, StringMatcher] {
	return func(yield func(string, StringMatcher) bool) {
		for k, v := range a.PodLabels {
			if !yield(k, v) {
				return
			}
		}
	}
}

func (a *RegexSelector) RangePodAnnotations() iter.Seq2[string, StringMatcher] {
	return func(yield func(string, StringMatcher) bool) {
		for k, v := range a.PodAnnotations {
			if !yield(k, v) {
				return
			}
		}
	}
}

func (a *RegexSelector) GetExportModes() ExportModes { return a.ExportModes }

func (a *RegexSelector) GetSamplerConfig() *SamplerConfig { return a.SamplerConfig }

func (a *RegexSelector) GetRoutesConfig() *CustomRoutesConfig { return a.Routes }
