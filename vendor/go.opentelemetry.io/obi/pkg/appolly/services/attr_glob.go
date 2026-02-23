// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package services // import "go.opentelemetry.io/obi/pkg/appolly/services"

import (
	"fmt"
	"iter"

	"github.com/gobwas/glob"
	"github.com/invopop/jsonschema"
	orderedmap "github.com/wk8/go-ordered-map/v2"
	"gopkg.in/yaml.v3"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
)

// GlobDefinitionCriteria allows defining a group of services to be instrumented according to a set
// of attributes. If a given executable/service matches multiple of the attributes, the
// earliest defined service will take precedence.
type GlobDefinitionCriteria []GlobAttributes

func (dc GlobDefinitionCriteria) Validate() error {
	// an empty definition criteria is valid
	for i := range dc {
		if dc[i].OpenPorts.Len() == 0 &&
			!dc[i].Path.IsSet() &&
			!dc[i].Languages.IsSet() &&
			len(dc[i].PIDs) == 0 &&
			len(dc[i].Metadata) == 0 &&
			len(dc[i].PodLabels) == 0 &&
			len(dc[i].PodAnnotations) == 0 {
			return fmt.Errorf("entry [%d] should define at least one selection criteria", i)
		}
		for k := range dc[i].Metadata {
			if _, ok := AllowedAttributeNames[k]; !ok {
				return fmt.Errorf("unknown attribute in discovery.instrument[%d]: %s", i, k)
			}
		}
	}
	return nil
}

func (dc GlobDefinitionCriteria) PortOfInterest(port int) bool {
	for i := range dc {
		if dc[i].OpenPorts.Matches(port) {
			return true
		}
	}
	return false
}

type MetadataGlobMap map[string]*GlobAttr

func (MetadataGlobMap) JSONSchema() *jsonschema.Schema {
	propMap := orderedmap.New[string, *jsonschema.Schema]()
	for k := range AllowedAttributeNames {
		propMap.Set(k, &jsonschema.Schema{
			Ref: "#/$defs/GlobAttr",
		})
	}
	return &jsonschema.Schema{
		Properties:  propMap,
		Type:        "object",
		Description: "Metadata attributes to match against the instrumented service",
	}
}

type GlobAttributes struct {
	// Name will define a name for the matching service. If unset, it will take the name of the executable process,
	// from the OTEL_SERVICE_NAME env var of the instrumented process, or from other metadata like Kubernetes annotations.
	//
	// Deprecated: Name should be set in the instrumentation target via kube metadata or standard env vars.
	//
	// To be kept undocumented until we remove it.
	Name string `yaml:"name"`
	// Namespace will define a namespace for the matching service. If unset, it will be left empty.
	//
	// Deprecated: Namespace should be set in the instrumentation target via kube metadata or standard env vars.
	//
	// To be kept undocumented until we remove it.
	Namespace string `yaml:"namespace"`

	// OpenPorts allows defining a group of ports that this service could open. It accepts a comma-separated
	// list of port numbers (e.g. 80) and port ranges (e.g. 8080-8089)
	OpenPorts IntEnum `yaml:"open_ports"`

	// Language allows defining services to instrument based on the
	// programming language they are written in. Use lowercase names, e.g. java,go
	Languages GlobAttr `yaml:"languages"`

	// PIDs allows selecting processes by PID. When non-empty, the process PID must be in this list (in addition to any path/port criteria).
	PIDs []uint32 `yaml:"target_pids"`

	// Path allows defining the regular expression matching the full executable path.
	Path GlobAttr `yaml:"exe_path"`

	// Metadata stores other attributes, such as Kubernetes object metadata
	Metadata MetadataGlobMap `yaml:",inline" mapstructure:",remain"`

	// PodLabels allows matching against the labels of a pod
	PodLabels map[string]*GlobAttr `yaml:"k8s_pod_labels"`

	// PodAnnotations allows matching against the annotations of a pod
	PodAnnotations map[string]*GlobAttr `yaml:"k8s_pod_annotations"`

	// ContainersOnly restricts the discovery to processes which are running inside a container
	ContainersOnly bool `yaml:"containers_only"`

	// Configures what to export. Allowed values are 'metrics', 'traces',
	// or an empty array (disabled). An unspecified value (nil) will use the
	// default configuration value
	ExportModes ExportModes `yaml:"exports"`

	SamplerConfig *SamplerConfig `yaml:"sampler"`

	Routes *CustomRoutesConfig `yaml:"routes"`

	// Metrics configuration that is custom for this service match
	Metrics perapp.SvcMetricsConfig `yaml:"metrics" env:"-"`
}

// GlobAttr provides a YAML handler for glob.Glob so the type can be parsed from YAML or environment variables
type GlobAttr struct {
	// str is kept for debugging/printing purposes
	str  string
	glob glob.Glob
}

func (GlobAttr) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type:        "string",
		Description: "Glob pattern to match against the attribute value",
		Format:      "glob",
		Examples:    []any{"app-*", "service-??", "prod-*-db"},
	}
}

func NewGlob(pattern string) GlobAttr {
	return GlobAttr{str: pattern, glob: glob.MustCompile(pattern)}
}

func (p *GlobAttr) IsSet() bool {
	return p.glob != nil
}

func (p *GlobAttr) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("GlobAttr: unexpected YAML node kind %d", value.Kind)
	}
	if len(value.Value) == 0 {
		p.glob = nil
		return nil
	}

	re, err := glob.Compile(value.Value)
	if err != nil {
		return fmt.Errorf("invalid regular expression in node %s: %w", value.Tag, err)
	}
	p.str = value.Value
	p.glob = re
	return nil
}

func (p GlobAttr) MarshalYAML() (any, error) {
	return p.str, nil
}

func (p *GlobAttr) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		p.glob = nil
		return nil
	}
	re, err := glob.Compile(string(text))
	if err != nil {
		return fmt.Errorf("invalid regular expression %q: %w", string(text), err)
	}
	p.glob = re
	return nil
}

func (p *GlobAttr) MatchString(input string) bool {
	// no glob means "empty glob", so anything will match it
	if p.glob == nil {
		return true
	}
	return p.glob.Match(input)
}

func (ga *GlobAttributes) GetName() string                        { return ga.Name }
func (ga *GlobAttributes) GetNamespace() string                   { return ga.Namespace }
func (ga *GlobAttributes) GetPath() StringMatcher                 { return &ga.Path }
func (ga *GlobAttributes) GetLanguages() StringMatcher            { return &ga.Languages }
func (ga *GlobAttributes) GetPathRegexp() StringMatcher           { return nilMatcher{} }
func (ga *GlobAttributes) GetOpenPorts() *IntEnum                 { return &ga.OpenPorts }
func (ga *GlobAttributes) GetPIDs() ([]app.PID, bool)             { return ga.pids() }
func (ga *GlobAttributes) IsContainersOnly() bool                 { return ga.ContainersOnly }
func (ga *GlobAttributes) MetricsConfig() perapp.SvcMetricsConfig { return ga.Metrics }

func (ga *GlobAttributes) RangeMetadata() iter.Seq2[string, StringMatcher] {
	return func(yield func(string, StringMatcher) bool) {
		for k, v := range ga.Metadata {
			if !yield(k, v) {
				break
			}
		}
	}
}

func (ga *GlobAttributes) RangePodLabels() iter.Seq2[string, StringMatcher] {
	return func(yield func(string, StringMatcher) bool) {
		for k, v := range ga.PodLabels {
			if !yield(k, v) {
				break
			}
		}
	}
}

func (ga *GlobAttributes) RangePodAnnotations() iter.Seq2[string, StringMatcher] {
	return func(yield func(string, StringMatcher) bool) {
		for k, v := range ga.PodAnnotations {
			if !yield(k, v) {
				break
			}
		}
	}
}

func (ga *GlobAttributes) GetExportModes() ExportModes { return ga.ExportModes }

func (ga *GlobAttributes) GetSamplerConfig() *SamplerConfig { return ga.SamplerConfig }

func (ga *GlobAttributes) GetRoutesConfig() *CustomRoutesConfig { return ga.Routes }

func (ga *GlobAttributes) pids() ([]app.PID, bool) {
	if len(ga.PIDs) == 0 {
		return nil, false
	}
	out := make([]app.PID, len(ga.PIDs))
	for i, pid := range ga.PIDs {
		out[i] = app.PID(pid)
	}
	return out, true
}

type nilMatcher struct{}

func (n nilMatcher) IsSet() bool               { return false }
func (n nilMatcher) MatchString(_ string) bool { return false }
