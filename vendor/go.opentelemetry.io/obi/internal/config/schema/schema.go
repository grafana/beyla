// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package schema parses OBI configuration documents that use the v2 schema.
//
// Callers choose the parser that matches the deployment target. The package does
// not auto-detect deployment mode because standalone and receiver deployments
// allow different sections:
//   - a full OpenTelemetry declarative configuration document with the OBI
//     extension at extensions.obi, parsed by ParseStandaloneYAML
//   - a receiver-embedded OBI configuration with version and capture sections at
//     the top level, parsed by ParseReceiverYAML
//
// This package validates only the version, shape, and deployment-specific
// section boundaries needed to route the configuration. OBI-owned extension
// sections are modeled locally as structs. OpenTelemetry-owned document sections
// are modeled with otelconf/x so the parser follows the upstream declarative
// configuration schema, including development sections.
package schema // import "go.opentelemetry.io/obi/internal/config/schema"

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"

	"github.com/mitchellh/copystructure"
	"go.yaml.in/yaml/v3"

	otelconfx "go.opentelemetry.io/contrib/otelconf/x"
)

const (
	// SupportedFileFormat is the OpenTelemetry declarative configuration file
	// format version handled by this package.
	SupportedFileFormat = "1.0"

	// SupportedVersion is the OBI configuration schema version handled by this
	// package.
	SupportedVersion = "2.0"
)

const (
	sectionEnrich      = "enrich"
	sectionCorrelation = "correlation"
	sectionDaemon      = "daemon"
)

// Document is the top-level OpenTelemetry declarative configuration document
// that contains extensions.obi.
//
// OBI-specific settings are available through Extensions.OBI. OpenTelemetry
// declarative configuration sections are modeled by otelconf/x so OBI follows
// the upstream schema surface instead of carrying a parallel local model.
type Document struct {
	otelconfx.OpenTelemetryConfiguration `yaml:",inline"`
	Extensions                           Extensions `yaml:"extensions"`
	logLevelSet                          bool
	openTelemetryExtensionFields         []string
}

// UnmarshalYAML decodes OpenTelemetry-owned fields with otelconf/x and the OBI
// extension with the local schema model.
func (d *Document) UnmarshalYAML(node *yaml.Node) error {
	extensionFields, err := validateOpenTelemetryFields(node)
	if err != nil {
		return err
	}
	_, logLevelSet := mappingValue(node, "log_level")
	if err := node.Decode(&d.OpenTelemetryConfiguration); err != nil {
		return err
	}
	if distribution, ok := mappingValue(node, "distribution"); ok {
		if err := distribution.Decode(&d.Distribution); err != nil {
			return err
		}
	}
	extensions, ok := mappingValue(node, "extensions")
	if !ok {
		return errors.New("missing extensions")
	}
	if err := decodeKnownFields(extensions, &d.Extensions); err != nil {
		return err
	}
	d.logLevelSet = logLevelSet
	d.openTelemetryExtensionFields = extensionFields
	return nil
}

func validateOpenTelemetryFields(node *yaml.Node) ([]string, error) {
	configType := reflect.TypeFor[otelconfx.OpenTelemetryConfiguration]()
	var extensionFields []string
	for i := 0; i < len(node.Content)-1; i += 2 {
		field := node.Content[i].Value
		if field == "extensions" {
			continue
		}

		fieldType, ok := yamlFieldType(configType, field)
		if !ok {
			if allowsAdditionalYAMLFields(configType) {
				extensionFields = append(extensionFields, field)
				continue
			}
			return nil, fmt.Errorf("field %s not found in config v2 document", field)
		}
		if err := validateYAMLFields(node.Content[i+1], fieldType, field, &extensionFields); err != nil {
			return nil, err
		}
	}
	return extensionFields, nil
}

func validateYAMLFields(node *yaml.Node, valueType reflect.Type, path string, extensionFields *[]string) error {
	for valueType.Kind() == reflect.Pointer {
		valueType = valueType.Elem()
	}

	switch valueType.Kind() {
	case reflect.Struct:
		if node.Kind != yaml.MappingNode {
			return nil
		}
		for i := 0; i < len(node.Content)-1; i += 2 {
			field := node.Content[i].Value
			fieldPath := path + "." + field
			fieldType, ok := yamlFieldType(valueType, field)
			if !ok {
				if allowsAdditionalYAMLFields(valueType) {
					*extensionFields = append(*extensionFields, fieldPath)
					continue
				}
				return fmt.Errorf("field %s not found in config v2 document", fieldPath)
			}
			if err := validateYAMLFields(node.Content[i+1], fieldType, fieldPath, extensionFields); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		if node.Kind != yaml.SequenceNode {
			return nil
		}
		for i, item := range node.Content {
			if err := validateYAMLFields(item, valueType.Elem(), fmt.Sprintf("%s[%d]", path, i), extensionFields); err != nil {
				return err
			}
		}
	case reflect.Map:
		if node.Kind != yaml.MappingNode {
			return nil
		}
		for i := 1; i < len(node.Content); i += 2 {
			if err := validateYAMLFields(node.Content[i], valueType.Elem(), path, extensionFields); err != nil {
				return err
			}
		}
	}
	return nil
}

func yamlFieldType(valueType reflect.Type, name string) (reflect.Type, bool) {
	for valueType.Kind() == reflect.Pointer {
		valueType = valueType.Elem()
	}
	if valueType.Kind() != reflect.Struct {
		return nil, false
	}

	for field := range valueType.Fields() {
		if !field.IsExported() || field.Name == "AdditionalProperties" {
			continue
		}
		tag, _, _ := strings.Cut(field.Tag.Get("yaml"), ",")
		if tag == "-" {
			continue
		}
		if tag == "" {
			tag = strings.ToLower(field.Name)
		}
		if tag == name {
			return field.Type, true
		}
	}
	return nil, false
}

func allowsAdditionalYAMLFields(valueType reflect.Type) bool {
	for valueType.Kind() == reflect.Pointer {
		valueType = valueType.Elem()
	}
	if valueType.Kind() != reflect.Struct {
		return false
	}

	field, ok := valueType.FieldByName("AdditionalProperties")
	return ok && field.IsExported()
}

// OpenTelemetryExtensionFields returns paths handled by upstream declarative
// configuration extension points rather than the core schema.
func (d *Document) OpenTelemetryExtensionFields() []string {
	if d == nil {
		return nil
	}
	return append([]string(nil), d.openTelemetryExtensionFields...)
}

// HasLogLevel reports whether the document explicitly declared top-level
// log_level. otelconf/x defaults omitted log_level to info, so callers need this
// signal to avoid treating the default as user intent.
func (d *Document) HasLogLevel() bool {
	return d != nil && d.logLevelSet
}

// SetLogLevel assigns a top-level log_level value and marks it as explicit.
func (d *Document) SetLogLevel(level otelconfx.SeverityNumber) {
	d.LogLevel = &level
	d.logLevelSet = true
}

// MarshalYAML emits the OpenTelemetry document fields and extensions. The
// explicit wrapper avoids relying on yaml inline behavior for a type with custom
// unmarshaling in the upstream otelconf/x package.
func (d Document) MarshalYAML() (any, error) {
	value := struct {
		AttributeLimits            *otelconfx.AttributeLimits                   `yaml:"attribute_limits,omitempty"`
		Disabled                   otelconfx.OpenTelemetryConfigurationDisabled `yaml:"disabled,omitempty"`
		Distribution               otelconfx.Distribution                       `yaml:"distribution,omitempty"`
		FileFormat                 string                                       `yaml:"file_format"`
		InstrumentationDevelopment *otelconfx.ExperimentalInstrumentation       `yaml:"instrumentation/development,omitempty"`
		LogLevel                   *otelconfx.SeverityNumber                    `yaml:"log_level,omitempty"`
		LoggerProvider             *otelconfx.LoggerProvider                    `yaml:"logger_provider,omitempty"`
		MeterProvider              *otelconfx.MeterProvider                     `yaml:"meter_provider,omitempty"`
		Propagator                 *otelconfx.Propagator                        `yaml:"propagator,omitempty"`
		Resource                   *otelconfx.Resource                          `yaml:"resource,omitempty"`
		TracerProvider             *otelconfx.TracerProvider                    `yaml:"tracer_provider,omitempty"`
		Extensions                 Extensions                                   `yaml:"extensions"`
	}{
		AttributeLimits:            d.AttributeLimits,
		Disabled:                   d.Disabled,
		Distribution:               d.Distribution,
		FileFormat:                 d.FileFormat,
		InstrumentationDevelopment: d.InstrumentationDevelopment,
		LogLevel:                   d.LogLevel,
		LoggerProvider:             d.LoggerProvider,
		MeterProvider:              d.MeterProvider,
		Propagator:                 d.Propagator,
		Resource:                   d.Resource,
		TracerProvider:             d.TracerProvider,
		Extensions:                 d.Extensions,
	}

	var node yaml.Node
	if err := node.Encode(value); err != nil {
		return nil, err
	}
	removeNullAdditionalProperties(&node)
	return &node, nil
}

// otelconf/x models extensible objects with an untagged AdditionalProperties
// field. Remove its nil value so the generated Go name is not emitted as a YAML
// configuration key.
func removeNullAdditionalProperties(node *yaml.Node) {
	for _, child := range node.Content {
		removeNullAdditionalProperties(child)
	}
	if node.Kind != yaml.MappingNode {
		return
	}

	content := make([]*yaml.Node, 0, len(node.Content))
	for i := 0; i < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if key.Value == "additionalproperties" && value.Tag == "!!null" {
			continue
		}
		content = append(content, key, value)
	}
	node.Content = content
}

// Extensions holds declarative configuration extensions recognized by this
// package.
type Extensions struct {
	OBI *Extension `yaml:"obi"`
}

// Extension is the OBI v2 extension configuration.
//
// Capture is valid in all deployment modes. Enrich, Correlation, and Daemon are
// standalone-only sections and are rejected when parsing receiver-embedded
// configuration. ParseReceiverYAML synthesizes this shape from top-level receiver
// capture sections.
type Extension struct {
	Version     string       `yaml:"version"`
	Capture     Capture      `yaml:"capture"`
	Enrich      *Enrich      `yaml:"enrich,omitempty"`
	Correlation *Correlation `yaml:"correlation,omitempty"`
	Daemon      *Daemon      `yaml:"daemon,omitempty"`

	source *yaml.Node
}

type extensionData Extension

// WithDefaults overlays a parsed extension onto defaults. Programmatically
// constructed extensions do not have source data and retain their existing
// partial-conversion behavior.
func (e *Extension) WithDefaults(defaults *Extension) (*Extension, bool, error) {
	if e == nil || e.source == nil {
		return e, false, nil
	}

	merged, err := cloneExtensionData(defaults)
	if err != nil {
		return nil, false, err
	}
	if err := decode(e.source, &merged); err != nil {
		return nil, false, err
	}

	result := Extension(merged)
	result.source = e.source
	return &result, true, nil
}

func cloneExtensionData(extension *Extension) (extensionData, error) {
	if extension == nil {
		return extensionData{}, errors.New("missing config v2 defaults")
	}

	cloned, err := copystructure.Copy(extension)
	if err != nil {
		return extensionData{}, fmt.Errorf("copying config v2 defaults: %w", err)
	}
	return extensionData(*cloned.(*Extension)), nil
}

// FlowLimitAliasPresence reports which network flow limit aliases were present
// in parsed YAML. Programmatically constructed extensions report known as false.
func (e *Extension) FlowLimitAliasPresence() (
	networkPackets bool,
	maxTrackedFlows bool,
	known bool,
) {
	if e == nil {
		return false, false, false
	}
	if e.source == nil {
		return false, false, false
	}

	_, networkPackets = nestedNode(
		e.source,
		"capture",
		"limits",
		"network_packets",
	)
	_, maxTrackedFlows = nestedNode(
		e.source,
		"capture",
		"network",
		"capture",
		"flow_lifecycle",
		"max_tracked_flows",
	)
	return networkPackets, maxTrackedFlows, true
}

// receiverConfig mirrors the receiver-embedded layout, where capture sections
// appear beside version at the top level instead of under an extension.capture
// object.
type receiverConfig struct {
	Version string `yaml:"version"`
	Capture `yaml:",inline"`
}

// ParseStandaloneYAML decodes a standalone OBI v2 declarative document.
//
// The document must contain extensions.obi.version equal to SupportedVersion.
// Missing v2 markers return NotV2Error; present but unsupported markers return
// UnsupportedVersionError.
func ParseStandaloneYAML(data []byte) (*Document, *Extension, error) {
	root, err := parseYAML(data)
	if err != nil {
		return nil, nil, err
	}

	if version, ok := nestedScalar(root, "extensions", "obi", "version"); ok {
		if version != SupportedVersion {
			return nil, nil, &UnsupportedVersionError{Version: version}
		}
		var doc Document
		if err := decode(root, &doc); err != nil {
			return nil, nil, err
		}
		extensionNode, _ := nestedNode(root, "extensions", "obi")
		extension, err := decodeExtension(extensionNode)
		if err != nil {
			return nil, nil, err
		}
		doc.Extensions.OBI = extension
		if err := validateFileFormat(doc.FileFormat); err != nil {
			return nil, nil, err
		}
		if doc.Extensions.OBI == nil {
			return nil, nil, &NotV2Error{Reason: "missing extensions.obi"}
		}
		if err := ValidateStandalone(extension); err != nil {
			return nil, nil, err
		}
		return &doc, extension, nil
	}

	if version, ok := nestedVersion(root, "extensions", "obi", "version"); ok {
		return nil, nil, &UnsupportedVersionError{Version: version}
	}

	if _, ok := nestedVersion(root, "version"); ok {
		return nil, nil, &NotV2Error{Reason: "missing extensions.obi.version field"}
	}

	if looksLikeV1(root) {
		return nil, nil, &NotV2Error{Reason: "detected legacy v1 config shape"}
	}

	return nil, nil, &NotV2Error{Reason: "missing extensions.obi.version field"}
}

// ParseReceiverYAML decodes a receiver-embedded OBI v2 configuration.
//
// Receiver capture sections are accepted at the top level and normalized into
// Extension.Capture. Standalone-only keys are rejected by presence before decode
// so null or malformed values still report SectionNotAllowedError.
func ParseReceiverYAML(data []byte) (*Extension, error) {
	root, err := parseYAML(data)
	if err != nil {
		return nil, err
	}

	if _, ok := nestedNode(root, "extensions", "obi"); ok {
		return nil, &ReceiverLayoutError{}
	}

	disallowedSection, hasDisallowedSection := disallowedReceiverSection(root)

	if version, ok := nestedScalar(root, "version"); ok {
		if version != SupportedVersion {
			return nil, &UnsupportedVersionError{Version: version}
		}
		if hasDisallowedSection {
			return nil, &SectionNotAllowedError{Section: disallowedSection}
		}
		var receiver receiverConfig
		if err := decodeKnownFields(root, &receiver); err != nil {
			return nil, err
		}
		cfg := Extension{
			Version: receiver.Version,
			Capture: receiver.Capture,
			source:  receiverExtensionNode(root),
		}
		if err := ValidateReceiver(&cfg); err != nil {
			return nil, err
		}
		return &cfg, nil
	}

	if version, ok := nestedVersion(root, "version"); ok {
		return nil, &UnsupportedVersionError{Version: version}
	}

	if hasDisallowedSection {
		return nil, &SectionNotAllowedError{Section: disallowedSection}
	}

	if looksLikeV1(root) {
		return nil, &NotV2Error{Reason: "detected legacy v1 config shape"}
	}

	return nil, &NotV2Error{Reason: "missing top-level OBI v2 version field"}
}

// ValidateStandalone checks version support for a standalone OBI extension.
func ValidateStandalone(cfg *Extension) error {
	return validateVersion(cfg)
}

// ValidateReceiver checks version support and receiver section boundaries for an
// already decoded OBI extension.
func ValidateReceiver(cfg *Extension) error {
	if err := validateVersion(cfg); err != nil {
		return err
	}
	if cfg.Enrich != nil {
		return &SectionNotAllowedError{Section: sectionEnrich}
	}
	if cfg.Correlation != nil {
		return &SectionNotAllowedError{Section: sectionCorrelation}
	}
	if cfg.Daemon != nil {
		return &SectionNotAllowedError{Section: sectionDaemon}
	}
	return nil
}

func validateVersion(cfg *Extension) error {
	if cfg == nil {
		return errors.New("missing OBI config")
	}
	if cfg.Version != SupportedVersion {
		return &UnsupportedVersionError{Version: cfg.Version}
	}
	return nil
}

func validateFileFormat(fileFormat string) error {
	if fileFormat != SupportedFileFormat {
		return &UnsupportedFileFormatError{FileFormat: fileFormat}
	}
	return nil
}

func disallowedReceiverSection(root *yaml.Node) (string, bool) {
	if _, ok := mappingValue(root, sectionEnrich); ok {
		return sectionEnrich, true
	}
	if _, ok := mappingValue(root, sectionCorrelation); ok {
		return sectionCorrelation, true
	}
	if _, ok := mappingValue(root, sectionDaemon); ok {
		return sectionDaemon, true
	}
	return "", false
}

func looksLikeV1(root *yaml.Node) bool {
	for _, key := range []string{
		"ebpf",
		"discovery",
		"otel_metrics_export",
		"otel_traces_export",
		"prometheus_export",
		"attributes",
		"routes",
		"stats",
		"javaagent",
	} {
		if _, ok := mappingValue(root, key); ok {
			return true
		}
	}
	return false
}

func parseYAML(data []byte) (*yaml.Node, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := decoder.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return &doc, nil
		}
		return nil, fmt.Errorf("parsing config v2 YAML: %w", err)
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); err == nil {
		return nil, errors.New("config v2 YAML must contain exactly one document")
	} else if !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parsing trailing config v2 YAML: %w", err)
	}
	if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
		return doc.Content[0], nil
	}
	return &doc, nil
}

func decode(node *yaml.Node, dst any) error {
	if err := node.Decode(dst); err != nil {
		return fmt.Errorf("decoding config v2 YAML: %w", err)
	}
	return nil
}

func decodeKnownFields(node *yaml.Node, dst any) error {
	resolved, err := cloneYAMLNodeWithoutAliases(node, map[*yaml.Node]bool{})
	if err != nil {
		return fmt.Errorf("resolving config v2 YAML aliases: %w", err)
	}

	var data bytes.Buffer
	if err := yaml.NewEncoder(&data).Encode(resolved); err != nil {
		return fmt.Errorf("encoding config v2 YAML: %w", err)
	}

	decoder := yaml.NewDecoder(&data)
	decoder.KnownFields(true)
	if err := decoder.Decode(dst); err != nil {
		return fmt.Errorf("decoding config v2 YAML: %w", err)
	}
	return nil
}

func cloneYAMLNodeWithoutAliases(node *yaml.Node, visiting map[*yaml.Node]bool) (*yaml.Node, error) {
	if node == nil {
		return nil, nil
	}
	if visiting[node] {
		return nil, fmt.Errorf("cyclic alias %q", node.Value)
	}

	visiting[node] = true
	defer delete(visiting, node)

	if node.Kind == yaml.AliasNode {
		if node.Alias == nil {
			return nil, fmt.Errorf("unresolved alias %q", node.Value)
		}
		return cloneYAMLNodeWithoutAliases(node.Alias, visiting)
	}

	cloned := *node
	cloned.Anchor = ""
	cloned.Alias = nil
	cloned.Content = make([]*yaml.Node, len(node.Content))
	for i, child := range node.Content {
		var err error
		cloned.Content[i], err = cloneYAMLNodeWithoutAliases(child, visiting)
		if err != nil {
			return nil, err
		}
	}
	return &cloned, nil
}

func decodeExtension(node *yaml.Node) (*Extension, error) {
	var decoded extensionData
	if err := decodeKnownFields(node, &decoded); err != nil {
		return nil, err
	}

	extension := Extension(decoded)
	extension.source = node
	return &extension, nil
}

func receiverExtensionNode(root *yaml.Node) *yaml.Node {
	capture := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	var version *yaml.Node
	for i := 0; i < len(root.Content)-1; i += 2 {
		key := root.Content[i]
		value := root.Content[i+1]
		if key.Value == "version" {
			version = value
			continue
		}
		capture.Content = append(capture.Content, key, value)
	}

	return &yaml.Node{
		Kind: yaml.MappingNode,
		Tag:  "!!map",
		Content: []*yaml.Node{
			{
				Kind:  yaml.ScalarNode,
				Tag:   "!!str",
				Value: "version",
			},
			version,
			{
				Kind:  yaml.ScalarNode,
				Tag:   "!!str",
				Value: "capture",
			},
			capture,
		},
	}
}

func nestedScalar(root *yaml.Node, path ...string) (string, bool) {
	value, ok := nestedNode(root, path...)
	if !ok || value.Kind != yaml.ScalarNode || value.ShortTag() != "!!str" {
		return "", false
	}
	return value.Value, true
}

func nestedVersion(root *yaml.Node, path ...string) (string, bool) {
	value, ok := nestedNode(root, path...)
	if !ok {
		return "", false
	}
	if value.Kind == yaml.ScalarNode {
		return value.Value, true
	}
	return value.ShortTag(), true
}

func nestedNode(root *yaml.Node, path ...string) (*yaml.Node, bool) {
	cur := root
	for _, key := range path {
		next, ok := mappingValue(cur, key)
		if !ok {
			return nil, false
		}
		cur = next
	}
	return cur, true
}

func mappingValue(node *yaml.Node, key string) (*yaml.Node, bool) {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil, false
	}
	for i := 0; i < len(node.Content)-1; i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1], true
		}
	}
	return nil, false
}
