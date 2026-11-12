// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package configcmd // import "go.opentelemetry.io/obi/cmd/obi/internal/configcmd"

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	"go.yaml.in/yaml/v3"
	legacyyaml "gopkg.in/yaml.v3"

	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"

	"go.opentelemetry.io/obi/internal/config/convert"
	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/appolly/discover"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	obiconfig "go.opentelemetry.io/obi/pkg/config"
	featureexport "go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/transform"
)

const (
	ExitSuccess = 0
	ExitError   = 1
	ExitUsage   = 2
	ExitPartial = 3
)

type validationMode string

const (
	validationModeStandalone validationMode = "standalone"
	validationModeReceiver   validationMode = "receiver"
)

// MaybeRun handles an obi config command and reports whether args selected the
// config command group.
func MaybeRun(args []string, stdout, stderr io.Writer) (bool, int) {
	if len(args) == 0 || args[0] != "config" {
		return false, ExitSuccess
	}
	return true, run(args[1:], stdout, stderr)
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: obi config <validate|migrate> ...")
		return ExitUsage
	}

	switch args[0] {
	case "-h", "--help":
		fmt.Fprintln(stderr, "usage: obi config <validate|migrate> ...")
		return ExitSuccess
	case "validate":
		return runValidate(args[1:], stdout, stderr)
	case "migrate":
		return runMigrate(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown config subcommand %q\n", args[0])
		return ExitUsage
	}
}

func runValidate(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("obi config validate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprintln(flags.Output(), "usage: obi config validate [--mode=standalone|receiver] <path>")
		flags.PrintDefaults()
	}
	mode := flags.String("mode", string(validationModeStandalone), "validation mode: standalone or receiver")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitSuccess
		}
		return ExitUsage
	}
	if flags.NArg() != 1 {
		flags.Usage()
		return ExitUsage
	}
	selectedMode := validationMode(*mode)
	if selectedMode != validationModeStandalone && selectedMode != validationModeReceiver {
		fmt.Fprintf(stderr, "invalid validation mode %q; expected standalone or receiver\n", *mode)
		return ExitUsage
	}

	data, err := os.ReadFile(flags.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "validation failed: read %s: %v\n", flags.Arg(0), err)
		return ExitError
	}
	if err := validateConfig(data, selectedMode); err != nil {
		fmt.Fprintf(stderr, "validation failed: %v\n", err)
		return ExitError
	}

	fmt.Fprintln(stdout, "configuration is valid")
	return ExitSuccess
}

var errInvalidMode = errors.New("invalid validation mode")

var runtimeValidationMu sync.Mutex

func validateConfig(data []byte, mode validationMode) error {
	data = obiconfig.ReplaceEnv(data)

	var cfg *obi.Config
	var err error
	switch mode {
	case validationModeStandalone:
		var doc *schema.Document
		doc, _, err = schema.ParseStandaloneYAML(data)
		if err == nil {
			cfg, err = convert.DocumentToRuntime(doc)
		}
	case validationModeReceiver:
		var ext *schema.Extension
		ext, err = schema.ParseReceiverYAML(data)
		if err == nil {
			cfg, err = convert.V2ToRuntime(ext)
		}
	default:
		return fmt.Errorf("%w %q; expected standalone or receiver", errInvalidMode, mode)
	}
	if err != nil {
		return err
	}
	err = validateRuntimeConfig(cfg, mode)
	if err != nil {
		return fmt.Errorf("runtime configuration: %w", err)
	}
	return nil
}

func validateRuntimeConfig(cfg *obi.Config, mode validationMode) error {
	runtimeValidationMu.Lock()
	defer runtimeValidationMu.Unlock()

	logger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer slog.SetDefault(logger)

	switch mode {
	case validationModeStandalone:
		return cfg.ValidateStatic()
	case validationModeReceiver:
		return cfg.ValidateStaticForReceiver()
	default:
		return fmt.Errorf("%w %q; expected standalone or receiver", errInvalidMode, mode)
	}
}

func runMigrate(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("obi config migrate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprintln(flags.Output(), "usage: obi config migrate [--allow-partial] [--mode=standalone|receiver] <path>")
		flags.PrintDefaults()
	}
	allowPartial := flags.Bool("allow-partial", false, "write valid v2 output when some v1 fields cannot be preserved")
	mode := flags.String("mode", string(validationModeStandalone), "migration mode: standalone or receiver")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitSuccess
		}
		return ExitUsage
	}
	if flags.NArg() != 1 {
		flags.Usage()
		return ExitUsage
	}
	selectedMode := validationMode(*mode)
	if selectedMode != validationModeStandalone && selectedMode != validationModeReceiver {
		fmt.Fprintf(stderr, "invalid migration mode %q; expected standalone or receiver\n", *mode)
		return ExitUsage
	}

	data, err := os.ReadFile(flags.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "migration failed: read %s: %v\n", flags.Arg(0), err)
		return ExitError
	}
	output, report, partial, err := migrateConfigForModeWithOptions(
		data,
		selectedMode,
		migrationOptions{allowPartial: *allowPartial},
	)
	if err != nil {
		fmt.Fprintf(stderr, "migration failed: %v\n", err)
		return ExitError
	}
	if _, err := stdout.Write(output); err != nil {
		fmt.Fprintf(stderr, "migration failed: write output: %v\n", err)
		return ExitError
	}
	if report != "" {
		fmt.Fprint(stderr, report)
	}
	if partial {
		return ExitPartial
	}
	return ExitSuccess
}

func migrateConfig(data []byte) ([]byte, string, error) {
	return migrateConfigForMode(data, validationModeStandalone)
}

func migrateConfigForMode(
	data []byte,
	mode validationMode,
) ([]byte, string, error) {
	output, report, _, err := migrateConfigForModeWithOptions(data, mode, migrationOptions{})
	return output, report, err
}

type migrationOptions struct {
	allowPartial bool
}

func migrateConfigForModeWithOptions(
	data []byte,
	mode validationMode,
	options migrationOptions,
) ([]byte, string, bool, error) {
	replaced := obiconfig.ReplaceEnv(data)
	var v2Err error
	switch mode {
	case validationModeStandalone:
		_, _, v2Err = schema.ParseStandaloneYAML(replaced)
	case validationModeReceiver:
		_, v2Err = schema.ParseReceiverYAML(replaced)
	default:
		return nil, "", false, fmt.Errorf("%w %q; expected standalone or receiver", errInvalidMode, mode)
	}
	if v2Err == nil {
		return nil, "", false, fmt.Errorf("input is already a %s OBI config v2 document", mode)
	} else {
		if _, ok := errors.AsType[*schema.NotV2Error](v2Err); !ok {
			return nil, "", false, fmt.Errorf("source is not supported v1 YAML: %w", v2Err)
		}
	}
	cfg, unknown, err := loadV1ConfigForMode(replaced, mode, options.allowPartial)
	if err != nil {
		return nil, "", false, err
	}
	unknown = append(unknown, unknownV1HTTPParsingMatchPaths(replaced)...)
	if err := validateRuntimeConfig(cfg, mode); err != nil {
		return nil, "", false, fmt.Errorf("v1 runtime configuration: %w", err)
	}
	if err := validateMigratableSelectorRefinements(cfg); err != nil {
		return nil, "", false, err
	}

	doc, ext := convert.RuntimeToV2(cfg)
	if !cfg.Enabled(obi.FeatureAppO11y) {
		ext.Capture.Policy.DefaultAction = schema.CaptureActionExclude
	}
	preserveV1DNSMetrics(cfg, ext)

	var roundTripped *obi.Config
	switch mode {
	case validationModeStandalone:
		roundTripped, err = convert.DocumentToRuntime(doc)
	case validationModeReceiver:
		roundTripped, err = convert.V2ToRuntime(&schema.Extension{
			Version: ext.Version,
			Capture: ext.Capture,
		})
		if err == nil {
			setReceiverConsumers(roundTripped)
		}
	}
	if err != nil {
		return nil, "", false, fmt.Errorf("verify migrated config v2: %w", err)
	}
	unsupported, err := changedInputFields(replaced, cfg, roundTripped)
	if err != nil {
		return nil, "", false, fmt.Errorf("verify migrated fields: %w", err)
	}
	unsupported = append(unsupported, unknown...)
	if mode == validationModeReceiver {
		unsupported = append(unsupported, receiverExporterPaths(replaced)...)
	}
	sort.Strings(unsupported)
	unsupported = slices.Compact(unsupported)
	partial := len(unsupported) != 0
	if partial && !options.allowPartial {
		return nil, "", false, fmt.Errorf(
			"fields are outside the supported v1-to-v2 migration contract: %s",
			strings.Join(unsupported, ", "),
		)
	}

	var output []byte
	switch mode {
	case validationModeStandalone:
		output, err = yaml.Marshal(doc)
	case validationModeReceiver:
		output, err = yaml.Marshal(struct {
			Version        string `yaml:"version"`
			schema.Capture `yaml:",inline"`
		}{
			Version: ext.Version,
			Capture: ext.Capture,
		})
	}
	if err != nil {
		return nil, "", false, fmt.Errorf("encode config v2 YAML: %w", err)
	}
	output = obiconfig.EscapeEnv(output)
	if err := validateConfig(output, mode); err != nil {
		return nil, "", false, fmt.Errorf("migrated config v2 did not validate: %w", err)
	}

	if partial {
		return output, partialMigrationReport(replaced, unsupported), true, nil
	}
	return output, migrationReport(replaced), false, nil
}

func validateMigratableSelectorRefinements(cfg *obi.Config) error {
	selectors := discover.FindingCriteria(cfg)
	if len(selectors) < 2 {
		return nil
	}

	var exportsSet, exportsOmitted bool
	var routesSet, routesOmitted bool
	for _, selector := range selectors {
		if selector.GetExportModes() == services.ExportModeUnset {
			exportsOmitted = true
		} else {
			exportsSet = true
		}
		if selector.GetRoutesConfig() == nil {
			routesOmitted = true
		} else {
			routesSet = true
		}
	}

	var mixed []string
	if exportsSet && exportsOmitted {
		mixed = append(mixed, "exports")
	}
	if routesSet && routesOmitted {
		mixed = append(mixed, "routes")
	}
	if len(mixed) == 0 {
		return nil
	}

	return fmt.Errorf(
		"v1 selector refinements cannot be migrated safely: multiple effective discovery selectors mix explicit and omitted fields: %s; each field must be set on every effective selector or omitted from every effective selector",
		strings.Join(mixed, ", "),
	)
}

func receiverExporterPaths(data []byte) []string {
	var source map[string]any
	if err := yaml.Unmarshal(data, &source); err != nil {
		return nil
	}

	var paths []string
	for _, section := range []string{
		"otel_traces_export",
		"otel_metrics_export",
		"prometheus_export",
	} {
		value, ok := source[section]
		if !ok {
			continue
		}
		for _, path := range leafPaths(value, yamlPath{section}) {
			paths = append(paths, formatPath(path))
		}
	}
	return paths
}

func preserveV1DNSMetrics(cfg *obi.Config, ext *schema.Extension) {
	otelDNS := cfg.OTELMetrics.EndpointEnabled() &&
		instrumentations.NewInstrumentationSelection(
			cfg.OTELMetrics.Instrumentations,
		).DNSEnabled()
	prometheusDNS := cfg.Prometheus.EndpointEnabled() &&
		instrumentations.NewInstrumentationSelection(
			cfg.Prometheus.Instrumentations,
		).DNSEnabled()
	if otelDNS || prometheusDNS {
		ext.Capture.Instrumentation.DNS.Enabled.Metrics = true
	}
}

func loadV1ConfigForMode(data []byte, mode validationMode, allowUnknown bool) (*obi.Config, []string, error) {
	cfg, err := newV1Config(mode)
	if err != nil {
		return nil, nil, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return cfg, nil, nil
	}

	err = decodeV1Config(data, cfg, true)
	var unknown []string
	if err != nil && allowUnknown {
		if paths, ok := unknownV1FieldPaths(data, err); ok {
			cfg, err = newV1Config(mode)
			if err != nil {
				return nil, nil, err
			}
			err = decodeV1Config(data, cfg, false)
			unknown = paths
		}
	}
	if err != nil {
		if paths := unsupportedFeaturePathsFromYAML(data); len(paths) != 0 {
			return nil, nil, fmt.Errorf(
				"decode v1 YAML fields at %s: %w",
				strings.Join(paths, ", "),
				err,
			)
		}
		return nil, nil, fmt.Errorf("decode v1 YAML fields: %w", err)
	}

	cfg.Attributes.Select.Normalize()
	if cfg.OTELMetrics.EndpointEnabled() && cfg.OTELMetrics.DeprFeatures != 0 {
		cfg.Metrics.Features = cfg.OTELMetrics.DeprFeatures
	} else if cfg.Prometheus.EndpointEnabled() && cfg.Prometheus.DeprFeatures != 0 {
		cfg.Metrics.Features = cfg.Prometheus.DeprFeatures
	}
	if cfg.NetworkFlows.Enable {
		cfg.Metrics.Features |= featureexport.FeatureNetwork
	}

	return cfg, unknown, nil
}

func newV1Config(mode validationMode) (*obi.Config, error) {
	cfg := obi.DefaultConfig
	if cfg.Routes != nil {
		routes := *cfg.Routes
		cfg.Routes = &routes
	}
	if cfg.NameResolver != nil {
		nameResolver := *cfg.NameResolver
		cfg.NameResolver = &nameResolver
	}
	switch mode {
	case validationModeStandalone:
	case validationModeReceiver:
		setReceiverConsumers(&cfg)
	default:
		return nil, fmt.Errorf("%w %q; expected standalone or receiver", errInvalidMode, mode)
	}
	return &cfg, nil
}

func decodeV1Config(data []byte, cfg *obi.Config, knownFields bool) error {
	// V1 custom unmarshallers use gopkg.in/yaml.v3.Node, so decoding through
	// go.yaml.in/yaml/v3 would bypass their compatibility behavior.
	decoder := legacyyaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(knownFields)
	if err := decoder.Decode(cfg); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("v1 YAML must contain exactly one document")
		}
		return fmt.Errorf("decode trailing v1 YAML: %w", err)
	}
	return nil
}

type yamlFieldLocation struct {
	line int
	name string
}

// The legacy decoder reports unknown fields only in TypeError messages. Recover
// their YAML paths only when every decode error has that shape, so invalid known
// fields remain hard failures.
func unknownV1FieldPaths(data []byte, decodeErr error) ([]string, bool) {
	var typeErr *legacyyaml.TypeError
	if !errors.As(decodeErr, &typeErr) {
		return nil, false
	}

	var fields []yamlFieldLocation
	for _, message := range typeErr.Errors {
		line, remainder, ok := strings.Cut(message, ": field ")
		name, typeName, fieldOK := strings.Cut(remainder, " not found in type ")
		if !ok || !fieldOK || name == "" || typeName == "" ||
			!strings.HasPrefix(line, "line ") {
			return nil, false
		}
		lineNumber, err := strconv.Atoi(strings.TrimPrefix(line, "line "))
		if err != nil {
			return nil, false
		}
		fields = append(fields, yamlFieldLocation{line: lineNumber, name: name})
	}

	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, false
	}
	pathsByField := map[yamlFieldLocation][]string{}
	collectYAMLKeyPaths(&root, nil, pathsByField)
	paths := make([]string, 0, len(fields))
	for _, field := range fields {
		candidates := pathsByField[field]
		if len(candidates) == 0 {
			return nil, false
		}
		paths = append(paths, candidates[0])
		pathsByField[field] = candidates[1:]
	}
	sort.Strings(paths)
	return slices.Compact(paths), true
}

func collectYAMLKeyPaths(
	node *yaml.Node,
	prefix yamlPath,
	paths map[yamlFieldLocation][]string,
) {
	switch node.Kind {
	case yaml.DocumentNode:
		if len(node.Content) != 0 {
			collectYAMLKeyPaths(node.Content[0], prefix, paths)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i]
			value := node.Content[i+1]
			path := appendPath(prefix, key.Value)
			location := yamlFieldLocation{line: key.Line, name: key.Value}
			paths[location] = append(paths[location], formatPath(path))
			collectYAMLKeyPaths(value, path, paths)
		}
	case yaml.SequenceNode:
		for i, child := range node.Content {
			collectYAMLKeyPaths(child, appendPath(prefix, i), paths)
		}
	case yaml.AliasNode:
		collectYAMLKeyPaths(node.Alias, prefix, paths)
	}
}

func unknownV1HTTPParsingMatchPaths(data []byte) []string {
	var source any
	if err := yaml.Unmarshal(data, &source); err != nil {
		return nil
	}
	rawRules, ok := valueAtPath(source, yamlPath{
		"ebpf", "payload_extraction", "http", "enrichment", "rules",
	})
	if !ok {
		return nil
	}
	rules, ok := rawRules.([]any)
	if !ok {
		return nil
	}
	matchFields := taggedYAMLFields(reflect.TypeFor[obiconfig.HTTPParsingMatch]())
	rangeFields := taggedYAMLFields(reflect.TypeFor[obiconfig.NumericRange]())

	var paths []string
	for index, rawRule := range rules {
		rule, ok := rawRule.(map[string]any)
		if !ok {
			continue
		}
		match, ok := rule["match"].(map[string]any)
		if !ok {
			continue
		}
		matchPath := yamlPath{
			"ebpf", "payload_extraction", "http", "enrichment", "rules", index, "match",
		}
		for name, value := range match {
			if _, ok := matchFields[name]; !ok {
				paths = append(paths, formatPath(appendPath(matchPath, name)))
				continue
			}
			if name != "response_status_code" {
				continue
			}
			rangeConfig, ok := value.(map[string]any)
			if !ok {
				continue
			}
			for rangeName := range rangeConfig {
				if _, ok := rangeFields[rangeName]; !ok {
					paths = append(paths, formatPath(appendPath(
						appendPath(matchPath, name),
						rangeName,
					)))
				}
			}
		}
	}
	sort.Strings(paths)
	return slices.Compact(paths)
}

func taggedYAMLFields(structType reflect.Type) map[string]struct{} {
	fields := make(map[string]struct{}, structType.NumField())
	for field := range structType.Fields() {
		name, _, _ := strings.Cut(field.Tag.Get("yaml"), ",")
		if name != "" && name != "-" {
			fields[name] = struct{}{}
		}
	}
	return fields
}

func setReceiverConsumers(cfg *obi.Config) {
	cfg.Traces.TracesExport = func(context.Context, ptrace.Traces) error { return nil }
	cfg.OTELMetrics.MetricsExport = func(context.Context, pmetric.Metrics) error { return nil }
}

type yamlPath []any

func changedInputFields(data []byte, before, after *obi.Config) ([]string, error) {
	var source any
	if len(bytes.TrimSpace(data)) != 0 {
		if err := yaml.Unmarshal(data, &source); err != nil {
			return nil, err
		}
	}
	beforeMap, err := configMap(before)
	if err != nil {
		return nil, err
	}
	afterMap, err := configMap(after)
	if err != nil {
		return nil, err
	}

	root, _ := source.(map[string]any)
	var changed []string
	if hasAnyPath(root, "attributes.select") && before.Attributes.Select.RequiresV2Review() {
		changed = append(changed, "attributes.select")
	}
	languageDetectionSkipsPath := yamlPath{"discovery", "excluded_linux_system_paths"}
	languageDetectionSkipsName := formatPath(languageDetectionSkipsPath)
	if _, configured := valueAtPath(source, languageDetectionSkipsPath); configured {
		beforeValue, beforeOK := valueAtPath(beforeMap, languageDetectionSkipsPath)
		afterValue, afterOK := valueAtPath(afterMap, languageDetectionSkipsPath)
		if beforeOK != afterOK || !reflect.DeepEqual(beforeValue, afterValue) {
			changed = append(changed, languageDetectionSkipsName)
		}
	}

	// v2 keeps one match clause per selector, so the v1 grouping of selectors into
	// service entries is not preserved: compare the flattened selection instead
	logEnricherPath := yamlPath{"ebpf", "log_enricher", "services"}
	logEnricherName := formatPath(logEnricherPath)
	if _, configured := valueAtPath(source, logEnricherPath); configured {
		beforeValue, _ := valueAtPath(beforeMap, logEnricherPath)
		afterValue, _ := valueAtPath(afterMap, logEnricherPath)
		if !reflect.DeepEqual(logEnricherSelectors(beforeValue), logEnricherSelectors(afterValue)) {
			changed = append(changed, logEnricherName)
		}
	}

	for _, path := range leafPaths(source, nil) {
		name := formatPath(path)
		if name == languageDetectionSkipsName || strings.HasPrefix(name, languageDetectionSkipsName+"[") {
			continue
		}
		if name == logEnricherName || strings.HasPrefix(name, logEnricherName+"[") {
			continue
		}
		if migrationAlias(name) {
			continue
		}
		beforeValue, beforeOK := valueAtPath(beforeMap, path)
		afterValue, afterOK := valueAtPath(afterMap, path)
		if beforeOK != afterOK || !equalMigrationValues(name, beforeValue, afterValue) {
			changed = append(changed, name)
		}
	}
	for _, path := range sequencePaths(source, nil) {
		name := formatPath(path)
		if migrationAlias(name) || migrationSequenceAlias(name) {
			continue
		}
		if name == logEnricherName || strings.HasPrefix(name, logEnricherName+"[") {
			continue
		}
		beforeValue, beforeOK := valueAtPath(beforeMap, path)
		afterValue, afterOK := valueAtPath(afterMap, path)
		if beforeOK != afterOK || !reflect.DeepEqual(beforeValue, afterValue) {
			changed = append(changed, name)
		}
	}
	changed = append(changed, unsupportedLayeredRoutePaths(root, before.Routes)...)
	changed = append(changed, unsupportedFeaturePaths(root)...)
	if hasAnyPath(root, "otel_traces_export.sampler") {
		if path := changedMigrationSamplerPath(
			before.Traces.SamplerConfig,
			after.Traces.SamplerConfig,
		); path != "" {
			changed = append(changed, path)
		}
	}
	if hasAnyPath(root, "otel_metrics_export.interval") &&
		before.OTELMetrics.GetInterval() != after.OTELMetrics.GetInterval() {
		changed = append(changed, "otel_metrics_export.interval")
	}
	if (before.Traces.Enabled() ||
		hasNonEmptyStringPath(root, "otel_traces_export.protocol")) &&
		before.Traces.GetProtocol() != after.Traces.GetProtocol() {
		changed = append(changed, migrationOTLPProtocolPath(root, "otel_traces_export"))
	}
	if (before.OTELMetrics.EndpointEnabled() ||
		hasNonEmptyStringPath(root, "otel_metrics_export.protocol")) &&
		before.OTELMetrics.GetProtocol() != after.OTELMetrics.GetProtocol() {
		changed = append(changed, migrationOTLPProtocolPath(root, "otel_metrics_export"))
	}
	if !equalMigrationFeatures(before.Metrics.Features, after.Metrics.Features) {
		for _, path := range []string{
			"metrics.features",
			"otel_metrics_export.features",
			"prometheus_export.features",
		} {
			if hasAnyPath(root, path) {
				changed = append(changed, path)
			}
		}
	}
	if before.Enabled(obi.FeatureNetO11y) != after.Enabled(obi.FeatureNetO11y) {
		changed = append(changed, migrationNetworkEnablePath(root))
	}
	for _, comparison := range []struct {
		path    string
		enabled bool
		metrics bool
		before  []instrumentations.Instrumentation
		after   []instrumentations.Instrumentation
	}{
		{
			path:    "otel_traces_export.instrumentations",
			enabled: before.Traces.Enabled(),
			before:  before.Traces.Instrumentations,
			after:   after.Traces.Instrumentations,
		},
		{
			path:    "otel_metrics_export.instrumentations",
			enabled: before.OTELMetrics.EndpointEnabled(),
			metrics: true,
			before:  before.OTELMetrics.Instrumentations,
			after:   after.OTELMetrics.Instrumentations,
		},
		{
			path:    "prometheus_export.instrumentations",
			enabled: before.Prometheus.EndpointEnabled(),
			metrics: true,
			before:  before.Prometheus.Instrumentations,
			after:   after.Prometheus.Instrumentations,
		},
	} {
		if (comparison.enabled || hasAnyPath(root, comparison.path)) &&
			!equalMigrationInstrumentations(comparison.before, comparison.after) {
			changed = append(changed, comparison.path)
		}
		if comparison.enabled && comparison.metrics &&
			(before.Metrics.Features.AnySpanMetrics() || before.Metrics.Features.ServiceGraph()) &&
			!preservesV1DerivedMetricProtocols(comparison.after) {
			changed = append(changed, comparison.path)
		}
	}
	sort.Strings(changed)
	return slices.Compact(changed), nil
}

func preservesV1DerivedMetricProtocols(protocols []instrumentations.Instrumentation) bool {
	selection := instrumentations.NewInstrumentationSelection(protocols)
	// V1 derived metrics bypass protocol selection. DNS does not emit derived
	// metrics; protocols without a v2 switch retain their default selection.
	for _, protocol := range []instrumentations.Instrumentation{
		instrumentations.InstrumentationHTTP,
		instrumentations.InstrumentationGRPC,
		instrumentations.InstrumentationSQL,
		instrumentations.InstrumentationRedis,
		instrumentations.InstrumentationKafka,
		instrumentations.InstrumentationMongo,
		instrumentations.InstrumentationCouchbase,
		instrumentations.InstrumentationGPU,
		instrumentations.InstrumentationAerospike,
	} {
		if !selection.Enabled(protocol) {
			return false
		}
	}
	return true
}

func equalMigrationFeatures(before, after featureexport.Features) bool {
	// "all" also sets unnamed bits that are not represented in a feature list.
	return slices.Equal(before.Names(), after.Names())
}

func equalMigrationInstrumentations(
	before, after []instrumentations.Instrumentation,
) bool {
	if len(before) != len(after) {
		return false
	}
	counts := make(map[instrumentations.Instrumentation]int, len(before))
	for _, instrumentation := range before {
		counts[instrumentation]++
	}
	for _, instrumentation := range after {
		counts[instrumentation]--
	}
	for _, count := range counts {
		if count != 0 {
			return false
		}
	}
	return true
}

func changedMigrationSamplerPath(
	before, after services.SamplerConfig,
) string {
	beforeName := normalizedMigrationSamplerName(before.Name)
	afterName := normalizedMigrationSamplerName(after.Name)
	beforeRatio, beforeErr := strconv.ParseFloat(before.Arg, 64)
	if (beforeName == services.SamplerTraceIDRatio ||
		beforeName == services.SamplerParentBasedTraceIDRatio) &&
		beforeErr != nil {
		return "otel_traces_export.sampler.arg"
	}
	if beforeName != afterName {
		return "otel_traces_export.sampler.name"
	}
	if beforeName != services.SamplerTraceIDRatio &&
		beforeName != services.SamplerParentBasedTraceIDRatio {
		return ""
	}

	afterRatio, afterErr := strconv.ParseFloat(after.Arg, 64)
	if afterErr != nil || beforeRatio != afterRatio {
		return "otel_traces_export.sampler.arg"
	}
	return ""
}

func normalizedMigrationSamplerName(name services.SamplerName) services.SamplerName {
	if name == "" {
		return services.SamplerParentBasedAlwaysOn
	}
	return name
}

// logEnricherSelectors flattens the marshaled ebpf.log_enricher.services value into
// the ordered list of its selectors, without the zero-valued fields that a
// re-imported selector marshals differently (an empty map instead of null)
func logEnricherSelectors(value any) []any {
	entries, _ := value.([]any)
	var selectors []any
	for _, entry := range entries {
		service, _ := entry.(map[string]any)
		nested, _ := service["service"].([]any)
		for _, selector := range nested {
			selectors = append(selectors, compactValue(selector))
		}
	}
	return selectors
}

func compactValue(value any) any {
	switch value := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(value))
		for key, nested := range value {
			if compacted := compactValue(nested); !zeroMigrationValue(compacted) {
				out[key] = compacted
			}
		}
		return out
	case []any:
		out := make([]any, 0, len(value))
		for _, nested := range value {
			out = append(out, compactValue(nested))
		}
		return out
	default:
		return value
	}
}

func zeroMigrationValue(value any) bool {
	switch value := value.(type) {
	case nil:
		return true
	case string:
		return value == ""
	case bool:
		return !value
	case int:
		return value == 0
	case float64:
		return value == 0
	case map[string]any:
		return len(value) == 0
	case []any:
		return len(value) == 0
	default:
		return false
	}
}

func equalMigrationValues(path string, before, after any) bool {
	if path == "log_level" {
		return strings.EqualFold(fmt.Sprint(before), fmt.Sprint(after))
	}
	return reflect.DeepEqual(before, after)
}

func configMap(cfg *obi.Config) (any, error) {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var out any
	if err := yaml.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func leafPaths(value any, prefix yamlPath) []yamlPath {
	switch value := value.(type) {
	case map[string]any:
		if len(value) == 0 {
			return []yamlPath{prefix}
		}
		var paths []yamlPath
		for key, child := range value {
			paths = append(paths, leafPaths(child, appendPath(prefix, key))...)
		}
		return paths
	case []any:
		if len(value) == 0 {
			return []yamlPath{prefix}
		}
		var paths []yamlPath
		for index, child := range value {
			paths = append(paths, leafPaths(child, appendPath(prefix, index))...)
		}
		return paths
	default:
		return []yamlPath{prefix}
	}
}

func sequencePaths(value any, prefix yamlPath) []yamlPath {
	switch value := value.(type) {
	case map[string]any:
		var paths []yamlPath
		for key, child := range value {
			paths = append(paths, sequencePaths(child, appendPath(prefix, key))...)
		}
		return paths
	case []any:
		paths := []yamlPath{prefix}
		for index, child := range value {
			paths = append(paths, sequencePaths(child, appendPath(prefix, index))...)
		}
		return paths
	default:
		return nil
	}
}

func appendPath(prefix yamlPath, part any) yamlPath {
	out := make(yamlPath, len(prefix), len(prefix)+1)
	copy(out, prefix)
	return append(out, part)
}

func valueAtPath(value any, path yamlPath) (any, bool) {
	for _, part := range path {
		switch part := part.(type) {
		case string:
			mapping, ok := value.(map[string]any)
			if !ok {
				return nil, false
			}
			value, ok = mapping[part]
			if !ok {
				return nil, false
			}
		case int:
			sequence, ok := value.([]any)
			if !ok || part >= len(sequence) {
				return nil, false
			}
			value = sequence[part]
		}
	}
	return value, true
}

func formatPath(path yamlPath) string {
	var out strings.Builder
	for _, part := range path {
		switch part := part.(type) {
		case string:
			if out.Len() != 0 {
				out.WriteByte('.')
			}
			out.WriteString(part)
		case int:
			fmt.Fprintf(&out, "[%d]", part)
		}
	}
	return out.String()
}

func migrationAlias(path string) bool {
	if migrationDiscoveryLegacyPathRegexpAlias(path) ||
		migrationDiscoveryExclusionAlias(path) ||
		migrationDiscoveryRouteAlias(path) {
		return true
	}
	for _, prefix := range []string{
		"executable_path",
		"filter.application",
		"open_port",
		"target_pids",
		"network.enable",
		"otel_metrics_export.features",
		"otel_metrics_export.interval",
		"otel_metrics_export.protocol",
		"prometheus_export.features",
		"routes",
		"otel_traces_export.protocol",
		"otel_traces_export.sampler",
		"otel_traces_export.instrumentations",
		"otel_metrics_export.instrumentations",
		"prometheus_export.instrumentations",
	} {
		if path == prefix || strings.HasPrefix(path, prefix+".") || strings.HasPrefix(path, prefix+"[") {
			return true
		}
	}
	return false
}

func migrationOTLPProtocolPath(root map[string]any, exporter string) string {
	if hasNonEmptyStringPath(root, exporter+".protocol") {
		return exporter + ".protocol"
	}
	return exporter + ".endpoint"
}

func migrationNetworkEnablePath(root map[string]any) string {
	for _, path := range []string{
		"network.enable",
		"metrics.features",
		"otel_metrics_export.features",
		"prometheus_export.features",
	} {
		if hasAnyPath(root, path) {
			return path
		}
	}
	return "network.enable"
}

func hasNonEmptyStringPath(root map[string]any, path string) bool {
	value, ok := rawValueAtPath(root, path)
	if !ok {
		return false
	}
	text, ok := value.(string)
	return ok && text != ""
}

func unsupportedFeaturePaths(root map[string]any) []string {
	var paths []string
	for _, path := range []string{
		"metrics.features",
		"otel_metrics_export.features",
		"prometheus_export.features",
	} {
		value, ok := rawValueAtPath(root, path)
		if ok && containsUnknownFeature(value) {
			paths = append(paths, path)
		}
	}

	discovery, ok := root["discovery"].(map[string]any)
	if !ok {
		return paths
	}
	for _, field := range []string{
		"instrument",
		"services",
		"exclude_instrument",
		"exclude_services",
		"default_exclude_instrument",
		"default_exclude_services",
	} {
		selectors, ok := discovery[field].([]any)
		if !ok {
			continue
		}
		for index, rawSelector := range selectors {
			selector, ok := rawSelector.(map[string]any)
			if !ok {
				continue
			}
			metrics, ok := selector["metrics"].(map[string]any)
			if !ok {
				continue
			}
			if _, ok := metrics["features"]; ok {
				paths = append(paths, fmt.Sprintf(
					"discovery.%s[%d].metrics.features",
					field,
					index,
				))
			}
		}
	}
	return paths
}

func unsupportedFeaturePathsFromYAML(data []byte) []string {
	var root map[string]any
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil
	}
	return unsupportedFeaturePaths(root)
}

func rawValueAtPath(root map[string]any, path string) (any, bool) {
	var current any = root
	for part := range strings.SplitSeq(path, ".") {
		mapping, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = mapping[part]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func containsUnknownFeature(value any) bool {
	features, ok := value.([]any)
	if !ok {
		return false
	}
	for _, value := range features {
		feature, ok := value.(string)
		if !ok {
			return true
		}
		if _, ok := featureexport.FeatureMapper[feature]; !ok {
			return true
		}
	}
	return false
}

func migrationSequenceAlias(path string) bool {
	switch path {
	case "metrics.features",
		"otel_metrics_export.features",
		"prometheus_export.features",
		"otel_traces_export.instrumentations",
		"otel_metrics_export.instrumentations",
		"prometheus_export.instrumentations",
		"discovery.instrument",
		"discovery.services",
		"discovery.exclude_services":
		return true
	default:
		return false
	}
}

func migrationDiscoveryRouteAlias(path string) bool {
	for _, prefix := range []string{
		"discovery.instrument",
		"discovery.services",
	} {
		field, ok := migrationDiscoverySelectorField(path, prefix)
		if ok && field == "routes" {
			return true
		}
	}
	return false
}

func unsupportedLayeredRoutePaths(
	root map[string]any,
	routes *transform.RoutesConfig,
) []string {
	policies := routes.DirectionalPolicies()
	directions := map[string]bool{
		"incoming": len(policies.Incoming.Patterns) > 0,
		"outgoing": len(policies.Outgoing.Patterns) > 0,
	}

	discovery, ok := root["discovery"].(map[string]any)
	if !ok {
		return nil
	}
	var paths []string
	for _, field := range []string{"instrument", "services"} {
		selectors, ok := discovery[field].([]any)
		if !ok {
			continue
		}
		for index, rawSelector := range selectors {
			selector, ok := rawSelector.(map[string]any)
			if !ok {
				continue
			}
			customRoutes, ok := selector["routes"].(map[string]any)
			if !ok {
				continue
			}
			for direction, globalPatterns := range directions {
				values, ok := customRoutes[direction].([]any)
				if globalPatterns && ok && len(values) > 0 {
					paths = append(paths, fmt.Sprintf(
						"discovery.%s[%d].routes.%s",
						field,
						index,
						direction,
					))
				}
			}
		}
	}
	return paths
}

func migrationDiscoveryLegacyPathRegexpAlias(path string) bool {
	for _, prefix := range []string{
		"discovery.services",
		"discovery.exclude_services",
		"discovery.default_exclude_services",
	} {
		field, ok := migrationDiscoverySelectorField(path, prefix)
		if ok && field == "exe_path_regexp" {
			return true
		}
	}
	return false
}

func migrationDiscoveryExclusionAlias(path string) bool {
	for _, prefix := range []string{
		"discovery.exclude_instrument",
		"discovery.default_exclude_instrument",
		"discovery.default_exclude_services",
	} {
		if path == prefix {
			return true
		}
		field, ok := migrationDiscoverySelectorField(path, prefix)
		if !ok {
			continue
		}
		switch field {
		case "open_ports", "target_pids", "languages", "exe_path", "cmd_args", "containers_only", "k8s_pod_labels", "k8s_pod_annotations":
			return true
		default:
			_, ok := services.AllowedAttributeNames[field]
			return ok
		}
	}
	return false
}

func migrationDiscoverySelectorField(path, prefix string) (string, bool) {
	remainder, ok := strings.CutPrefix(path, prefix+"[")
	if !ok {
		return "", false
	}
	_, remainder, ok = strings.Cut(remainder, "].")
	if !ok {
		return "", false
	}
	field, _, _ := strings.Cut(remainder, ".")
	field, _, _ = strings.Cut(field, "[")
	return field, true
}

func migrationReport(data []byte) string {
	return strings.Join(migrationReportLines(data, false), "\n") + "\n"
}

func partialMigrationReport(data []byte, unsupported []string) string {
	lines := migrationReportLines(data, true)
	lines = append(lines, "- v1 fields not preserved exactly and requiring manual migration:")
	for _, path := range unsupported {
		lines = append(lines, "  - "+path)
	}
	return strings.Join(lines, "\n") + "\n"
}

func migrationReportLines(data []byte, partial bool) []string {
	var root map[string]any
	_ = yaml.Unmarshal(data, &root)

	status := "migrated v1 config to OBI config v2"
	if partial {
		status = "partially migrated v1 config to OBI config v2; manual changes are required"
	}
	lines := []string{status}
	if hasAnyPath(root, "filter.application", "filter.network", "filter.stats") {
		lines = append(lines, "- fanned out v1 attribute filters to signal-scoped v2 filters")
	}
	if hasAnyPath(root,
		"discovery.instrument",
		"discovery.services",
		"discovery.exclude_instrument",
		"discovery.exclude_services",
		"executable_path",
		"open_port",
		"target_pids",
	) {
		lines = append(lines, "- reshaped effective discovery selectors into capture.rules")
	}
	if hasAnyPath(root, "discovery.skip_go_specific_tracers") {
		lines = append(lines, "- inverted discovery.skip_go_specific_tracers into capture.runtimes.go.enabled")
	}
	if hasAnyPath(root, "routes") || hasDiscoveryRoutes(root) {
		lines = append(lines, "- expanded v1 route settings into incoming and outgoing HTTP route policies")
	}
	if hasAnyPath(root, "otel_traces_export", "otel_metrics_export", "prometheus_export") {
		lines = append(lines, "- moved exporter configuration into top-level OpenTelemetry providers")
	}
	return lines
}

func hasDiscoveryRoutes(root map[string]any) bool {
	discovery, ok := root["discovery"].(map[string]any)
	if !ok {
		return false
	}
	for _, field := range []string{"instrument", "services"} {
		selectors, ok := discovery[field].([]any)
		if !ok {
			continue
		}
		for _, selector := range selectors {
			selector, ok := selector.(map[string]any)
			if ok {
				if _, ok := selector["routes"]; ok {
					return true
				}
			}
		}
	}
	return false
}

func hasAnyPath(root map[string]any, paths ...string) bool {
	for _, path := range paths {
		var current any = root
		found := true
		for part := range strings.SplitSeq(path, ".") {
			mapping, ok := current.(map[string]any)
			if !ok {
				found = false
				break
			}
			current, ok = mapping[part]
			if !ok {
				found = false
				break
			}
		}
		if found {
			return true
		}
	}
	return false
}
