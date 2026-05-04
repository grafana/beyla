// Copyright Grafana Labs
// SPDX-License-Identifier: Apache-2.0

// beyla-schema generates a JSON schema from the Beyla configuration struct.
// Usage:
//
//	go run ./cmd/beyla-schema > config-schema.json
//	go run ./cmd/beyla-schema -output schema.json
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/invopop/jsonschema"

	"github.com/grafana/beyla/v3/pkg/beyla"
)

// SchemaGenerator holds the state for schema generation.
type SchemaGenerator struct {
	// enums maps type names to their valid enum values.
	enums map[string][]any
	// envVars maps (typeName, yamlFieldName) to environment variable names.
	envVars map[string]map[string]string
	// inlineFields maps typeName to a list of inline field type names.
	inlineFields map[string][]string
}

// NewSchemaGenerator creates a new SchemaGenerator with initialized registries.
func NewSchemaGenerator() *SchemaGenerator {
	return &SchemaGenerator{
		enums:        make(map[string][]any),
		envVars:      make(map[string]map[string]string),
		inlineFields: make(map[string][]string),
	}
}

// obiPackagesToScan lists OBI packages that contain types used in Beyla's config.
var obiPackagesToScan = []string{
	"pkg/obi",
	"pkg/config",
	"pkg/export",
	"pkg/export/debug",
	"pkg/export/imetrics",
	"pkg/export/instrumentations",
	"pkg/export/otel/otelcfg",
	"pkg/export/otel",
	"pkg/export/otel/perapp",
	"pkg/export/prom",
	"pkg/kube/kubeflags",
	"pkg/transform",
	"pkg/filter",
	"pkg/appolly/services",
	"pkg/appolly/meta",
	"pkg/internal/pipe/geoip",
	"pkg/internal/pipe/rdns",
}

// beylaPackagesToScan lists Beyla-specific packages that contain config types.
var beylaPackagesToScan = []string{
	"pkg/beyla",
	"pkg/export/otel",
	"pkg/export/otel/spanscfg",
	"pkg/internal/infraolly/process",
	"pkg/services",
}

// scanPackages scans all Go source files in the given packages under moduleRoot.
func (g *SchemaGenerator) scanPackages(moduleRoot string, packages []string) {
	fset := token.NewFileSet()
	for _, pkg := range packages {
		pkgPath := filepath.Join(moduleRoot, pkg)
		entries, err := os.ReadDir(pkgPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading package %s: %v\n", pkg, err)
			os.Exit(1)
		}

		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
				continue
			}
			if strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}

			filePath := filepath.Join(pkgPath, entry.Name())
			file, err := parser.ParseFile(fset, filePath, nil, parser.ParseComments)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error parsing %s: %v\n", filePath, err)
				os.Exit(1)
			}
			g.extractFileMetadata(file)
		}
	}
}

// extractFileMetadata extracts all metadata from a Go source file in a single pass.
func (g *SchemaGenerator) extractFileMetadata(file *ast.File) {
	for _, decl := range file.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}

		switch genDecl.Tok {
		case token.CONST:
			g.extractEnumsFromDecl(genDecl)
		case token.TYPE:
			g.extractStructMetadataFromDecl(genDecl)
		}
	}
}

// extractEnumsFromDecl extracts enum values from a const declaration.
func (g *SchemaGenerator) extractEnumsFromDecl(genDecl *ast.GenDecl) {
	var currentType string

	for _, spec := range genDecl.Specs {
		valueSpec, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}

		if valueSpec.Type != nil {
			currentType = exprToTypeName(valueSpec.Type)
		}

		for i, name := range valueSpec.Names {
			if name.Name == "_" || !name.IsExported() {
				continue
			}

			if i < len(valueSpec.Values) {
				typeName, value := extractConstValueAndType(valueSpec.Values[i], currentType)
				if typeName != "" && value != nil {
					g.enums[typeName] = append(g.enums[typeName], value)
				}
			}
		}
	}
}

// extractStructMetadataFromDecl extracts env vars and inline fields from a type declaration.
func (g *SchemaGenerator) extractStructMetadataFromDecl(genDecl *ast.GenDecl) {
	for _, spec := range genDecl.Specs {
		typeSpec, ok := spec.(*ast.TypeSpec)
		if !ok {
			continue
		}

		structType, ok := typeSpec.Type.(*ast.StructType)
		if !ok {
			continue
		}

		typeName := typeSpec.Name.Name
		if g.envVars[typeName] == nil {
			g.envVars[typeName] = make(map[string]string)
		}

		for _, field := range structType.Fields.List {
			if field.Tag == nil {
				continue
			}

			tag := strings.Trim(field.Tag.Value, "`")
			yamlName := extractTagValue(tag, "yaml")

			// Handle inline fields
			if strings.Contains(yamlName, "inline") || yamlName == ",inline" {
				g.extractInlineField(typeName, field)
				continue
			}

			// Handle env vars
			g.extractEnvVar(typeName, tag, yamlName)
		}
	}
}

// extractInlineField records an inline field relationship.
func (g *SchemaGenerator) extractInlineField(parentType string, field *ast.Field) {
	inlineTypeName := exprToTypeName(field.Type)
	if inlineTypeName != "" {
		g.inlineFields[parentType] = append(g.inlineFields[parentType], inlineTypeName)
	}
}

// extractEnvVar extracts environment variable mapping from a struct field.
func (g *SchemaGenerator) extractEnvVar(typeName, tag, yamlName string) {
	envVar := extractTagValue(tag, "env")
	if yamlName == "" || envVar == "" {
		return
	}

	// Remove options from yaml tag (e.g., "field,omitempty" -> "field")
	if idx := strings.Index(yamlName, ","); idx != -1 {
		yamlName = yamlName[:idx]
	}
	// Remove options from env tag (e.g., "VAR,expand" -> "VAR")
	if idx := strings.Index(envVar, ","); idx != -1 {
		envVar = envVar[:idx]
	}
	// Skip env vars that are just variable expansions
	if !strings.HasPrefix(envVar, "${") {
		g.envVars[typeName][yamlName] = envVar
	}
}

// extractTagValue extracts the value for a given key from a struct tag string.
func extractTagValue(tag, key string) string {
	search := key + `:"`
	idx := strings.Index(tag, search)
	if idx == -1 {
		return ""
	}
	start := idx + len(search)
	end := strings.Index(tag[start:], `"`)
	if end == -1 {
		return ""
	}
	return tag[start : start+end]
}

// findModuleRoot walks up from start until it finds a directory containing go.mod.
func findModuleRoot(start string) string {
	dir := start
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// findOBIModuleRoot reads Beyla's go.mod replace directive to locate the OBI module root.
func findOBIModuleRoot(beylaRoot string) string {
	data, err := os.ReadFile(filepath.Join(beylaRoot, "go.mod"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "replace go.opentelemetry.io/obi =>") {
			parts := strings.Fields(line)
			// format: replace go.opentelemetry.io/obi => ./path [version]
			if len(parts) >= 4 {
				return filepath.Join(beylaRoot, parts[3])
			}
		}
	}
	return ""
}

func exprToTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		return t.Sel.Name
	}
	return ""
}

// extractConstValueAndType extracts both the type name and value from a const expression.
func extractConstValueAndType(expr ast.Expr, inheritedType string) (typeName string, value any) {
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind == token.STRING {
			return inheritedType, strings.Trim(e.Value, `"`)
		}
	case *ast.CallExpr:
		callTypeName := exprToTypeName(e.Fun)
		if callTypeName != "" && len(e.Args) == 1 {
			if lit, ok := e.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
				return callTypeName, strings.Trim(lit.Value, `"`)
			}
		}
	case *ast.BinaryExpr:
		return "", nil
	case *ast.Ident:
		return "", nil
	}
	return "", nil
}

func main() {
	outputFile := flag.String("output", "", "Output file path (default: stdout)")
	flag.Parse()

	g := NewSchemaGenerator()

	beylaRoot := findModuleRoot(".")
	if beylaRoot == "" {
		fmt.Fprintln(os.Stderr, "Error: could not find Beyla module root (go.mod)")
		os.Exit(1)
	}

	obiRoot := findOBIModuleRoot(beylaRoot)
	if obiRoot == "" {
		fmt.Fprintln(os.Stderr, "Error: could not find OBI module root from go.mod replace directive")
		os.Exit(1)
	}

	g.scanPackages(obiRoot, obiPackagesToScan)
	g.scanPackages(beylaRoot, beylaPackagesToScan)

	reflector := &jsonschema.Reflector{
		RequiredFromJSONSchemaTags: true,
		AllowAdditionalProperties:  true,
		ExpandedStruct:             true,
		FieldNameTag:               "yaml",
		Mapper:                     g.customMapper(),
	}
	if err := reflector.AddGoComments("go.opentelemetry.io/obi", obiRoot, jsonschema.WithFullComment()); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not add OBI Go comments: %v\n", err)
	}
	if err := reflector.AddGoComments("github.com/grafana/beyla/v3", beylaRoot, jsonschema.WithFullComment()); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not add Beyla Go comments: %v\n", err)
	}

	schema := reflector.Reflect(&beyla.Config{})
	schema.Title = "Beyla Configuration Schema"
	schema.Description = "JSON Schema for Beyla eBPF auto-instrumentation configuration"

	g.processInlineFields(schema)
	processDeprecated(schema)
	g.processEnvVars(schema)
	normalizeDescriptions(schema)
	sortSchemaProperties(schema)

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(schema); err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding schema: %v\n", err)
		os.Exit(1)
	}

	data := buf.String()
	data = strings.ReplaceAll(data, `\u003c`, `<`)
	data = strings.ReplaceAll(data, `\u003e`, `>`)
	data = strings.ReplaceAll(data, `\u0026`, `&`)

	if *outputFile != "" {
		if err := os.WriteFile(*outputFile, []byte(data), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing to file: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Schema written to %s\n", *outputFile)
	} else {
		fmt.Print(data)
	}
}

// jsonSchemaer is the interface for types that provide custom JSON schemas.
type jsonSchemaer interface {
	JSONSchema() *jsonschema.Schema
}

// jsonSchemaerType is the reflect.Type for the jsonSchemaer interface.
var jsonSchemaerType = reflect.TypeOf((*jsonSchemaer)(nil)).Elem()

// buildInlineTypeSchemas uses reflection to find inline fields that implement JSONSchema().
func buildInlineTypeSchemas(rootType reflect.Type) map[string]func() *jsonschema.Schema {
	result := make(map[string]func() *jsonschema.Schema)
	visited := make(map[reflect.Type]bool)

	var walk func(t reflect.Type)
	walk = func(t reflect.Type) {
		for t.Kind() == reflect.Ptr {
			t = t.Elem()
		}

		if t.Kind() == reflect.Slice || t.Kind() == reflect.Array {
			walk(t.Elem())
			return
		}

		if t.Kind() == reflect.Map {
			walk(t.Elem())
			return
		}

		if t.Kind() != reflect.Struct {
			return
		}

		if visited[t] {
			return
		}
		visited[t] = true

		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			yamlTag := field.Tag.Get("yaml")

			if strings.Contains(yamlTag, "inline") {
				fieldType := field.Type
				for fieldType.Kind() == reflect.Ptr {
					fieldType = fieldType.Elem()
				}

				if hasJSONSchemaMethod(fieldType) {
					typeName := fieldType.Name()
					ft := fieldType
					result[typeName] = func() *jsonschema.Schema {
						return callJSONSchemaMethod(ft)
					}
				}
			}

			walk(field.Type)
		}
	}

	walk(rootType)
	return result
}

// hasJSONSchemaMethod checks if a type implements the JSONSchema() method.
func hasJSONSchemaMethod(t reflect.Type) bool {
	return t.Implements(jsonSchemaerType) || reflect.PointerTo(t).Implements(jsonSchemaerType)
}

// callJSONSchemaMethod calls the JSONSchema() method on a zero value of the given type.
func callJSONSchemaMethod(t reflect.Type) *jsonschema.Schema {
	method, ok := t.MethodByName("JSONSchema")
	if ok {
		zero := reflect.Zero(t)
		results := method.Func.Call([]reflect.Value{zero})
		if len(results) == 1 {
			if schema, ok := results[0].Interface().(*jsonschema.Schema); ok {
				return schema
			}
		}
	}

	method, ok = reflect.PointerTo(t).MethodByName("JSONSchema")
	if ok {
		zero := reflect.New(t)
		results := method.Func.Call([]reflect.Value{zero})
		if len(results) == 1 {
			if schema, ok := results[0].Interface().(*jsonschema.Schema); ok {
				return schema
			}
		}
	}

	return nil
}

// processInlineFields merges properties from inline field types into their parent schemas.
func (g *SchemaGenerator) processInlineFields(schema *jsonschema.Schema) {
	if schema == nil {
		return
	}

	inlineTypeSchemas := buildInlineTypeSchemas(reflect.TypeOf(beyla.Config{}))

	for typeName, inlineTypes := range g.inlineFields {
		defSchema, ok := schema.Definitions[typeName]
		if !ok {
			continue
		}

		for _, inlineTypeName := range inlineTypes {
			inlineSchema, ok := schema.Definitions[inlineTypeName]
			if !ok {
				if schemaFunc, found := inlineTypeSchemas[inlineTypeName]; found {
					inlineSchema = schemaFunc()
				}
			}

			if inlineSchema == nil {
				continue
			}

			if inlineSchema.Properties != nil && defSchema.Properties != nil {
				for pair := inlineSchema.Properties.Oldest(); pair != nil; pair = pair.Next() {
					if _, exists := defSchema.Properties.Get(pair.Key); !exists {
						defSchema.Properties.Set(pair.Key, pair.Value)
					}
				}
			}
		}
	}
}

// processEnvVars walks through all schemas and adds x-env-var extension.
func (g *SchemaGenerator) processEnvVars(schema *jsonschema.Schema) {
	if schema == nil {
		return
	}

	for typeName, defSchema := range schema.Definitions {
		if envVars, ok := g.envVars[typeName]; ok {
			addEnvVarsToProperties(defSchema, envVars)
		}
		g.processEnvVars(defSchema)
	}

	if envVars, ok := g.envVars["Config"]; ok {
		addEnvVarsToProperties(schema, envVars)
	}
}

// addEnvVarsToProperties adds x-env-var extension to properties that have env vars.
func addEnvVarsToProperties(schema *jsonschema.Schema, envVars map[string]string) {
	if schema == nil || schema.Properties == nil {
		return
	}

	for pair := schema.Properties.Oldest(); pair != nil; pair = pair.Next() {
		propName := pair.Key
		propSchema := pair.Value

		if envVar, ok := envVars[propName]; ok {
			if propSchema.Extras == nil {
				propSchema.Extras = make(map[string]any)
			}
			propSchema.Extras["x-env-var"] = envVar
		}
	}
}

// visitNestedSchemas recursively visits all nested schemas and calls the visitor function.
func visitNestedSchemas(schema *jsonschema.Schema, visitor func(*jsonschema.Schema)) {
	if schema == nil {
		return
	}
	visitor(schema)

	if schema.Properties != nil {
		for pair := schema.Properties.Oldest(); pair != nil; pair = pair.Next() {
			visitNestedSchemas(pair.Value, visitor)
		}
	}

	for _, s := range schema.Definitions {
		visitNestedSchemas(s, visitor)
	}

	for _, s := range []*jsonschema.Schema{
		schema.Not, schema.If, schema.Then, schema.Else,
		schema.Items, schema.Contains, schema.AdditionalProperties,
	} {
		visitNestedSchemas(s, visitor)
	}

	for _, list := range [][]*jsonschema.Schema{
		schema.AllOf, schema.AnyOf, schema.OneOf, schema.PrefixItems,
	} {
		for _, s := range list {
			visitNestedSchemas(s, visitor)
		}
	}

	for _, m := range []map[string]*jsonschema.Schema{
		schema.PatternProperties, schema.DependentSchemas,
	} {
		for _, s := range m {
			visitNestedSchemas(s, visitor)
		}
	}
}

// sortSchemaProperties sorts all properties and enums in the schema alphabetically.
func sortSchemaProperties(schema *jsonschema.Schema) {
	visitNestedSchemas(schema, sortSchemaNode)
}

func sortSchemaNode(schema *jsonschema.Schema) {
	if schema == nil {
		return
	}

	if len(schema.Enum) > 0 {
		sort.Slice(schema.Enum, func(i, j int) bool {
			return fmt.Sprint(schema.Enum[i]) < fmt.Sprint(schema.Enum[j])
		})
	}

	if schema.Properties != nil {
		var keys []string
		for pair := schema.Properties.Oldest(); pair != nil; pair = pair.Next() {
			keys = append(keys, pair.Key)
		}
		sort.Strings(keys)

		newProps := jsonschema.NewProperties()
		for _, key := range keys {
			if val, ok := schema.Properties.Get(key); ok {
				newProps.Set(key, val)
			}
		}
		schema.Properties = newProps
	}
}

// processDeprecated walks through all schemas and extracts "Deprecated:" from descriptions.
func processDeprecated(schema *jsonschema.Schema) {
	visitNestedSchemas(schema, processSchemaDeprecation)
}

func processSchemaDeprecation(schema *jsonschema.Schema) {
	if schema == nil || schema.Description == "" {
		return
	}

	lines := strings.Split(schema.Description, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)

		if strings.HasPrefix(lower, "deprecated:") {
			schema.Deprecated = true
			msg := strings.TrimSpace(trimmed[len("deprecated:"):])
			lines[i] = msg
			schema.Description = strings.TrimSpace(strings.Join(lines, "\n"))
			return
		}
		if lower == "deprecated" {
			schema.Deprecated = true
			lines = append(lines[:i], lines[i+1:]...)
			schema.Description = strings.TrimSpace(strings.Join(lines, "\n"))
			return
		}
	}
}

// normalizeDescriptions collapses newlines in all schema descriptions into single spaces.
func normalizeDescriptions(schema *jsonschema.Schema) {
	visitNestedSchemas(schema, func(s *jsonschema.Schema) {
		if s == nil || s.Description == "" {
			return
		}
		s.Description = strings.ReplaceAll(s.Description, "\n", " ")
	})
}

// customMapper returns a mapper function for types the default reflector cannot process.
func (g *SchemaGenerator) customMapper() func(reflect.Type) *jsonschema.Schema {
	return func(t reflect.Type) *jsonschema.Schema {
		if t.Implements(jsonSchemaerType) || reflect.PointerTo(t).Implements(jsonSchemaerType) {
			return nil
		}

		if t.Kind() == reflect.Func {
			return &jsonschema.Schema{
				Type:        "null",
				Description: "Function type (not serializable)",
			}
		}

		if t == reflect.TypeOf(time.Duration(0)) {
			return &jsonschema.Schema{
				Type:        "string",
				Description: "Duration in Go format (e.g., '30s', '5m', '1ms')",
				Pattern:     "^[0-9]+(ms|s|m)$",
				Examples:    []any{"30s", "5m", "1ms"},
			}
		}

		typeName := t.Name()
		if values, ok := g.enums[typeName]; ok && len(values) > 0 {
			return &jsonschema.Schema{
				Type: "string",
				Enum: values,
			}
		}

		return nil
	}
}
