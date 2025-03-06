package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type Field struct {
	Name       string
	StructName string
	FilePath   string
	Line       int
	Column     int
	Ignored    bool
	Tag        string
}

func hasNoDocDirective(comments *ast.CommentGroup) bool {
	if comments == nil {
		return false
	}
	for _, comment := range comments.List {
		text := comment.Text
		// Check for nolint directive with normalized spaces
		normalizedText := strings.ReplaceAll(text, "// /", "//")
		normalizedText = strings.ReplaceAll(normalizedText, "//  ", "//")
		normalizedText = strings.ReplaceAll(normalizedText, "// ", "//")
		if strings.Contains(normalizedText, "//nolint:undoc") {
			return true
		}
		// Check for Deprecated without normalizing spaces
		if strings.Contains(text, "// Deprecated") {
			return true
		}
	}
	return false
}

func shouldIgnoreStruct(structName string) bool {
	ignoredStructs := map[string]bool{
		"Config":        true, // main config
		"GrafanaConfig": true,
		"MetricsConfig": true,
		"GrafanaOTLP":   true,
	}
	return ignoredStructs[structName]
}

func shouldIgnoreField(structName, fieldName, tag string) bool {
	// Map of struct name -> field name -> tag to ignore
	ignoredFields := map[string]map[string][]string{
		"TracesConfig": {
			"TracesEndpoint":     {"endpoint"},
			"Protocol":           {"protocol"},
			"InsecureSkipVerify": {"insecure_skip_verify"},
		},
		"PrometheusConfig": {
			"Port": {"port"},
			"Path": {"path"},
			"TTL":  {"ttl"},
		},
	}

	if fields, ok := ignoredFields[structName]; ok {
		if tags, ok := fields[fieldName]; ok {
			for _, t := range tags {
				if t == tag {
					return true
				}
			}
		}
	}
	return false
}

func findGoFiles() ([]string, error) {
	var goFiles []string
	err := filepath.Walk("pkg", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(path, ".go") {
			goFiles = append(goFiles, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("error walking directory: %w", err)
	}
	return goFiles, nil
}

func parseStructFields(st *ast.StructType, structName string, file string, fset *token.FileSet) []Field {
	var fields []Field
	for _, field := range st.Fields.List {
		if !isValidField(field) {
			continue
		}

		fieldData, ok := processField(field, structName, file, fset)
		if !ok {
			continue
		}

		fields = append(fields, fieldData)
	}
	return fields
}

func isValidField(field *ast.Field) bool {
	return field.Names != nil && field.Tag != nil
}

func processField(field *ast.Field, structName, file string, fset *token.FileSet) (Field, bool) {
	tag := strings.Trim(field.Tag.Value, "`")
	yamlTag := getTagValue(tag, "yaml")
	envTag := getTagValue(tag, "env")

	// Skip if field doesn't have yaml or env tag
	if yamlTag == "" && envTag == "" {
		return Field{}, false
	}

	// Get the actual tag value without options
	yamlTag = stripTagOptions(yamlTag)
	envTag = stripTagOptions(envTag)

	// Skip if the tag is "-" or "inline"
	if isSkippableTag(yamlTag) || isSkippableTag(envTag) {
		return Field{}, false
	}

	fieldName := field.Names[0].Name
	tagValue := yamlTag
	if yamlTag == "" {
		tagValue = envTag
	}

	// Skip if this specific field should be ignored
	if shouldIgnoreField(structName, fieldName, tagValue) {
		return Field{}, false
	}

	pos := fset.Position(field.Pos())
	return Field{
		Name:       fieldName,
		StructName: structName,
		Ignored:    hasNoDocDirective(field.Doc),
		FilePath:   file,
		Tag:        tagValue,
		Line:       pos.Line,
		Column:     pos.Column,
	}, true
}

func stripTagOptions(tag string) string {
	if idx := strings.Index(tag, ","); idx != -1 {
		return tag[:idx]
	}
	return tag
}

func isSkippableTag(tag string) bool {
	return tag == "-" || tag == ",inline"
}

func getTagValue(tag, key string) string {
	tag = strings.Trim(tag, "`")
	for _, t := range strings.Split(tag, " ") {
		if strings.HasPrefix(t, key+":") {
			value := strings.TrimPrefix(t, key+":")
			value = strings.Trim(value, "\"")
			return value
		}
	}
	return ""
}

func collectAllFields() ([]Field, error) {
	goFiles, err := findGoFiles()
	if err != nil {
		return nil, err
	}

	var allFields []Field
	for _, file := range goFiles {
		fields, err := processFile(file)
		if err != nil {
			log.Printf("Error processing %s: %v", file, err)
			continue
		}
		allFields = append(allFields, fields...)
	}
	return allFields, nil
}

func processFile(file string) ([]Field, error) {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, file, nil, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	var fields []Field
	ast.Inspect(node, func(n ast.Node) bool {
		if typeSpec, ok := n.(*ast.TypeSpec); ok {
			if shouldIgnoreStruct(typeSpec.Name.Name) {
				return true
			}
			if st, ok := typeSpec.Type.(*ast.StructType); ok {
				fields = append(fields, parseStructFields(st, typeSpec.Name.Name, file, fset)...)
			}
		}
		return true
	})
	return fields, nil
}

func checkAlloyMapping(fields []Field) error {
	content, err := fetchAlloyFile()
	if err != nil {
		return err
	}

	assignedFields, err := extractAssignedFields(content)
	if err != nil {
		return err
	}

	return checkUnmappedFields(fields, assignedFields)
}

func fetchAlloyFile() ([]byte, error) {
	resp, err := http.Get("https://raw.githubusercontent.com/grafana/alloy/main/internal/component/beyla/ebpf/beyla_linux.go")
	if err != nil {
		return nil, fmt.Errorf("error fetching beyla_linux.go: %w", err)
	}
	defer resp.Body.Close()

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading beyla_linux.go: %w", err)
	}

	return content, nil
}

func extractAssignedFields(content []byte) (map[string]bool, error) {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, "", content, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("error parsing beyla_linux.go: %w", err)
	}

	assignedFields := make(map[string]bool)
	defaultConfigFields := make(map[string]bool)

	// First pass: find DefaultConfig assignments
	ast.Inspect(node, func(n ast.Node) bool {
		if assign, ok := n.(*ast.AssignStmt); ok {
			processAssignment(assign, defaultConfigFields)
		}
		return true
	})

	// Second pass: track field assignments
	ast.Inspect(node, func(n ast.Node) bool {
		processNode(n, assignedFields, defaultConfigFields)
		return true
	})

	return assignedFields, nil
}

func processAssignment(assign *ast.AssignStmt, defaultConfigFields map[string]bool) {
	for _, rhs := range assign.Rhs {
		if sel, ok := rhs.(*ast.SelectorExpr); ok {
			if xsel, ok := sel.X.(*ast.SelectorExpr); ok {
				if xident, ok := xsel.X.(*ast.Ident); ok {
					if xident.Name == "beyla" && xsel.Sel.Name == "DefaultConfig" {
						if lhs, ok := assign.Lhs[0].(*ast.Ident); ok {
							defaultConfigFields[lhs.Name] = true
						}
					}
				}
			}
		}
	}
}

func processNode(n ast.Node, assignedFields, defaultConfigFields map[string]bool) {
	if assign, ok := n.(*ast.AssignStmt); ok {
		processAssignStatement(assign, assignedFields, defaultConfigFields)
	} else if sel, ok := n.(*ast.SelectorExpr); ok {
		processSelector(sel, assignedFields)
	} else if kv, ok := n.(*ast.KeyValueExpr); ok {
		if key, ok := kv.Key.(*ast.Ident); ok {
			assignedFields[strings.ToLower(key.Name)] = true
		}
	}
}

func processAssignStatement(assign *ast.AssignStmt, assignedFields, defaultConfigFields map[string]bool) {
	for i, lhs := range assign.Lhs {
		if sel, ok := lhs.(*ast.SelectorExpr); ok {
			processFieldPath(sel, assignedFields, defaultConfigFields)
			if i < len(assign.Rhs) {
				processFieldPath(assign.Rhs[i], assignedFields, defaultConfigFields)
			}
		}
	}
}

func processSelector(sel *ast.SelectorExpr, assignedFields map[string]bool) {
	fieldPath := getFieldPath(sel)
	if fieldPath != "" {
		parts := strings.Split(fieldPath, ".")
		for i := range parts {
			path := strings.Join(parts[:i+1], ".")
			assignedFields[path] = true
		}
	}
}

func checkUnmappedFields(fields []Field, assignedFields map[string]bool) error {
	var unmappedFields []Field
	for _, field := range fields {
		if !field.Ignored && !isFieldMapped(field, assignedFields) {
			unmappedFields = append(unmappedFields, field)
		}
	}

	if len(unmappedFields) > 0 {
		fmt.Printf("\nFound %d unmapped fields:\n", len(unmappedFields))
		for _, field := range unmappedFields {
			fmt.Printf("  %s.%s (tag: %s) (%s:%d)\n", field.StructName, field.Name, field.Tag, field.FilePath, field.Line)
		}
		return fmt.Errorf("found unmapped fields")
	}

	return nil
}

func isFieldMapped(field Field, assignedFields map[string]bool) bool {
	fieldName := strings.ToLower(field.Name)
	if assignedFields[fieldName] {
		return true
	}

	// Check if any parent struct is assigned
	for assignedField := range assignedFields {
		if strings.HasSuffix(assignedField, "."+fieldName) {
			return true
		}
	}
	return false
}

func getFieldPath(expr ast.Expr) string {
	var parts []string
	for {
		switch x := expr.(type) {
		case *ast.SelectorExpr:
			parts = append([]string{x.Sel.Name}, parts...)
			expr = x.X
		case *ast.Ident:
			parts = append([]string{x.Name}, parts...)
			return strings.ToLower(strings.Join(parts, "."))
		default:
			return strings.ToLower(strings.Join(parts, "."))
		}
	}
}

func processFieldPath(expr ast.Expr, assignedFields map[string]bool, defaultConfigFields map[string]bool) {
	fieldPath := getFieldPath(expr)
	if fieldPath != "" {
		parts := strings.Split(fieldPath, ".")
		for i := range parts {
			path := strings.Join(parts[:i+1], ".")
			assignedFields[path] = true
		}

		// Check if the base variable is from DefaultConfig
		if sel, ok := expr.(*ast.SelectorExpr); ok {
			if ident, ok := sel.X.(*ast.Ident); ok {
				if defaultConfigFields[ident.Name] {
					assignedFields[strings.ToLower(sel.Sel.Name)] = true
				}
			}
		}
	}
}

func main() {
	fields, err := collectAllFields()
	if err != nil {
		log.Fatal(err)
	}

	if err := checkAlloyMapping(fields); err != nil {
		os.Exit(1)
	}
}
