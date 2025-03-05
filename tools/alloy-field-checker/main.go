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
		return nil, err
	}
	return goFiles, nil
}

func parseStructFields(st *ast.StructType, structName string, file string, fset *token.FileSet) []Field {
	var fields []Field
	for _, field := range st.Fields.List {
		if field.Names == nil || field.Tag == nil {
			continue
		}

		tag := strings.Trim(field.Tag.Value, "`")
		yamlTag := getTagValue(tag, "yaml")
		envTag := getTagValue(tag, "env")

		// Skip if field doesn't have yaml or env tag
		if yamlTag == "" && envTag == "" {
			continue
		}

		// Get the actual tag value without options
		if yamlTag != "" {
			if idx := strings.Index(yamlTag, ","); idx != -1 {
				yamlTag = yamlTag[:idx]
			}
		}
		if envTag != "" {
			if idx := strings.Index(envTag, ","); idx != -1 {
				envTag = envTag[:idx]
			}
		}

		// Skip if the tag is "-" or "inline"
		if yamlTag == "-" || envTag == "-" || yamlTag == ",inline" || envTag == ",inline" {
			continue
		}

		fieldName := field.Names[0].Name
		tagValue := yamlTag
		if yamlTag == "" {
			tagValue = envTag
		}

		// Skip if this specific field should be ignored
		if shouldIgnoreField(structName, fieldName, tagValue) {
			continue
		}

		fieldData := Field{
			Name:       fieldName,
			StructName: structName,
			Ignored:    hasNoDocDirective(field.Doc),
			FilePath:   file,
			Tag:        tagValue,
		}

		pos := fset.Position(field.Pos())
		fieldData.Line = pos.Line
		fieldData.Column = pos.Column

		fields = append(fields, fieldData)
	}
	return fields
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
		return nil, fmt.Errorf("error walking directory: %v", err)
	}

	var allFields []Field
	for _, file := range goFiles {
		fset := token.NewFileSet()
		node, err := parser.ParseFile(fset, file, nil, parser.ParseComments)
		if err != nil {
			log.Printf("Error parsing %s: %v", file, err)
			continue
		}

		ast.Inspect(node, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.TypeSpec:
				if shouldIgnoreStruct(x.Name.Name) {
					return true
				}
				if st, ok := x.Type.(*ast.StructType); ok {
					fields := parseStructFields(st, x.Name.Name, file, fset)
					allFields = append(allFields, fields...)
				}
			}
			return true
		})
	}
	return allFields, nil
}

func checkAlloyMapping(fields []Field) error {
	// Fetch beyla_linux.go from GitHub
	resp, err := http.Get("https://raw.githubusercontent.com/grafana/alloy/main/internal/component/beyla/ebpf/beyla_linux.go")
	if err != nil {
		return fmt.Errorf("error fetching beyla_linux.go: %v", err)
	}
	defer resp.Body.Close()

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading beyla_linux.go: %v", err)
	}

	// Parse the file content
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, "", content, parser.ParseComments)
	if err != nil {
		return fmt.Errorf("error parsing beyla_linux.go: %v", err)
	}

	assignedFields := make(map[string]bool)
	defaultConfigFields := make(map[string]bool)

	// Helper function to get the full field path
	getFieldPath := func(expr ast.Expr) string {
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

	// First pass: find all fields that are assigned from DefaultConfig
	ast.Inspect(node, func(n ast.Node) bool {
		if assign, ok := n.(*ast.AssignStmt); ok {
			for _, rhs := range assign.Rhs {
				if sel, ok := rhs.(*ast.SelectorExpr); ok {
					if xsel, ok := sel.X.(*ast.SelectorExpr); ok {
						if xident, ok := xsel.X.(*ast.Ident); ok {
							if xident.Name == "beyla" && xsel.Sel.Name == "DefaultConfig" {
								// Get the variable name being assigned to
								if lhs, ok := assign.Lhs[0].(*ast.Ident); ok {
									defaultConfigFields[lhs.Name] = true
								}
							}
						}
					}
				}
			}
		}
		return true
	})

	// Second pass: track all field assignments and accesses
	ast.Inspect(node, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			for i, lhs := range x.Lhs {
				if sel, ok := lhs.(*ast.SelectorExpr); ok {
					fieldPath := getFieldPath(lhs)

					// Mark all parts of the path as assigned
					parts := strings.Split(fieldPath, ".")
					for i := range parts {
						path := strings.Join(parts[:i+1], ".")
						assignedFields[path] = true
					}

					// Check if the base variable is from DefaultConfig
					if ident, ok := sel.X.(*ast.Ident); ok {
						if defaultConfigFields[ident.Name] {
							assignedFields[strings.ToLower(sel.Sel.Name)] = true
						}
					}

					// Also check the RHS for field accesses
					if i < len(x.Rhs) {
						rhsPath := getFieldPath(x.Rhs[i])
						if rhsPath != "" {
							parts := strings.Split(rhsPath, ".")
							for i := range parts {
								path := strings.Join(parts[:i+1], ".")
								assignedFields[path] = true
							}
						}
					}
				}
			}

		case *ast.SelectorExpr:
			// Track field accesses in any context
			fieldPath := getFieldPath(x)
			if fieldPath != "" {
				parts := strings.Split(fieldPath, ".")
				for i := range parts {
					path := strings.Join(parts[:i+1], ".")
					assignedFields[path] = true
				}
			}

		case *ast.KeyValueExpr:
			if key, ok := x.Key.(*ast.Ident); ok {
				fieldName := strings.ToLower(key.Name)
				assignedFields[fieldName] = true
			}
		}
		return true
	})

	unmappedFields := []Field{}
	for _, field := range fields {
		if field.Ignored {
			continue
		}

		fieldName := strings.ToLower(field.Name)
		if !assignedFields[fieldName] && field.Tag != "" {
			// Check if any parent struct is assigned
			found := false
			for assignedField := range assignedFields {
				if strings.HasSuffix(assignedField, "."+fieldName) {
					found = true
					break
				}
			}
			if !found {
				unmappedFields = append(unmappedFields, field)
			}
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

func main() {
	fields, err := collectAllFields()
	if err != nil {
		log.Fatal(err)
	}

	if err := checkAlloyMapping(fields); err != nil {
		os.Exit(1)
	}
}
