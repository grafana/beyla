package main

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

const (
	colorRed   = "\033[31m"
	colorBold  = "\033[1m"
	colorReset = "\033[0m"
)

type Field struct {
	Name     string
	YAMLKey  string
	EnvKey   string
	Ignored  bool
	FilePath string
	Line     int
	Column   int
	IsStruct bool
}

func findMarkdownFiles(root string) ([]string, error) {
	var mdFiles []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(path, ".md") {
			mdFiles = append(mdFiles, path)
		}
		return nil
	})
	return mdFiles, err
}

func isKnownStructName(name string) bool {
	return strings.HasSuffix(name, "Config") ||
		strings.HasSuffix(name, "Options") ||
		strings.HasSuffix(name, "Decorator") ||
		strings.HasSuffix(name, "Sampler") ||
		strings.Contains(name, "OTLP") ||
		name == "GrafanaOTLP"
}

func isKnownPackageStruct(pkg, selector string) bool {
	// Known struct types from specific packages
	if pkg == "otel" && selector == "Sampler" {
		return true
	}
	if pkg == "transform" && strings.HasSuffix(selector, "Decorator") {
		return true
	}
	return false
}

func isStructType(expr ast.Expr) bool {
	switch t := expr.(type) {
	case *ast.StructType:
		return true
	case *ast.Ident:
		return isKnownStructName(t.Name)
	case *ast.SelectorExpr:
		if ident, ok := t.X.(*ast.Ident); ok {
			selector := t.Sel.Name
			pkg := ident.Name

			if isKnownPackageStruct(pkg, selector) {
				return true
			}

			// General patterns
			return isKnownStructName(selector)
		}
	}
	return false
}

func hasNoDocDirective(comments *ast.CommentGroup) bool {
	if comments == nil {
		return false
	}
	for _, comment := range comments.List {
		// Remove spaces between // and the directive
		text := strings.ReplaceAll(comment.Text, "// /", "//")
		text = strings.ReplaceAll(text, "//  ", "//")
		text = strings.ReplaceAll(text, "// ", "//")
		if strings.Contains(text, "//nolint:undoc") || strings.Contains(text, "//Deprecated") {
			return true
		}
	}
	return false
}

func printError(field Field) {
	// Print the file location in a clickable format with color
	fmt.Printf("%s%s%s:%d:%d:%s %serror:%s undocumented configuration field '%s'%s\n",
		colorBold, field.FilePath, colorReset,
		field.Line, field.Column,
		colorReset,
		colorRed,
		colorReset,
		field.Name,
		colorReset)

	// Print the code context if available
	if code, err := readLineFromFile(field.FilePath, field.Line); err == nil {
		fmt.Printf("    %d | %s\n", field.Line, code)
	}
	fmt.Println()
}

func readLineFromFile(filepath string, line int) (string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	currentLine := 1
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if currentLine == line {
			return scanner.Text(), nil
		}
		currentLine++
	}
	return "", fmt.Errorf("line %d not found", line)
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
	return goFiles, err
}

func parseGoFile(file string) ([]Field, error) {
	var fields []Field
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, file, nil, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	ast.Inspect(node, func(n ast.Node) bool {
		if ts, ok := n.(*ast.TypeSpec); ok {
			if st, ok := ts.Type.(*ast.StructType); ok {
				fields = append(fields, parseStructFields(st, file, fset)...)
			}
		}
		return true
	})
	return fields, nil
}

func parseStructFields(st *ast.StructType, file string, fset *token.FileSet) []Field {
	var fields []Field
	for _, field := range st.Fields.List {
		if field.Tag == nil {
			continue
		}

		tag := reflect.StructTag(strings.Trim(field.Tag.Value, "`"))
		yamlKey := tag.Get("yaml")
		envKey := tag.Get("env")

		if yamlKey == "" && envKey == "" {
			continue
		}

		fieldData := extractFieldData(field, yamlKey, envKey, file, fset)
		fields = append(fields, fieldData)
	}
	return fields
}

func extractFieldData(field *ast.Field, yamlKey, envKey, file string, fset *token.FileSet) Field {
	ignored := hasNoDocDirective(field.Doc)

	var fieldName string
	if len(field.Names) > 0 {
		fieldName = field.Names[0].Name
	}

	// Clean up yaml/env keys
	yamlKey = strings.SplitN(yamlKey, ",", 2)[0]
	envKey = strings.SplitN(envKey, ",", 2)[0]

	pos := fset.Position(field.Pos())
	return Field{
		Name:     fieldName,
		YAMLKey:  yamlKey,
		EnvKey:   envKey,
		Ignored:  ignored,
		FilePath: file,
		Line:     pos.Line,
		Column:   pos.Column,
		IsStruct: isStructType(field.Type),
	}
}

func collectAllFields() ([]Field, error) {
	goFiles, err := findGoFiles()
	if err != nil {
		return nil, fmt.Errorf("error walking directory: %w", err)
	}

	var allFields []Field
	for _, file := range goFiles {
		fields, err := parseGoFile(file)
		if err != nil {
			log.Printf("Error parsing %s: %v", file, err)
			continue
		}
		allFields = append(allFields, fields...)
	}
	return allFields, nil
}

func buildDocString() (string, error) {
	mdFiles, err := findMarkdownFiles("docs")
	if err != nil {
		return "", fmt.Errorf("error finding markdown files: %w", err)
	}

	var docBuilder strings.Builder
	for _, file := range mdFiles {
		content, err := os.ReadFile(file)
		if err != nil {
			log.Printf("Error reading %s: %v", file, err)
			continue
		}
		docBuilder.Write(content)
	}
	return docBuilder.String(), nil
}

func findUndocumentedFields(fields []Field, docStr string) []Field {
	var undocumented []Field
	for _, field := range fields {
		if field.Ignored || field.IsStruct {
			continue
		}

		if field.YAMLKey != "" && !strings.Contains(docStr, "`"+field.YAMLKey+"`") {
			undocumented = append(undocumented, field)
			continue
		}

		if field.EnvKey != "" && !strings.Contains(docStr, "`"+field.EnvKey+"`") {
			undocumented = append(undocumented, field)
		}
	}
	return undocumented
}

func main() {
	fields, err := collectAllFields()
	if err != nil {
		log.Fatal(err)
	}

	docStr, err := buildDocString()
	if err != nil {
		log.Fatal(err)
	}

	undocumented := findUndocumentedFields(fields, docStr)
	if len(undocumented) > 0 {
		fmt.Printf("Found %d undocumented configuration fields:\n\n", len(undocumented))
		for _, field := range undocumented {
			printError(field)
		}
		fmt.Printf("%sTo fix these errors either:%s\n", colorBold, colorReset)
		fmt.Printf("  1. Add documentation for the fields in the docs/ directory\n")
		fmt.Printf("  2. Add '// nolint:undoc' above the field to skip the check\n\n")
		os.Exit(1)
	}

	fmt.Println("All configuration fields are documented!")
}
