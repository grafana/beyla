package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"regexp"
)

// findFunction finds the start and end byte positions of a function in source code
func findFunction(content []byte, funcName string) (start, end int, err error) {
	// Find function declaration
	funcPattern := fmt.Sprintf(`(?m)^func %s\(`, regexp.QuoteMeta(funcName))
	re := regexp.MustCompile(funcPattern)

	loc := re.FindIndex(content)
	if loc == nil {
		return 0, 0, fmt.Errorf("function %s not found", funcName)
	}

	start = loc[0]

	// Find the opening brace
	openBrace := -1
	for i := loc[1]; i < len(content); i++ {
		if content[i] == '{' {
			openBrace = i
			break
		}
	}

	if openBrace == -1 {
		return 0, 0, fmt.Errorf("opening brace not found for function %s", funcName)
	}

	// Count braces to find matching closing brace
	braceCount := 1
	for i := openBrace + 1; i < len(content); i++ {
		switch content[i] {
		case '{':
			braceCount++
		case '}':
			braceCount--
			if braceCount == 0 {
				// Found the matching closing brace
				// Include the closing brace and newline if present
				end = i + 1
				if end < len(content) && content[end] == '\n' {
					end++
				}
				return start, end, nil
			}
		}
	}

	return 0, 0, fmt.Errorf("matching closing brace not found for function %s", funcName)
}

// replaceFunction replaces a function in a Go file with new content, preserving exact formatting
func replaceFunction(filepath, funcName, newFuncContent string) error {
	// Read the file
	content, err := os.ReadFile(filepath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Find the function to replace
	start, end, err := findFunction(content, funcName)
	if err != nil {
		return err
	}

	// Build new content: before + new function + after
	var buf bytes.Buffer
	buf.Write(content[:start])
	buf.WriteString(newFuncContent)
	if end < len(content) {
		buf.Write(content[end:])
	}

	// Write back to file
	return os.WriteFile(filepath, buf.Bytes(), 0644)
}

func main() {
	var (
		filepath    string
		funcName    string
		newFuncFile string
	)

	flag := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flag.StringVar(&filepath, "file", "", "Go source file to modify")
	flag.StringVar(&funcName, "func", "", "Function name to replace")
	flag.StringVar(&newFuncFile, "new", "", "File containing new function content")

	if err := flag.Parse(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	if filepath == "" || funcName == "" || newFuncFile == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -file <file> -func <function_name> -new <new_function_file>\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Read new function content
	newFuncContent, err := os.ReadFile(newFuncFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading new function file: %v\n", err)
		os.Exit(1)
	}

	if err := replaceFunction(filepath, funcName, string(newFuncContent)); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Replaced %s in %s\n", funcName, filepath)
}
