// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package frameworks // import "go.opentelemetry.io/obi/pkg/internal/pythontools/frameworks"

import (
	"path/filepath"
	"slices"
	"strings"
	"unicode"
)

type TargetKind uint8

const (
	TargetNone TargetKind = iota
	TargetFile
	TargetScriptPath
	TargetModule
	TargetRunnableModule
	TargetDottedReference
)

type PythonLaunch struct {
	Target       string
	TargetKind   TargetKind
	SearchPaths  []string
	ScriptDir    string
	FallbackName string
	FastAPIAuto  bool
	FlaskAuto    bool
	PathConfig   PythonPathConfig
}

var genericModuleNames = map[string]struct{}{
	"api":         {},
	"app":         {},
	"application": {},
	"asgi":        {},
	"celery":      {},
	"cli":         {},
	"conf":        {},
	"config":      {},
	"entrypoint":  {},
	"index":       {},
	"main":        {},
	"manage":      {},
	"models":      {},
	"project":     {},
	"routes":      {},
	"run":         {},
	"runserver":   {},
	"server":      {},
	"service":     {},
	"settings":    {},
	"src":         {},
	"start":       {},
	"tasks":       {},
	"urls":        {},
	"views":       {},
	"web":         {},
	"worker":      {},
	"wsgi":        {},
}

func optionSet(values ...string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}

func CleanValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsFunc(value, unicode.IsControl) {
		return ""
	}
	return value
}

func isStrictApplicationReference(value string) bool {
	module, object, ok := strings.Cut(value, ":")
	return ok && validModule(module) && validModule(object)
}

func validModule(value string) bool {
	if value == "" {
		return false
	}
	for part := range strings.SplitSeq(value, ".") {
		if !validIdentifier(part) {
			return false
		}
	}
	return true
}

func validIdentifier(value string) bool {
	for i, r := range value {
		if i == 0 {
			if r != '_' && !unicode.IsLetter(r) {
				return false
			}
		} else if r != '_' && !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return value != ""
}

func separatedOptionValue(value string) bool {
	if value == "-" || !strings.HasPrefix(value, "-") {
		return true
	}

	digits := 0
	dot := false
	for i := 1; i < len(value); i++ {
		switch {
		case value[i] >= '0' && value[i] <= '9':
			digits++
		case value[i] == '.' && !dot:
			dot = true
		default:
			return false
		}
	}
	return digits > 0 && value[len(value)-1] != '.'
}

func splitShellFields(value string) ([]string, bool) {
	var fields []string
	var field strings.Builder
	var quote rune
	escaped := false
	started := false
	flush := func() {
		if started {
			fields = append(fields, field.String())
			field.Reset()
			started = false
		}
	}

	for _, r := range value {
		if escaped {
			field.WriteRune(r)
			escaped = false
			started = true
			continue
		}
		if r == '\\' && quote != '\'' {
			escaped = true
			started = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			} else {
				field.WriteRune(r)
			}
			started = true
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			started = true
			continue
		}
		if unicode.IsSpace(r) {
			flush()
			continue
		}
		field.WriteRune(r)
		started = true
	}
	if quote != 0 || escaped {
		return nil, false
	}
	flush()
	return fields, true
}

func splitList(value string) []string {
	var values []string
	for item := range strings.SplitSeq(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			values = append(values, item)
		}
	}
	return values
}

func specificModuleName(value string) string {
	value = CleanValue(value)
	if value == "" || value == "." || value == ".." || value == "-" || value == "__init__" || value == "__main__" {
		return ""
	}
	if _, generic := genericModuleNames[strings.ToLower(value)]; generic {
		return ""
	}
	return value
}

func isApplicationReference(value string) bool {
	module, object, ok := strings.Cut(value, ":")
	if !ok || !validModule(module) {
		return false
	}
	if before, _, found := strings.Cut(object, "("); found {
		object = before
	}
	return validModule(object)
}

func firstApplicationReference(values []string) string {
	for _, value := range values {
		if isApplicationReference(value) {
			return value
		}
	}
	return ""
}

func lastLongOptionValue(args []string, option, initial string) string {
	value := initial
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == option && i+1 < len(args):
			i++
			value = args[i]
		case strings.HasPrefix(args[i], option+"="):
			value = strings.TrimPrefix(args[i], option+"=")
		}
	}
	return value
}

func TargetReference(target string) string {
	target = strings.TrimSpace(target)
	if before, _, ok := strings.Cut(target, ":"); ok {
		target = before
	}
	return strings.TrimSpace(target)
}

func TargetName(target string) string {
	target = TargetReference(target)
	if target == "" {
		return ""
	}
	target = strings.ReplaceAll(target, `\`, "/")
	if strings.Contains(target, "/") {
		target = strings.TrimSuffix(filepath.Base(target), filepath.Ext(target))
	} else if strings.HasSuffix(strings.ToLower(target), ".py") {
		target = strings.TrimSuffix(target, filepath.Ext(target))
	}
	parts := strings.Split(target, ".")
	for i, part := range parts {
		if strings.EqualFold(part, "settings") && i > 0 {
			return specificModuleName(parts[i-1])
		}
	}
	for _, part := range slices.Backward(parts) {
		if name := specificModuleName(part); name != "" {
			return name
		}
	}
	return ""
}

func ClassifyTarget(target string) TargetKind {
	target = TargetReference(target)
	if target == "" {
		return TargetNone
	}
	if filepath.IsAbs(target) || strings.ContainsAny(target, `/\`) || strings.HasSuffix(strings.ToLower(target), ".py") {
		return TargetFile
	}
	return TargetModule
}
