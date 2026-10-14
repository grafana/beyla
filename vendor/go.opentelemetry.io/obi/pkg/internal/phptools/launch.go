// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package phptools // import "go.opentelemetry.io/obi/pkg/internal/phptools"

import (
	"path/filepath"
	"strings"
)

func isPHPFPM(executable string) bool {
	return strings.Contains(strings.ToLower(filepath.Base(executable)), "php-fpm")
}

func phpScriptArgument(args []string) string {
	isScript := true
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--":
			if isScript && i+1 < len(args) {
				return args[i+1]
			}
			return ""
		case arg == "-f" || arg == "--file" || arg == "-F" || arg == "--process-file":
			if i+1 < len(args) {
				return args[i+1]
			}
			return ""
		case strings.HasPrefix(arg, "--file="):
			return strings.TrimPrefix(arg, "--file=")
		case strings.HasPrefix(arg, "--process-file="):
			return strings.TrimPrefix(arg, "--process-file=")
		case arg == "-r" || arg == "--run" || arg == "-B" || arg == "--process-begin" ||
			arg == "-R" || arg == "--process-code" || arg == "-E" || arg == "--process-end":
			isScript = false
			if i+1 < len(args) {
				i++
			}
		case optionTakesNextArgument(arg):
			if i+1 < len(args) {
				i++
			}
		case strings.HasPrefix(arg, "-"):
			continue
		case isScript:
			return arg
		}
	}
	return ""
}

func optionTakesNextArgument(arg string) bool {
	switch arg {
	case "-c", "--php-ini", "-d", "--define", "-S", "--server", "-t", "--docroot", "-z", "--zend-extension":
		return true
	default:
		return false
	}
}
