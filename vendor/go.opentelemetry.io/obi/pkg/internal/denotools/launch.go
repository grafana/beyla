// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package denotools // import "go.opentelemetry.io/obi/pkg/internal/denotools"

import (
	"log/slog"
	"strings"
)

// DenoLaunch contains metadata parsed from a Deno command line.
type DenoLaunch struct {
	EntryPoint      string
	ConfigPath      string
	NoConfig        bool
	DiscoverProject bool
	direct          bool
}

type optionArity uint8

const (
	noValue optionArity = iota
	requiredValue
	optionalValue
	attachedValue
)

type commandContext uint8

const (
	rootContext commandContext = iota
	runContext
	serveContext
	watchContext
	evalContext
	replContext
)

var rootOptions = map[string]optionArity{
	"-L":          requiredValue,
	"-q":          noValue,
	"--log-level": requiredValue,
	"--quiet":     noValue,
}

var runtimeOptions = map[string]optionArity{
	"-A":                                   noValue,
	"-E":                                   attachedValue,
	"-I":                                   attachedValue,
	"-N":                                   attachedValue,
	"-P":                                   attachedValue,
	"-R":                                   attachedValue,
	"-S":                                   attachedValue,
	"-W":                                   attachedValue,
	"-c":                                   requiredValue,
	"-r":                                   attachedValue,
	"--allow-all":                          noValue,
	"--allow-env":                          attachedValue,
	"--allow-ffi":                          attachedValue,
	"--allow-hrtime":                       noValue,
	"--allow-import":                       attachedValue,
	"--allow-net":                          attachedValue,
	"--allow-plugin":                       noValue,
	"--allow-read":                         attachedValue,
	"--allow-run":                          attachedValue,
	"--allow-scripts":                      attachedValue,
	"--allow-sys":                          attachedValue,
	"--allow-write":                        attachedValue,
	"--cached-only":                        noValue,
	"--cert":                               requiredValue,
	"--compat":                             noValue,
	"--conditions":                         requiredValue,
	"--config":                             requiredValue,
	"--cpu-prof":                           noValue,
	"--cpu-prof-dir":                       requiredValue,
	"--cpu-prof-flamegraph":                noValue,
	"--cpu-prof-interval":                  requiredValue,
	"--cpu-prof-md":                        noValue,
	"--cpu-prof-name":                      requiredValue,
	"--deny-env":                           attachedValue,
	"--deny-ffi":                           attachedValue,
	"--deny-hrtime":                        noValue,
	"--deny-import":                        attachedValue,
	"--deny-net":                           attachedValue,
	"--deny-read":                          attachedValue,
	"--deny-run":                           attachedValue,
	"--deny-sys":                           attachedValue,
	"--deny-write":                         attachedValue,
	"--enable-op-summary-metrics":          noValue,
	"--enable-testing-features-do-not-use": noValue,
	"--eszip-internal-do-not-use":          noValue,
	"--frozen":                             attachedValue,
	"--frozen-lockfile":                    attachedValue,
	"--import":                             requiredValue,
	"--import-map":                         requiredValue,
	"--importmap":                          requiredValue,
	"--ignore-env":                         attachedValue,
	"--ignore-read":                        attachedValue,
	"--inspect":                            attachedValue,
	"--inspect-brk":                        attachedValue,
	"--inspect-publish-uid":                attachedValue,
	"--inspect-wait":                       attachedValue,
	"--linker":                             attachedValue,
	"--location":                           requiredValue,
	"--lock":                               optionalValue,
	"--lock-write":                         noValue,
	"--min-dep-age":                        requiredValue,
	"--minimum-dependency-age":             requiredValue,
	"--no-config":                          noValue,
	"--no-lock":                            noValue,
	"--no-npm":                             noValue,
	"--no-prompt":                          noValue,
	"--no-remote":                          noValue,
	"--no-use-env-proxy":                   noValue,
	"--node-modules-dir":                   attachedValue,
	"--node-modules-linker":                attachedValue,
	"--permission-set":                     attachedValue,
	"--preload":                            requiredValue,
	"--prompt":                             noValue,
	"--reload":                             attachedValue,
	"--require":                            requiredValue,
	"--seed":                               requiredValue,
	"--sloppy-imports":                     noValue,
	"--strace-ops":                         attachedValue,
	"--trace-ops":                          attachedValue,
	"--unsafely-ignore-certificate-errors": attachedValue,
	"--unstable":                           noValue,
	"--unstable-bare-node-builtins":        noValue,
	"--unstable-broadcast-channel":         noValue,
	"--unstable-bundle":                    noValue,
	"--unstable-byonm":                     noValue,
	"--unstable-cron":                      noValue,
	"--unstable-detect-cjs":                noValue,
	"--unstable-ffi":                       noValue,
	"--unstable-fs":                        noValue,
	"--unstable-http":                      noValue,
	"--unstable-kv":                        noValue,
	"--unstable-lazy-dynamic-imports":      noValue,
	"--unstable-lockfile-v5":               noValue,
	"--unstable-net":                       noValue,
	"--unstable-node-conditions":           requiredValue,
	"--unstable-node-globals":              noValue,
	"--unstable-no-legacy-abort":           noValue,
	"--unstable-npm-lazy-caching":          noValue,
	"--unstable-otel":                      noValue,
	"--unstable-process":                   noValue,
	"--unstable-raw-imports":               noValue,
	"--unstable-sloppy-imports":            noValue,
	"--unstable-subdomain-wildcards":       noValue,
	"--unstable-temporal":                  noValue,
	"--unstable-tsgo":                      noValue,
	"--unstable-unsafe-proto":              noValue,
	"--unstable-vsock":                     noValue,
	"--unstable-webgpu":                    noValue,
	"--unstable-worker-options":            noValue,
	"--use-env-proxy":                      noValue,
	"--unsafe-proto":                       noValue,
	"--v8-flags":                           attachedValue,
	"--vendor":                             attachedValue,
}

var applicationOptions = map[string]optionArity{
	"--check":           attachedValue,
	"--connected":       attachedValue,
	"--env":             attachedValue,
	"--env-file":        attachedValue,
	"--ext":             requiredValue,
	"--no-check":        attachedValue,
	"--no-clear-screen": noValue,
	"--no-code-cache":   noValue,
	"--tunnel":          attachedValue,
	"--unstable-hmr":    attachedValue,
	"--watch":           attachedValue,
	"--watch-exclude":   attachedValue,
	"--watch-hmr":       attachedValue,
	"-t":                attachedValue,
}

var runOptions = map[string]optionArity{
	"--coverage": attachedValue,
}

var serveOptions = map[string]optionArity{
	"--host":     requiredValue,
	"--open":     noValue,
	"--parallel": noValue,
	"--port":     requiredValue,
}

var evalOptions = map[string]optionArity{
	"-T":      noValue,
	"-p":      noValue,
	"--print": noValue,
	"--ts":    noValue,
}

var replOptions = map[string]optionArity{
	"--eval":      requiredValue,
	"--eval-file": requiredValue,
	"--json":      noValue,
}

var toolingCommands = map[string]struct{}{
	"add":             {},
	"approve-builds":  {},
	"approve-scripts": {},
	"audit":           {},
	"bench":           {},
	"bundle":          {},
	"bump-version":    {},
	"cache":           {},
	"check":           {},
	"ci":              {},
	"clean":           {},
	"compile":         {},
	"completions":     {},
	"coverage":        {},
	"create":          {},
	"deploy":          {},
	"desktop":         {},
	"doc":             {},
	"fmt":             {},
	"help":            {},
	"i":               {},
	"info":            {},
	"init":            {},
	"install":         {},
	"json_reference":  {},
	"jupyter":         {},
	"link":            {},
	"lint":            {},
	"list":            {},
	"lsp":             {},
	"outdated":        {},
	"pack":            {},
	"publish":         {},
	"remove":          {},
	"sandbox":         {},
	"task":            {},
	"test":            {},
	"transpile":       {},
	"types":           {},
	"uninstall":       {},
	"unlink":          {},
	"update":          {},
	"upgrade":         {},
	"vendor":          {},
	"why":             {},
	"x":               {},
}

// ParseDenoLaunch finds the application entrypoint and project options in a Deno command line.
func ParseDenoLaunch(args []string) DenoLaunch {
	launch := DenoLaunch{DiscoverProject: true}
	return parseDenoArgs(args, rootContext, launch, false)
}

func parseDenoArgs(args []string, context commandContext, launch DenoLaunch, projectOnly bool) DenoLaunch {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "" {
			continue
		}
		if arg == "--" {
			if !projectOnly && i+1 < len(args) && args[i+1] != "-" {
				launch.EntryPoint = args[i+1]
				launch.direct = context == rootContext
			}
			return launch
		}
		if arg == "-" {
			return launch
		}
		if strings.HasPrefix(arg, "-") {
			name, value, hasValue := splitOption(arg)
			if exitsWithoutApplication(name) {
				return DenoLaunch{}
			}
			if valid, exits := shortOptionBundle(context, name); valid {
				if exits {
					return DenoLaunch{}
				}
				continue
			}

			arity, ok := optionForContext(context, name)
			if !ok {
				if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
					slog.Debug("can't reliably discover Deno entrypoint after unknown option", "option", sanitizedOptionName(arg))
					return launch
				}
				continue
			}

			if name == "--no-config" {
				launch.NoConfig = true
			}
			if name == "--config" || name == "-c" {
				if hasValue {
					launch.ConfigPath = value
				} else if i+1 < len(args) {
					launch.ConfigPath = args[i+1]
				}
			}

			if hasValue {
				continue
			}
			switch arity {
			case requiredValue:
				if i+1 < len(args) {
					i++
				}
			case optionalValue:
				if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
					i++
				}
			}
			continue
		}

		if projectOnly {
			continue
		}
		if context != rootContext {
			launch.EntryPoint = arg
			return launch
		}

		switch arg {
		case "run":
			return parseDenoArgs(args[i+1:], runContext, launch, false)
		case "serve":
			return parseDenoArgs(args[i+1:], serveContext, launch, false)
		case "watch":
			return parseDenoArgs(args[i+1:], watchContext, launch, false)
		case "eval":
			return parseDenoArgs(args[i+1:], evalContext, launch, true)
		case "repl":
			return parseDenoArgs(args[i+1:], replContext, launch, true)
		}
		if _, ok := toolingCommands[arg]; ok {
			return DenoLaunch{}
		}

		launch.EntryPoint = arg
		launch.direct = true
		return launch
	}

	return launch
}

func optionForContext(context commandContext, name string) (optionArity, bool) {
	if arity, ok := rootOptions[name]; ok {
		return arity, true
	}
	if arity, ok := runtimeOptions[name]; ok {
		return arity, true
	}
	if arity, ok := applicationOptions[name]; ok {
		return arity, true
	}

	switch context {
	case rootContext, runContext, watchContext:
		arity, ok := runOptions[name]
		return arity, ok
	case serveContext:
		arity, ok := serveOptions[name]
		return arity, ok
	case evalContext:
		arity, ok := evalOptions[name]
		return arity, ok
	case replContext:
		arity, ok := replOptions[name]
		return arity, ok
	default:
		return noValue, false
	}
}

func splitOption(arg string) (name, value string, hasValue bool) {
	if name, value, hasValue = strings.Cut(arg, "="); hasValue {
		return name, value, true
	}
	if strings.HasPrefix(arg, "-c") && len(arg) > 2 {
		return "-c", arg[2:], true
	}
	if strings.HasPrefix(arg, "-L") && len(arg) > 2 {
		return "-L", arg[2:], true
	}
	return arg, "", false
}

func exitsWithoutApplication(name string) bool {
	switch name {
	case "-h", "-v", "-V", "--help", "--version":
		return true
	default:
		return false
	}
}

func shortOptionBundle(context commandContext, name string) (valid, exits bool) {
	if !strings.HasPrefix(name, "-") || strings.HasPrefix(name, "--") || len(name) <= 2 {
		return false, false
	}
	for _, option := range name[1:] {
		short := "-" + string(option)
		if exitsWithoutApplication(short) {
			exits = true
			continue
		}
		arity, ok := optionForContext(context, short)
		if !ok || arity == requiredValue {
			return false, false
		}
	}
	return true, exits
}

func sanitizedOptionName(arg string) string {
	name, _, _ := strings.Cut(arg, "=")
	if strings.HasPrefix(name, "--") || len(name) <= 2 {
		return name
	}
	return name[:2]
}
