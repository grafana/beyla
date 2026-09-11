// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rubytools // import "go.opentelemetry.io/obi/pkg/internal/rubytools"

import (
	"log/slog"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

var rubyCommand = regexp.MustCompile(`^ruby[\d.]*$`)

var rubyTooling = map[string]struct{}{
	"bundle":        {},
	"bundler":       {},
	"gem":           {},
	"irb":           {},
	"passenger":     {},
	"puma":          {},
	"rackup":        {},
	"rails":         {},
	"rake":          {},
	"sidekiq":       {},
	"unicorn":       {},
	"unicorn_rails": {},
}

type optionArity uint8

const (
	noValue optionArity = iota
	requiredValue
	terminalOption
	dumpValue
	placedOptionalValue
	attachedOptionalValue
)

var longOptions = map[string]optionArity{
	"--backtrace-limit":              requiredValue,
	"--crash-report":                 requiredValue,
	"--copyright":                    terminalOption,
	"--debug":                        noValue,
	"--disable":                      requiredValue,
	"--dump":                         dumpValue,
	"--enable":                       requiredValue,
	"--encoding":                     requiredValue,
	"--external-encoding":            requiredValue,
	"--help":                         terminalOption,
	"--internal-encoding":            requiredValue,
	"--jit":                          noValue,
	"--jit-debug":                    noValue,
	"--jit-max-cache":                noValue,
	"--jit-min-calls":                noValue,
	"--jit-save-temps":               noValue,
	"--jit-verbose":                  noValue,
	"--jit-wait":                     noValue,
	"--jit-warnings":                 noValue,
	"--mjit":                         noValue,
	"--mjit-debug":                   noValue,
	"--mjit-max-cache":               noValue,
	"--mjit-min-calls":               noValue,
	"--mjit-save-temps":              noValue,
	"--mjit-verbose":                 noValue,
	"--mjit-wait":                    noValue,
	"--mjit-warnings":                noValue,
	"--parser":                       requiredValue,
	"--rjit":                         noValue,
	"--rjit-call-threshold":          noValue,
	"--rjit-disable":                 noValue,
	"--rjit-dump-disasm":             noValue,
	"--rjit-exec-mem-size":           noValue,
	"--rjit-stats":                   noValue,
	"--rjit-trace":                   noValue,
	"--rjit-trace-exits":             noValue,
	"--source-encoding":              requiredValue,
	"--verbose":                      noValue,
	"--version":                      terminalOption,
	"--yjit":                         noValue,
	"--yjit-call-threshold":          noValue,
	"--yjit-code-gc":                 noValue,
	"--yjit-cold-threshold":          noValue,
	"--yjit-disable":                 noValue,
	"--yjit-exec-mem-size":           noValue,
	"--yjit-greedy-versioning":       noValue,
	"--yjit-log":                     noValue,
	"--yjit-max-versions":            noValue,
	"--yjit-mem-size":                noValue,
	"--yjit-perf":                    noValue,
	"--yjit-stats":                   noValue,
	"--yjit-trace-exits":             noValue,
	"--yjit-trace-exits-sample-rate": noValue,
	"--yydebug":                      noValue,
	"--zjit":                         noValue,
	"--zjit-call-threshold":          noValue,
	"--zjit-disable":                 noValue,
	"--zjit-log-compiled-iseqs":      noValue,
	"--zjit-mem-size":                noValue,
	"--zjit-num-profiles":            noValue,
	"--zjit-perf":                    noValue,
	"--zjit-stats":                   noValue,
	"--zjit-stats-quiet":             noValue,
	"--zjit-trace-exits":             noValue,
	"--zjit-trace-exits-sample-rate": noValue,
}

const (
	launcherNoValue               = noValue
	launcherRequiredValue         = requiredValue
	launcherPlacedOptionalValue   = placedOptionalValue
	launcherAttachedOptionalValue = attachedOptionalValue
)

var rackupOptions = map[string]optionArity{
	"-?":                  launcherNoValue,
	"-D":                  launcherNoValue,
	"-E":                  launcherRequiredValue,
	"-I":                  launcherRequiredValue,
	"-O":                  launcherRequiredValue,
	"-P":                  launcherRequiredValue,
	"-b":                  launcherRequiredValue,
	"-d":                  launcherNoValue,
	"-e":                  launcherRequiredValue,
	"-h":                  launcherNoValue,
	"-o":                  launcherRequiredValue,
	"-p":                  launcherRequiredValue,
	"-q":                  launcherNoValue,
	"-r":                  launcherRequiredValue,
	"-s":                  launcherRequiredValue,
	"-w":                  launcherNoValue,
	"--builder":           launcherRequiredValue,
	"--daemonize":         launcherNoValue,
	"--daemonize-noclose": launcherNoValue,
	"--debug":             launcherNoValue,
	"--env":               launcherRequiredValue,
	"--eval":              launcherRequiredValue,
	"--heap":              launcherRequiredValue,
	"--help":              launcherNoValue,
	"--host":              launcherRequiredValue,
	"--include":           launcherRequiredValue,
	"--option":            launcherRequiredValue,
	"--pid":               launcherRequiredValue,
	"--port":              launcherRequiredValue,
	"--profile":           launcherRequiredValue,
	"--profile-mode":      launcherRequiredValue,
	"--quiet":             launcherNoValue,
	"--require":           launcherRequiredValue,
	"--server":            launcherRequiredValue,
	"--version":           launcherNoValue,
	"--warn":              launcherNoValue,
}

var pumaOptions = map[string]optionArity{
	"-C":                           launcherRequiredValue,
	"-I":                           launcherRequiredValue,
	"-R":                           launcherRequiredValue,
	"-S":                           launcherRequiredValue,
	"-V":                           launcherNoValue,
	"-b":                           launcherRequiredValue,
	"-e":                           launcherRequiredValue,
	"-f":                           launcherAttachedOptionalValue,
	"-h":                           launcherNoValue,
	"-p":                           launcherRequiredValue,
	"-q":                           launcherNoValue,
	"-s":                           launcherNoValue,
	"-t":                           launcherRequiredValue,
	"-v":                           launcherNoValue,
	"-w":                           launcherRequiredValue,
	"--bind":                       launcherRequiredValue,
	"--bind-to-activated-sockets":  launcherPlacedOptionalValue,
	"--config":                     launcherRequiredValue,
	"--control-token":              launcherRequiredValue,
	"--control-url":                launcherRequiredValue,
	"--debug":                      launcherNoValue,
	"--dir":                        launcherRequiredValue,
	"--early-hints":                launcherNoValue,
	"--environment":                launcherRequiredValue,
	"--extra-runtime-dependencies": launcherRequiredValue,
	"--fork-worker":                launcherAttachedOptionalValue,
	"--help":                       launcherNoValue,
	"--idle-timeout":               launcherRequiredValue,
	"--include":                    launcherRequiredValue,
	"--log-requests":               launcherNoValue,
	"--no-config":                  launcherNoValue,
	"--no-redirect-append":         launcherNoValue,
	"--pidfile":                    launcherRequiredValue,
	"--plugin":                     launcherRequiredValue,
	"--port":                       launcherRequiredValue,
	"--preload":                    launcherNoValue,
	"--prune-bundler":              launcherNoValue,
	"--quiet":                      launcherNoValue,
	"--redirect-append":            launcherNoValue,
	"--redirect-stderr":            launcherRequiredValue,
	"--redirect-stdout":            launcherRequiredValue,
	"--restart-cmd":                launcherRequiredValue,
	"--silent":                     launcherNoValue,
	"--state":                      launcherRequiredValue,
	"--tag":                        launcherRequiredValue,
	"--threads":                    launcherRequiredValue,
	"--version":                    launcherNoValue,
	"--workers":                    launcherRequiredValue,
}

var unicornOptions = map[string]optionArity{
	"-D":                      launcherNoValue,
	"-E":                      launcherRequiredValue,
	"-I":                      launcherRequiredValue,
	"-N":                      launcherNoValue,
	"-P":                      launcherRequiredValue,
	"-c":                      launcherRequiredValue,
	"-d":                      launcherNoValue,
	"-e":                      launcherRequiredValue,
	"-h":                      launcherNoValue,
	"-l":                      launcherRequiredValue,
	"-o":                      launcherRequiredValue,
	"-p":                      launcherRequiredValue,
	"-r":                      launcherRequiredValue,
	"-s":                      launcherRequiredValue,
	"-v":                      launcherNoValue,
	"-w":                      launcherNoValue,
	"--config-file":           launcherRequiredValue,
	"--daemonize":             launcherNoValue,
	"--debug":                 launcherNoValue,
	"--env":                   launcherRequiredValue,
	"--eval":                  launcherRequiredValue,
	"--help":                  launcherNoValue,
	"--host":                  launcherRequiredValue,
	"--include":               launcherRequiredValue,
	"--listen":                launcherRequiredValue,
	"--no-default-middleware": launcherNoValue,
	"--pid":                   launcherRequiredValue,
	"--port":                  launcherRequiredValue,
	"--require":               launcherRequiredValue,
	"--server":                launcherRequiredValue,
	"--version":               launcherNoValue,
	"--warn":                  launcherNoValue,
}

// RubyLaunch contains application paths parsed from a Ruby command line.
type RubyLaunch struct {
	EntryPoint  string
	ProjectPath string

	projectPathAuthoritative bool
}

// ParseRubyLaunch finds application paths in a Ruby command line.
func ParseRubyLaunch(command string, args []string) RubyLaunch {
	if path, ok := strings.CutPrefix(command, "Passenger RubyApp: "); ok {
		path = strings.TrimSpace(path)
		if path != "" {
			return RubyLaunch{ProjectPath: path, projectPathAuthoritative: true}
		}
		return RubyLaunch{}
	}

	base := filepath.Base(command)
	if !rubyCommand.MatchString(base) {
		// we don't support these for now.
		if base == "jruby" || base == "truffleruby" {
			return RubyLaunch{}
		}

		if _, tool := rubyTooling[base]; tool {
			return parseToolLaunch(base, command, args)
		}

		if isCommandPath(command) {
			return RubyLaunch{EntryPoint: command}
		}

		return RubyLaunch{}
	}

	if len(args) == 0 {
		return RubyLaunch{}
	}
	return parseRubyArgs(args)
}

func isCommandPath(command string) bool {
	if strings.Contains(command, "://") {
		return false
	}

	if strings.ContainsFunc(command, unicode.IsSpace) {
		return false
	}

	return strings.Contains(command, string(filepath.Separator)) || strings.HasSuffix(command, ".rb")
}

func parseToolLaunch(tool, command string, args []string) RubyLaunch {
	launch := RubyLaunch{}

	if strings.Contains(command, string(filepath.Separator)) {
		launch.ProjectPath = command
	}

	switch tool {
	case "bundle", "bundler":
		if len(args) > 1 && args[0] == "exec" {
			return ParseRubyLaunch(args[1], args[2:])
		}
	case "rackup":
		parsed := parseLauncherArguments(args, rackupOptions, "", "")
		if parsed.positionalsKnown && filepath.Base(parsed.lastPositional) == "config.ru" {
			launch.ProjectPath = parsed.lastPositional
			launch.projectPathAuthoritative = true
		}
	case "puma":
		parsed := parseLauncherArguments(args, pumaOptions, "-C", "--config")
		if parsed.configPath != "" {
			launch.ProjectPath = parsed.configPath
		}
		if parsed.positionalsKnown && filepath.Base(parsed.firstPositional) == "config.ru" {
			launch.ProjectPath = parsed.firstPositional
			launch.projectPathAuthoritative = true
		}
	case "unicorn", "unicorn_rails":
		parsed := parseLauncherArguments(args, unicornOptions, "-c", "--config-file")
		if parsed.configPath != "" {
			launch.ProjectPath = parsed.configPath
		}
		if parsed.positionalsKnown && filepath.Base(parsed.firstPositional) == "config.ru" {
			launch.ProjectPath = parsed.firstPositional
			launch.projectPathAuthoritative = true
		}
	case "sidekiq":
		if path := lastLauncherOption(args, "-r", "--require"); path != "" {
			return RubyLaunch{EntryPoint: path}
		}
	case "passenger":
		if len(args) > 1 && args[0] == "start" && !strings.HasPrefix(args[1], "-") {
			launch.ProjectPath = args[1]
			launch.projectPathAuthoritative = true
		}
		for i := 0; i < len(args); i++ {
			name, value, attached := strings.Cut(args[i], "=")
			if name == "--app-start-command" {
				if !attached {
					i++
				}
				continue
			}

			if name != "--rackup" && name != "--startup-file" {
				continue
			}

			if !attached {
				i++
				if i >= len(args) {
					break
				}
				value = args[i]
			}

			if value != "" {
				launch.ProjectPath = value
				launch.projectPathAuthoritative = true
			}
		}
	}
	return launch
}

func lastLauncherOption(args []string, short, long string) string {
	var value string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			break
		}

		switch {
		case arg == short || arg == long:
			i++
			if i < len(args) {
				value = args[i]
			}
		case strings.HasPrefix(arg, long+"="):
			value = strings.TrimPrefix(arg, long+"=")
		case strings.HasPrefix(arg, short) && len(arg) > len(short):
			value = strings.TrimPrefix(arg, short)
		}
	}
	return value
}

type launcherArguments struct {
	firstPositional  string
	lastPositional   string
	configPath       string
	positionalsKnown bool
}

func parseLauncherArguments(
	args []string,
	options map[string]optionArity,
	configShort string,
	configLong string,
) launcherArguments {
	parsed := launcherArguments{positionalsKnown: true}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			for _, positional := range args[i+1:] {
				parsed.addPositional(positional)
			}
			return parsed
		}

		if arg == "-" || !strings.HasPrefix(arg, "-") {
			parsed.addPositional(arg)
			continue
		}

		if strings.HasPrefix(arg, "--") {
			name, value, attached := strings.Cut(arg, "=")
			arity, ok := options[name]
			if !ok || attached && arity == launcherNoValue {
				logUnknownOption(arg)
				parsed.positionalsKnown = false
				return parsed
			}
			value, i, ok = consumeOptionValue(args, i, value, attached, arity)
			if !ok {
				parsed.positionalsKnown = false
				return parsed
			}
			if name == configLong && value != "" {
				parsed.configPath = value
			}
			continue
		}

		for offset := 1; offset < len(arg); offset++ {
			name := "-" + arg[offset:offset+1]
			arity, ok := options[name]

			if !ok {
				logUnknownOption(name)
				parsed.positionalsKnown = false
				return parsed
			}

			if arity == launcherNoValue {
				continue
			}

			value := arg[offset+1:]
			var valueOK bool
			value, i, valueOK = consumeOptionValue(args, i, value, value != "", arity)
			if !valueOK {
				parsed.positionalsKnown = false
				return parsed
			}

			if name == configShort && value != "" {
				parsed.configPath = value
			}

			break
		}
	}
	return parsed
}

func (args *launcherArguments) addPositional(value string) {
	if args.firstPositional == "" {
		args.firstPositional = value
	}

	args.lastPositional = value
}

func parseRubyArgs(args []string) RubyLaunch {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			if i+1 < len(args) && args[i+1] != "-" {
				return launchFromProgram(args[i+1], args[i+2:])
			}
			return RubyLaunch{}
		}

		if arg == "-" {
			return RubyLaunch{}
		}

		if strings.HasPrefix(arg, "--") {
			name, value, attached := splitLongOption(arg)
			arity, ok := longOptions[name]
			if !ok {
				logUnknownOption(arg)
				return RubyLaunch{}
			}

			if attached && (arity == terminalOption || arity == noValue && !allowsAttachedLongValue(name)) {
				logUnknownOption(arg)
				return RubyLaunch{}
			}

			if arity == terminalOption {
				return RubyLaunch{}
			}

			value, i, ok = consumeOptionValue(args, i, value, attached, arity)
			if !ok {
				return RubyLaunch{}
			}

			if arity == dumpValue {
				terminal, known := classifyDumpValue(value)
				if terminal {
					return RubyLaunch{}
				}
				if !known {
					slog.Debug("unknown dump target while discovering Ruby entrypoint", "option", "--dump")
				}
			}

			continue
		}

		if strings.HasPrefix(arg, "-") {
			consumeNext, terminal, valid := scanShortOption(arg)
			if !valid {
				logUnknownOption(arg)
				return RubyLaunch{}
			}

			if terminal {
				return RubyLaunch{}
			}

			if consumeNext {
				i++
			}

			continue
		}
		return launchFromProgram(arg, args[i+1:])
	}
	return RubyLaunch{}
}

func consumeOptionValue(
	args []string,
	index int,
	value string,
	attached bool,
	arity optionArity,
) (string, int, bool) {
	if attached {
		return value, index, true
	}

	switch arity {
	case requiredValue, dumpValue:
		index++
		if index >= len(args) {
			return "", index, false
		}
		return args[index], index, true
	case placedOptionalValue:
		if index+1 < len(args) && !strings.HasPrefix(args[index+1], "-") {
			index++
			return args[index], index, true
		}
	}

	return "", index, true
}

func allowsAttachedLongValue(name string) bool {
	return name == "--debug" ||
		strings.HasPrefix(name, "--jit") ||
		strings.HasPrefix(name, "--mjit") ||
		strings.HasPrefix(name, "--rjit") ||
		strings.HasPrefix(name, "--yjit") ||
		strings.HasPrefix(name, "--zjit")
}

func launchFromProgram(program string, args []string) RubyLaunch {
	base := filepath.Base(program)
	if base == "config.ru" {
		return RubyLaunch{ProjectPath: program, projectPathAuthoritative: true}
	}

	if _, tool := rubyTooling[base]; tool {
		return parseToolLaunch(base, program, args)
	}

	return RubyLaunch{EntryPoint: program}
}

func splitLongOption(option string) (string, string, bool) {
	if name, value, attached := strings.Cut(option, "="); attached {
		return name, value, true
	}

	for _, name := range []string{"--crash-report", "--debug", "--disable", "--enable"} {
		if value, attached := strings.CutPrefix(option, name+"-"); attached {
			return name, value, true
		}
	}
	return option, "", false
}

func scanShortOption(option string) (bool, bool, bool) {
	short := option[1:]
	for i := 0; i < len(short); {
		switch short[i] {
		case 'a', 'c', 'd', 'l', 'n', 'p', 's', 'S', 'U', 'v', 'w', 'y':
			i++
		case 'h', 'e':
			return false, true, true
		case 'C', 'E', 'I', 'X', 'r':
			return i+1 == len(short), false, true
		case 'F', 'i', 'x':
			return false, false, true
		case '0':
			i++
			for digits := 0; digits < 3 && i < len(short) && short[i] >= '0' && short[i] <= '7'; digits++ {
				i++
			}
		case 'K':
			i++
			if i < len(short) {
				i++
			}
		case 'W':
			i++
			if i < len(short) && short[i] == ':' {
				return false, false, true
			}
			if i < len(short) && short[i] >= '0' && short[i] <= '7' {
				i++
			}
		default:
			return false, false, false
		}
	}
	return false, false, true
}

func logUnknownOption(option string) {
	slog.Debug("can't reliably discover Ruby entrypoint after unknown option", "option", sanitizedOptionName(option))
}

func sanitizedOptionName(option string) string {
	if name, _, ok := strings.Cut(option, "="); ok {
		return name
	}

	if strings.HasPrefix(option, "-") && !strings.HasPrefix(option, "--") && len(option) > 2 {
		return option[:2]
	}

	return option
}

func classifyDumpValue(value string) (bool, bool) {
	targets := []struct {
		name     string
		terminal bool
	}{
		{name: "version", terminal: true},
		{name: "copyright", terminal: true},
		{name: "usage", terminal: true},
		{name: "help", terminal: true},
		{name: "yydebug"},
		{name: "syntax"},
		{name: "parsetree"},
		{name: "parsetree_with_comment"},
		{name: "insns"},
		{name: "insns_without_opt"},
	}

	items := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || unicode.IsSpace(r)
	})

	known := len(items) != 0
	terminal := false
	for _, item := range items {
		item = strings.ToLower(item)
		matched := false
		for _, target := range targets {
			if strings.HasPrefix(target.name, item) {
				matched = true
				terminal = terminal || target.terminal
			}
		}
		known = known && matched
	}

	return terminal, known
}
