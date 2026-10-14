// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejstools // import "go.opentelemetry.io/obi/pkg/internal/nodejstools"

import (
	"log/slog"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
)

// NodeLaunch contains the application entrypoint parsed from a Node.js command line.
type NodeLaunch struct {
	EntryPoint string
}

var optionsWithValues = map[string]struct{}{
	"-C":                                  {},
	"-r":                                  {},
	"--allow-fs-read":                     {},
	"--allow-fs-write":                    {},
	"--build-sea":                         {},
	"--build-snapshot-config":             {},
	"--conditions":                        {},
	"--cpu-prof-dir":                      {},
	"--cpu-prof-interval":                 {},
	"--cpu-prof-name":                     {},
	"--debug-port":                        {},
	"--diagnostic-dir":                    {},
	"--disable-proto":                     {},
	"--disable-warning":                   {},
	"--dns-result-order":                  {},
	"--env-file":                          {},
	"--env-file-if-exists":                {},
	"--experimental-config-file":          {},
	"--experimental-default-type":         {},
	"--experimental-loader":               {},
	"--experimental-package-map":          {},
	"--experimental-policy":               {},
	"--experimental-sea-config":           {},
	"--experimental-specifier-resolution": {},
	"--experimental-test-isolation":       {},
	"--experimental-test-tag-filter":      {},
	"--heap-prof-dir":                     {},
	"--heap-prof-interval":                {},
	"--heap-prof-name":                    {},
	"--heapsnapshot-near-heap-limit":      {},
	"--heapsnapshot-signal":               {},
	"--http-parser":                       {},
	"--icu-data-dir":                      {},
	"--import":                            {},
	"--input-type":                        {},
	"--inspect-port":                      {},
	"--inspect-publish-uid":               {},
	"--loader":                            {},
	"--localstorage-file":                 {},
	"--max-http-header-size":              {},
	"--max-old-space-size-percentage":     {},
	"--network-family-autoselection-attempt-timeout": {},
	"--openssl-config":            {},
	"--policy-integrity":          {},
	"--redirect-warnings":         {},
	"--report-dir":                {},
	"--report-directory":          {},
	"--report-filename":           {},
	"--report-signal":             {},
	"--require":                   {},
	"--secure-heap":               {},
	"--secure-heap-min":           {},
	"--security-revert":           {},
	"--snapshot-blob":             {},
	"--test-concurrency":          {},
	"--test-coverage-branches":    {},
	"--test-coverage-exclude":     {},
	"--test-coverage-functions":   {},
	"--test-coverage-include":     {},
	"--test-coverage-lines":       {},
	"--test-global-setup":         {},
	"--test-isolation":            {},
	"--test-name-pattern":         {},
	"--test-random-seed":          {},
	"--test-reporter":             {},
	"--test-reporter-destination": {},
	"--test-rerun-failures":       {},
	"--test-shard":                {},
	"--test-skip-pattern":         {},
	"--test-timeout":              {},
	"--title":                     {},
	"--tls-cipher-list":           {},
	"--tls-keylog":                {},
	"--trace-event-categories":    {},
	"--trace-event-file-pattern":  {},
	"--trace-require-module":      {},
	"--unhandled-rejections":      {},
	"--use-largepages":            {},
	"--v8-pool-size":              {},
	"--watch-kill-signal":         {},
	"--watch-path":                {},
}

var validOptions = map[string]struct{}{
	"-":                             {},
	"--":                            {},
	"--abort-on-uncaught-exception": {},
	"--allow-addons":                {},
	"--allow-child-process":         {},
	"--allow-ffi":                   {},
	"--allow-fs-read":               {},
	"--allow-fs-write":              {},
	"--allow-inspector":             {},
	"--allow-net":                   {},
	"--allow-openssl-store":         {},
	"--allow-wasi":                  {},
	"--allow-worker":                {},
	"--build-sea":                   {},
	"--build-snapshot":              {},
	"--build-snapshot-config":       {},
	"--check":                       {},
	"--completion-bash":             {},
	"--conditions":                  {},
	"--cpu-prof":                    {},
	"--cpu-prof-dir":                {},
	"--cpu-prof-interval":           {},
	"--cpu-prof-name":               {},
	"--debug-port":                  {},
	"--diagnostic-dir":              {},
	"--disable-proto":               {},
	"--disable-sigusr1":             {},
	"--disable-warning":             {},
	"--disable-wasm-trap-handler":   {},
	"--disallow-code-generation-from-strings":        {},
	"--dns-result-order":                             {},
	"--enable-etw-stack-walking":                     {},
	"--enable-fips":                                  {},
	"--enable-network-family-autoselection":          {},
	"--enable-source-maps":                           {},
	"--entry-url":                                    {},
	"--env-file":                                     {},
	"--env-file-if-exists":                           {},
	"--eval":                                         {},
	"--experimental-abortcontroller":                 {},
	"--experimental-addon-modules":                   {},
	"--experimental-config-file":                     {},
	"--experimental-default-config-file":             {},
	"--experimental-detect-module":                   {},
	"--experimental-eventsource":                     {},
	"--experimental-ffi":                             {},
	"--experimental-import-meta-resolve":             {},
	"--experimental-import-text":                     {},
	"--experimental-inspector-network-resource":      {},
	"--experimental-json-modules":                    {},
	"--experimental-loader":                          {},
	"--experimental-modules":                         {},
	"--experimental-network-inspection":              {},
	"--experimental-package-map":                     {},
	"--experimental-print-required-tla":              {},
	"--experimental-quic":                            {},
	"--experimental-require-module":                  {},
	"--experimental-sea-config":                      {},
	"--experimental-shadow-realm":                    {},
	"--experimental-specifier-resolution":            {},
	"--experimental-storage-inspection":              {},
	"--experimental-stream-iter":                     {},
	"--experimental-test-coverage":                   {},
	"--experimental-test-isolation":                  {},
	"--experimental-test-module-mocks":               {},
	"--experimental-test-tag-filter":                 {},
	"--experimental-top-level-await":                 {},
	"--experimental-vfs":                             {},
	"--experimental-vm-modules":                      {},
	"--experimental-wasi-unstable-preview1":          {},
	"--experimental-worker-inspection":               {},
	"--expose-gc":                                    {},
	"--force-context-aware":                          {},
	"--force-fips":                                   {},
	"--force-node-api-uncaught-exceptions-policy":    {},
	"--frozen-intrinsics":                            {},
	"--harmony-shadow-realm":                         {},
	"--heap-prof":                                    {},
	"--heap-prof-dir":                                {},
	"--heap-prof-interval":                           {},
	"--heap-prof-name":                               {},
	"--heap-snapshot-on-oom":                         {},
	"--heapsnapshot-near-heap-limit":                 {},
	"--heapsnapshot-signal":                          {},
	"--help":                                         {},
	"--http-parser":                                  {},
	"--icu-data-dir":                                 {},
	"--import":                                       {},
	"--input-type":                                   {},
	"--insecure-http-parser":                         {},
	"--inspect":                                      {},
	"--inspect-brk":                                  {},
	"--inspect-port":                                 {},
	"--inspect-publish-uid":                          {},
	"--inspect-wait":                                 {},
	"--interactive":                                  {},
	"--interpreted-frames-native-stack":              {},
	"--jitless":                                      {},
	"--localstorage-file":                            {},
	"--loader":                                       {},
	"--max-heap-size":                                {},
	"--max-http-header-size":                         {},
	"--max-old-space-size":                           {},
	"--max-old-space-size-percentage":                {},
	"--max-semi-space-size":                          {},
	"--network-family-autoselection-attempt-timeout": {},
	"--no-addons":                                    {},
	"--no-async-context-frame":                       {},
	"--no-deprecation":                               {},
	"--no-experimental-detect-module":                {},
	"--no-experimental-global-navigator":             {},
	"--no-experimental-repl-await":                   {},
	"--no-experimental-require-module":               {},
	"--no-experimental-sqlite":                       {},
	"--no-experimental-strip-types":                  {},
	"--no-experimental-websocket":                    {},
	"--no-experimental-webstorage":                   {},
	"--no-extra-info-on-fatal-exception":             {},
	"--no-force-async-hooks-checks":                  {},
	"--no-global-search-paths":                       {},
	"--no-network-family-autoselection":              {},
	"--no-require-module":                            {},
	"--no-strip-types":                               {},
	"--no-warnings":                                  {},
	"--no-webstorage":                                {},
	"--node-memory-debug":                            {},
	"--openssl-config":                               {},
	"--openssl-legacy-provider":                      {},
	"--openssl-shared-config":                        {},
	"--pending-deprecation":                          {},
	"--perf-basic-prof":                              {},
	"--perf-basic-prof-only-functions":               {},
	"--perf-prof":                                    {},
	"--perf-prof-unwinding-info":                     {},
	"--permission":                                   {},
	"--permission-audit":                             {},
	"--preserve-symlinks":                            {},
	"--preserve-symlinks-main":                       {},
	"--print":                                        {},
	"--prof":                                         {},
	"--prof-process":                                 {},
	"--redirect-warnings":                            {},
	"--report-compact":                               {},
	"--report-dir":                                   {},
	"--report-directory":                             {},
	"--report-exclude-env":                           {},
	"--report-exclude-network":                       {},
	"--report-filename":                              {},
	"--report-on-fatalerror":                         {},
	"--report-on-signal":                             {},
	"--report-signal":                                {},
	"--report-uncaught-exception":                    {},
	"--require":                                      {},
	"--require-module":                               {},
	"--run":                                          {},
	"--secure-heap":                                  {},
	"--secure-heap-min":                              {},
	"--security-revert":                              {},
	"--snapshot-blob":                                {},
	"--stack-trace-limit":                            {},
	"--test":                                         {},
	"--test-concurrency":                             {},
	"--test-coverage-branches":                       {},
	"--test-coverage-exclude":                        {},
	"--test-coverage-functions":                      {},
	"--test-coverage-include":                        {},
	"--test-coverage-include-all":                    {},
	"--test-coverage-lines":                          {},
	"--test-force-exit":                              {},
	"--test-global-setup":                            {},
	"--test-isolation":                               {},
	"--test-name-pattern":                            {},
	"--test-only":                                    {},
	"--test-random-seed":                             {},
	"--test-randomize":                               {},
	"--test-reporter":                                {},
	"--test-reporter-destination":                    {},
	"--test-rerun-failures":                          {},
	"--test-shard":                                   {},
	"--test-skip-pattern":                            {},
	"--test-timeout":                                 {},
	"--test-update-snapshots":                        {},
	"--throw-deprecation":                            {},
	"--title":                                        {},
	"--tls-cipher-list":                              {},
	"--tls-keylog":                                   {},
	"--tls-max-v1.2":                                 {},
	"--tls-max-v1.3":                                 {},
	"--tls-min-v1.0":                                 {},
	"--tls-min-v1.1":                                 {},
	"--tls-min-v1.2":                                 {},
	"--tls-min-v1.3":                                 {},
	"--trace-deprecation":                            {},
	"--trace-env":                                    {},
	"--trace-env-js-stack":                           {},
	"--trace-env-native-stack":                       {},
	"--trace-event-categories":                       {},
	"--trace-event-file-pattern":                     {},
	"--trace-events-enabled":                         {},
	"--trace-exit":                                   {},
	"--trace-require-module":                         {},
	"--trace-sigint":                                 {},
	"--trace-sync-io":                                {},
	"--trace-tls":                                    {},
	"--trace-uncaught":                               {},
	"--trace-warnings":                               {},
	"--track-heap-objects":                           {},
	"--unhandled-rejections":                         {},
	"--use-bundled-ca":                               {},
	"--use-env-proxy":                                {},
	"--use-largepages":                               {},
	"--use-openssl-ca":                               {},
	"--use-system-ca":                                {},
	"--v8-options":                                   {},
	"--v8-pool-size":                                 {},
	"--version":                                      {},
	"--watch":                                        {},
	"--watch-kill-signal":                            {},
	"--watch-path":                                   {},
	"--watch-preserve-output":                        {},
	"--zero-fill-buffers":                            {},
	"-C":                                             {},
	"-c":                                             {},
	"-e":                                             {},
	"-h":                                             {},
	"-i":                                             {},
	"-p":                                             {},
	"-r":                                             {},
	"-v":                                             {},
}

var historicalOptions = map[string]struct{}{
	"--experimental-async-context-frame":   {},
	"--experimental-default-type":          {},
	"--experimental-fetch":                 {},
	"--experimental-global-customevent":    {},
	"--experimental-global-webcrypto":      {},
	"--experimental-network-imports":       {},
	"--experimental-permission":            {},
	"--experimental-policy":                {},
	"--experimental-transform-types":       {},
	"--experimental-wasm-modules":          {},
	"--experimental-websocket":             {},
	"--experimental-webstorage":            {},
	"--huge-max-old-generation-size":       {},
	"--napi-modules":                       {},
	"--no-experimental-fetch":              {},
	"--no-experimental-global-customevent": {},
	"--no-experimental-global-webcrypto":   {},
	"--policy-integrity":                   {},
	"--trace-atomics-wait":                 {},
}

// ParseNodeLaunch finds the application entrypoint in a Node.js command line.
func ParseNodeLaunch(args []string) NodeLaunch {
	inspect := false
	entryURL := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "" {
			continue
		}
		if arg == "--" {
			if i+1 < len(args) {
				return launchForEntryPoint(args[i+1], inspect, entryURL)
			}
			return NodeLaunch{}
		}
		if noFileLaunch(arg) || arg == "-" {
			return NodeLaunch{}
		}
		if arg == "--entry-url" {
			entryURL = true
			continue
		}
		if strings.HasPrefix(arg, "-") {
			name := optionName(arg)
			nextArgMayBeValue := i+1 < len(args) && !strings.HasPrefix(args[i+1], "-")
			if !validOption(arg) && nextArgMayBeValue {
				slog.Debug("can't reliably discover Node.js entrypoint after unknown option", "option", name)
				return NodeLaunch{}
			}
			if consumesNextArg(arg) {
				i++
			}
			continue
		}
		if !inspect && arg == "inspect" {
			inspect = true
			continue
		}
		return launchForEntryPoint(arg, inspect, entryURL)
	}

	return NodeLaunch{}
}

func noFileLaunch(arg string) bool {
	if arg == "-e" || arg == "-p" || arg == "-pe" ||
		arg == "--eval" || arg == "--print" || arg == "--run" {
		return true
	}
	return strings.HasPrefix(arg, "--eval=") ||
		strings.HasPrefix(arg, "--print=") ||
		strings.HasPrefix(arg, "--run=")
}

func validOption(arg string) bool {
	name := optionName(arg)
	if _, ok := validOptions[name]; ok {
		return true
	}
	if _, ok := historicalOptions[name]; ok {
		return true
	}
	return false
}

func consumesNextArg(arg string) bool {
	if strings.Contains(arg, "=") {
		return false
	}
	_, ok := optionsWithValues[optionName(arg)]
	return ok
}

func optionName(arg string) string {
	name, _, _ := strings.Cut(arg, "=")
	return strings.ReplaceAll(name, "_", "-")
}

func launchForEntryPoint(entryPoint string, inspect, entryURL bool) NodeLaunch {
	if inspect && isInspectorAddress(entryPoint) {
		return NodeLaunch{}
	}
	if entryURL {
		parsed, err := url.Parse(entryPoint)
		if err != nil || parsed.Scheme != "file" || parsed.Path == "" ||
			(parsed.Host != "" && parsed.Host != "localhost") {
			return NodeLaunch{}
		}
		entryPoint = filepath.FromSlash(parsed.Path)
	}
	return NodeLaunch{EntryPoint: entryPoint}
}

func isInspectorAddress(value string) bool {
	if port, err := strconv.Atoi(value); err == nil && port > 0 {
		return true
	}
	_, port, err := net.SplitHostPort(value)
	if err != nil {
		return false
	}
	portNumber, err := strconv.Atoi(port)
	return err == nil && portNumber > 0
}
