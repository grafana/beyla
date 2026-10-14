// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package procs // import "go.opentelemetry.io/obi/pkg/internal/procs"

import (
	"regexp"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
)

const nodeSymbolNamespace = "_ZN4node"

// nodeRuntimeSymbols are Node's own internals, which no other runtime carries.
//
// The public N-API surface is deliberately absent: Bun re-exports node::
// symbols such as MakeCallback, so matching those would identify it as Node.
// libuv's symbols are absent for the same reason: any runtime linking libuv
// has them, Bun included, so they say nothing about which runtime this is.
var nodeRuntimeSymbols = []string{
	"_ZN4node16NodeMainInstance",
	"_ZN4node11Environment",
	"_ZN4node5StartE",
}

var (
	rubyModule      = regexp.MustCompile(`^(.*/)?ruby[\d.]*$`)
	pythonModule    = regexp.MustCompile(`^(.*/)?python[\d.]*$`)
	libpythonModule = regexp.MustCompile(`libpython3[\d.]*\.so`)
	librubyModule   = regexp.MustCompile(`libruby-[\d.]*\.so`)
)

func instrumentableFromModuleMapSharedLib(moduleName string) svc.InstrumentableType {
	if strings.Contains(moduleName, "libcoreclr.so") {
		return svc.InstrumentableDotnet
	}
	if strings.Contains(moduleName, "libjvm.so") {
		return svc.InstrumentableJava
	}
	if libpythonModule.MatchString(moduleName) {
		return svc.InstrumentablePython
	}
	if librubyModule.MatchString(moduleName) {
		return svc.InstrumentableRuby
	}
	// Distribution packages link the runtime as a library and leave the
	// executable a launcher whose node:: symbols are all undefined imports.
	if strings.Contains(moduleName, "libnode.so") {
		return svc.InstrumentableNodejs
	}

	return svc.InstrumentableGeneric
}

func instrumentableFromModuleMap(moduleName string) svc.InstrumentableType {
	if strings.HasSuffix(moduleName, "/deno") || moduleName == "deno" {
		return svc.InstrumentableDeno
	}
	if rubyModule.MatchString(moduleName) {
		return svc.InstrumentableRuby
	}
	if pythonModule.MatchString(moduleName) {
		return svc.InstrumentablePython
	}

	return instrumentableFromModuleMapSharedLib(moduleName)
}

func instrumentableFromSymbolName(symbol string) svc.InstrumentableType {
	if strings.Contains(symbol, "rust_panic") {
		return svc.InstrumentableRust
	}
	if strings.HasPrefix(symbol, "JVM_") || strings.HasPrefix(symbol, "graal_") {
		return svc.InstrumentableJavaNative
	}
	if isNodeRuntimeSymbol(symbol) {
		return svc.InstrumentableNodejs
	}

	return svc.InstrumentableGeneric
}

func isNodeRuntimeSymbol(symbol string) bool {
	if !strings.HasPrefix(symbol, nodeSymbolNamespace) {
		return false
	}

	for _, runtimeSymbol := range nodeRuntimeSymbols {
		if strings.HasPrefix(symbol, runtimeSymbol) {
			return true
		}
	}

	return false
}

func instrumentableFromPath(path string) svc.InstrumentableType {
	if strings.Contains(path, "php") || strings.Contains(path, "php-fpm") {
		return svc.InstrumentablePHP
	}
	return svc.InstrumentableGeneric
}

func instrumentableLastResort(moduleName string) svc.InstrumentableType {
	if strings.Contains(moduleName, "libstdc++.so") || // GCC
		strings.Contains(moduleName, "libc++.so") { // Clang
		return svc.InstrumentableCPP
	}

	return svc.InstrumentableGeneric
}
