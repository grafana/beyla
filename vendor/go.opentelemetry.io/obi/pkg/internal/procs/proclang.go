// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package procs // import "go.opentelemetry.io/obi/pkg/internal/procs"

import (
	"regexp"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
)

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

	return svc.InstrumentableGeneric
}

func instrumentableFromModuleMap(moduleName string) svc.InstrumentableType {
	if strings.HasSuffix(moduleName, "/node") || moduleName == "node" {
		return svc.InstrumentableNodejs
	}
	if rubyModule.MatchString(moduleName) {
		return svc.InstrumentableRuby
	}
	if pythonModule.MatchString(moduleName) {
		return svc.InstrumentablePython
	}

	return instrumentableFromModuleMapSharedLib(moduleName)
}

func instrumentableFromEnviron(environ string) svc.InstrumentableType {
	if strings.Contains(environ, "ASPNET") || strings.Contains(environ, "DOTNET") {
		return svc.InstrumentableDotnet
	}
	return svc.InstrumentableGeneric
}

func instrumentableFromSymbolName(symbol string) svc.InstrumentableType {
	if strings.Contains(symbol, "rust_panic") {
		return svc.InstrumentableRust
	}
	if strings.HasPrefix(symbol, "JVM_") || strings.HasPrefix(symbol, "graal_") {
		return svc.InstrumentableJavaNative
	}

	return svc.InstrumentableGeneric
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
