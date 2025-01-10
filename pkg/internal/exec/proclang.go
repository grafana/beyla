package exec

import (
	"regexp"
	"strings"

	"github.com/grafana/beyla/pkg/internal/svc"
)

var rubyModule = regexp.MustCompile(`^(.*/)?ruby[\d.]*$`)
var pythonModule = regexp.MustCompile(`^(.*/)?python[\d.]*$`)

func instrumentableFromModuleMap(moduleName string) svc.InstrumentableType {
	if strings.Contains(moduleName, "libcoreclr.so") {
		return svc.InstrumentableDotnet
	}
	if strings.Contains(moduleName, "libjvm.so") {
		return svc.InstrumentableJava
	}
	if strings.HasSuffix(moduleName, "/node") || moduleName == "node" {
		return svc.InstrumentableNodejs
	}
	if rubyModule.MatchString(moduleName) {
		return svc.InstrumentableRuby
	}
	if pythonModule.MatchString(moduleName) {
		return svc.InstrumentablePython
	}

	return svc.InstrumentableGeneric
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
		return svc.InstrumentableJava
	}

	return svc.InstrumentableGeneric
}

func instrumentableFromPath(path string) svc.InstrumentableType {
	if strings.Contains(path, "php") {
		return svc.InstrumentablePHP
	}
	return svc.InstrumentableGeneric
}
