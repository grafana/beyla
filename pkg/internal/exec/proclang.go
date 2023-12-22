package exec

import (
	"strings"

	"github.com/grafana/beyla/pkg/internal/svc"
)

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
	if strings.HasSuffix(moduleName, "/ruby") || moduleName == "ruby" {
		return svc.InstrumentableRuby
	}
	if strings.Contains(moduleName, "/python") || moduleName == "python" || moduleName == "python3" {
		return svc.InstrumentablePython
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
