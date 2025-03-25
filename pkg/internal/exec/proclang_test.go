package exec

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/grafana/beyla/v2/pkg/internal/svc"
)

func TestModuleDetection(t *testing.T) {
	assert.Equal(t, svc.InstrumentableDotnet, instrumentableFromModuleMap("/usr/lib\\//libcoreclr.so/dklksjdf"))
	assert.Equal(t, svc.InstrumentableDotnet, instrumentableFromModuleMap("libcoreclr.so"))
	assert.Equal(t, svc.InstrumentableGeneric, instrumentableFromModuleMap("/usr/lib\\//clr.so/dklksjdf"))
	assert.Equal(t, svc.InstrumentableJava, instrumentableFromModuleMap("/usr/lib\\//libjvm.so/dklksjdf"))
	assert.Equal(t, svc.InstrumentableJava, instrumentableFromModuleMap("libjvm.so"))
	assert.Equal(t, svc.InstrumentableGeneric, instrumentableFromModuleMap("/usr/lib\\//libj9vm25.so/dklksjdf")) // OpenJDK only for now
	assert.Equal(t, svc.InstrumentableNodejs, instrumentableFromModuleMap("/usr/bin/node"))
	assert.Equal(t, svc.InstrumentableNodejs, instrumentableFromModuleMap("node"))
	assert.Equal(t, svc.InstrumentableRuby, instrumentableFromModuleMap("/usr/bin/ruby"))
	assert.Equal(t, svc.InstrumentableRuby, instrumentableFromModuleMap("/usr/bin/ruby3"))
	assert.Equal(t, svc.InstrumentableRuby, instrumentableFromModuleMap("/usr/bin/ruby3.0"))
	assert.Equal(t, svc.InstrumentableRuby, instrumentableFromModuleMap("ruby"))
	assert.Equal(t, svc.InstrumentableRuby, instrumentableFromModuleMap("ruby3"))
	assert.Equal(t, svc.InstrumentableRuby, instrumentableFromModuleMap("ruby3.1.2"))
	assert.Equal(t, svc.InstrumentablePython, instrumentableFromModuleMap("/usr/bin/python3.18"))
	assert.Equal(t, svc.InstrumentablePython, instrumentableFromModuleMap("python"))
	assert.Equal(t, svc.InstrumentablePython, instrumentableFromModuleMap("/usr/bin/python"))
	assert.Equal(t, svc.InstrumentablePython, instrumentableFromModuleMap("python3"))

	assert.Equal(t, svc.InstrumentableGeneric, instrumentableFromModuleMap("/usr/lib/rubybutnotreallyruby"))
	assert.Equal(t, svc.InstrumentableGeneric, instrumentableFromModuleMap("/usr/lib/pythonbutnotreallypython"))
}

func TestSymbolDetection(t *testing.T) {
	assert.Equal(t, svc.InstrumentableRust, instrumentableFromSymbolName("rust_panic"))
	assert.Equal(t, svc.InstrumentableRust, instrumentableFromSymbolName("ZN387639_rust_panic_.NAME"))
	assert.Equal(t, svc.InstrumentableJava, instrumentableFromSymbolName("JVM_2398743897"))
	assert.Equal(t, svc.InstrumentableJava, instrumentableFromSymbolName("graal_testing"))
	assert.Equal(t, svc.InstrumentableGeneric, instrumentableFromSymbolName("graal"))
	assert.Equal(t, svc.InstrumentableGeneric, instrumentableFromSymbolName("rust"))
}

func TestEnvironDetection(t *testing.T) {
	assert.Equal(t, svc.InstrumentableDotnet, instrumentableFromEnviron("ASPNETCORE_HTTP_PORTS=8080"))
	assert.Equal(t, svc.InstrumentableDotnet, instrumentableFromEnviron("DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=true"))
	assert.Equal(t, svc.InstrumentableGeneric, instrumentableFromEnviron("SOME_ENV_VAR=123"))
	assert.Equal(t, svc.InstrumentableGeneric, instrumentableFromEnviron("DOT=1"))
}

func TestPathDetection(t *testing.T) {
	assert.Equal(t, svc.InstrumentablePHP, instrumentableFromPath("php"))
	assert.Equal(t, svc.InstrumentableGeneric, instrumentableFromPath("python"))
}
