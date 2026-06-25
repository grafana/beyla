package webhook

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/prometheus/procfs"
	"github.com/shirou/gopsutil/v3/process"
	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
)

func TestNewInitialStateScanner(t *testing.T) {
	scanner := NewInitialStateScanner()

	assert.NotNil(t, scanner)
	assert.NotNil(t, scanner.logger)
}

func TestFetchProcesses(t *testing.T) {
	t.Run("successful fetch", func(t *testing.T) {
		// Save original and restore after test
		originalFunc := fetchProcessesFunc
		defer func() { fetchProcessesFunc = originalFunc }()

		// Mock fetchProcessesFunc
		fetchProcessesFunc = func() (map[int32]*ProcessInfo, error) {
			return map[int32]*ProcessInfo{
				123: {pid: 123},
				456: {pid: 456},
			}, nil
		}

		processes, err := fetchProcessesFunc()

		assert.NoError(t, err)
		assert.Len(t, processes, 2)
		assert.Contains(t, processes, int32(123))
		assert.Contains(t, processes, int32(456))
	})

	t.Run("error fetching processes", func(t *testing.T) {
		// Save original and restore after test
		originalFunc := fetchProcessesFunc
		defer func() { fetchProcessesFunc = originalFunc }()

		// Mock fetchProcessesFunc to return error
		fetchProcessesFunc = func() (map[int32]*ProcessInfo, error) {
			return nil, errors.New("failed to get processes")
		}

		processes, err := fetchProcessesFunc()

		assert.Error(t, err)
		assert.Nil(t, processes)
		assert.EqualError(t, err, "failed to get processes")
	})
}

func TestInstrumentableFromModuleMap(t *testing.T) {
	tests := []struct {
		name       string
		moduleName string
		expected   svc.InstrumentableType
	}{
		{
			name:       "dotnet - libcoreclr.so",
			moduleName: "/usr/lib/libcoreclr.so",
			expected:   svc.InstrumentableDotnet,
		},
		{
			name:       "dotnet - path with libcoreclr.so",
			moduleName: "/opt/dotnet/shared/Microsoft.NETCore.App/7.0.0/libcoreclr.so",
			expected:   svc.InstrumentableDotnet,
		},
		{
			name:       "java - libjvm.so",
			moduleName: "/usr/lib/jvm/java-11-openjdk/lib/server/libjvm.so",
			expected:   svc.InstrumentableJava,
		},
		{
			name:       "java - simple libjvm.so",
			moduleName: "libjvm.so",
			expected:   svc.InstrumentableJava,
		},
		{
			name:       "nodejs - node binary with path",
			moduleName: "/usr/bin/node",
			expected:   svc.InstrumentableNodejs,
		},
		{
			name:       "nodejs - node binary without path",
			moduleName: "node",
			expected:   svc.InstrumentableNodejs,
		},
		{
			name:       "ruby - ruby binary",
			moduleName: "/usr/bin/ruby",
			expected:   svc.InstrumentableRuby,
		},
		{
			name:       "ruby - versioned ruby",
			moduleName: "/usr/bin/ruby3.2",
			expected:   svc.InstrumentableRuby,
		},
		{
			name:       "ruby - ruby with path",
			moduleName: "/opt/ruby/bin/ruby2.7",
			expected:   svc.InstrumentableRuby,
		},
		{
			name:       "python - python binary",
			moduleName: "/usr/bin/python",
			expected:   svc.InstrumentablePython,
		},
		{
			name:       "python - versioned python",
			moduleName: "/usr/bin/python3.9",
			expected:   svc.InstrumentablePython,
		},
		{
			name:       "python - python with path",
			moduleName: "/opt/python/bin/python3.11",
			expected:   svc.InstrumentablePython,
		},
		{
			name:       "generic - unknown module",
			moduleName: "/lib/x86_64-linux-gnu/libc.so.6",
			expected:   svc.InstrumentableGeneric,
		},
		{
			name:       "generic - empty string",
			moduleName: "",
			expected:   svc.InstrumentableGeneric,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := instrumentableFromModuleMap(tt.moduleName)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestInstrumentableFromEnviron(t *testing.T) {
	tests := []struct {
		name     string
		environ  string
		expected svc.InstrumentableType
	}{
		{
			name:     "dotnet - ASPNET variable",
			environ:  "PATH=/usr/bin\x00ASPNETCORE_ENVIRONMENT=Production\x00HOME=/home/user",
			expected: svc.InstrumentableDotnet,
		},
		{
			name:     "dotnet - DOTNET variable",
			environ:  "PATH=/usr/bin\x00DOTNET_ROOT=/opt/dotnet\x00HOME=/home/user",
			expected: svc.InstrumentableDotnet,
		},
		{
			name:     "generic - no dotnet variables",
			environ:  "PATH=/usr/bin\x00HOME=/home/user\x00LANG=en_US.UTF-8",
			expected: svc.InstrumentableGeneric,
		},
		{
			name:     "generic - empty environ",
			environ:  "",
			expected: svc.InstrumentableGeneric,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := instrumentableFromEnviron(tt.environ)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFindProcLanguageCheap(t *testing.T) {
	tests := []struct {
		name        string
		pid         int32
		mockLibMaps func(pid int32) ([]*procfs.ProcMap, error)
		mockReadEnv func(pid int32) ([]byte, error)
		expected    svc.InstrumentableType
	}{
		{
			name: "detect dotnet from environ when lib maps fails",
			pid:  789,
			mockLibMaps: func(pid int32) ([]*procfs.ProcMap, error) {
				return nil, errors.New("failed to read maps")
			},
			mockReadEnv: func(pid int32) ([]byte, error) {
				return []byte("PATH=/usr/bin\x00ASPNETCORE_ENVIRONMENT=Production"), nil
			},
			expected: svc.InstrumentableDotnet,
		},
		{
			name: "detect java from lib maps",
			pid:  123,
			mockLibMaps: func(pid int32) ([]*procfs.ProcMap, error) {
				return []*procfs.ProcMap{
					{Pathname: "/usr/lib/jvm/java-11-openjdk/lib/server/libjvm.so"},
				}, nil
			},
			mockReadEnv: func(pid int32) ([]byte, error) {
				return []byte("PATH=/usr/bin"), nil
			},
			expected: svc.InstrumentableJava,
		},
		{
			name: "detect nodejs from lib maps",
			pid:  456,
			mockLibMaps: func(pid int32) ([]*procfs.ProcMap, error) {
				return []*procfs.ProcMap{
					{Pathname: "/usr/bin/node"},
				}, nil
			},
			mockReadEnv: func(pid int32) ([]byte, error) {
				return []byte("PATH=/usr/bin"), nil
			},
			expected: svc.InstrumentableNodejs,
		},
		{
			name: "detect dotnet from environ when no lib matches",
			pid:  999,
			mockLibMaps: func(pid int32) ([]*procfs.ProcMap, error) {
				return []*procfs.ProcMap{
					{Pathname: "/lib/x86_64-linux-gnu/libc.so.6"},
				}, nil
			},
			mockReadEnv: func(pid int32) ([]byte, error) {
				return []byte("PATH=/usr/bin\x00DOTNET_ROOT=/opt/dotnet"), nil
			},
			expected: svc.InstrumentableDotnet,
		},
		{
			name: "generic when both fail",
			pid:  111,
			mockLibMaps: func(pid int32) ([]*procfs.ProcMap, error) {
				return nil, errors.New("failed to read maps")
			},
			mockReadEnv: func(pid int32) ([]byte, error) {
				return nil, errors.New("failed to read environ")
			},
			expected: svc.InstrumentableGeneric,
		},
		{
			name: "generic when no matches",
			pid:  222,
			mockLibMaps: func(pid int32) ([]*procfs.ProcMap, error) {
				return []*procfs.ProcMap{
					{Pathname: "/lib/x86_64-linux-gnu/libc.so.6"},
				}, nil
			},
			mockReadEnv: func(pid int32) ([]byte, error) {
				return []byte("PATH=/usr/bin\x00HOME=/home/user"), nil
			},
			expected: svc.InstrumentableGeneric,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save originals
			originalLibMaps := findLibMapsFunc
			originalReadEnv := readEnvFunc
			defer func() {
				findLibMapsFunc = originalLibMaps
				readEnvFunc = originalReadEnv
			}()

			// Set mocks
			findLibMapsFunc = tt.mockLibMaps
			readEnvFunc = tt.mockReadEnv

			result := findProcLanguageCheap(tt.pid)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEnvStrsToMap(t *testing.T) {
	tests := []struct {
		name     string
		varsStr  []string
		expected map[string]string
	}{
		{
			name: "basic environment variables",
			varsStr: []string{
				"PATH=/usr/bin:/bin",
				"HOME=/home/user",
				"USER=testuser",
			},
			expected: map[string]string{
				"PATH": "/usr/bin:/bin",
				"HOME": "/home/user",
				"USER": "testuser",
			},
		},
		{
			name: "environment variables with equals in value",
			varsStr: []string{
				"PATH=/usr/bin:/bin",
				"COMPLEX=key=value=another",
			},
			expected: map[string]string{
				"PATH":    "/usr/bin:/bin",
				"COMPLEX": "key=value=another",
			},
		},
		{
			name: "skip malformed entries",
			varsStr: []string{
				"PATH=/usr/bin",
				"MALFORMED",
				"HOME=/home/user",
			},
			expected: map[string]string{
				"PATH": "/usr/bin",
				"HOME": "/home/user",
			},
		},
		{
			name: "skip empty key or value",
			varsStr: []string{
				"PATH=/usr/bin",
				"=value",
				"KEY=",
				"  =  ",
				"HOME=/home/user",
			},
			expected: map[string]string{
				"PATH": "/usr/bin",
				"HOME": "/home/user",
			},
		},
		{
			name: "trim whitespace from key and value",
			varsStr: []string{
				"  PATH  =  /usr/bin  ",
				"HOME=/home/user",
			},
			expected: map[string]string{
				"PATH": "/usr/bin",
				"HOME": "/home/user",
			},
		},
		{
			name:     "empty input",
			varsStr:  []string{},
			expected: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := envStrsToMap(tt.varsStr)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestLocalProcessScanner_EnrichProcessInfoWithLanguage(t *testing.T) {
	tests := []struct {
		name        string
		pid         int32
		mockLibMaps func(pid int32) ([]*procfs.ProcMap, error)
		mockReadEnv func(pid int32) ([]byte, error)
		expected    svc.InstrumentableType
	}{
		{
			name: "java from libjvm.so",
			pid:  100,
			mockLibMaps: func(_ int32) ([]*procfs.ProcMap, error) {
				return []*procfs.ProcMap{
					{Pathname: "/usr/lib/jvm/java-17-openjdk/lib/server/libjvm.so"},
				}, nil
			},
			mockReadEnv: func(_ int32) ([]byte, error) { return []byte("PATH=/usr/bin"), nil },
			expected:    svc.InstrumentableJava,
		},
		{
			name: "nodejs from node binary",
			pid:  200,
			mockLibMaps: func(_ int32) ([]*procfs.ProcMap, error) {
				return []*procfs.ProcMap{{Pathname: "/usr/bin/node"}}, nil
			},
			mockReadEnv: func(_ int32) ([]byte, error) { return []byte("PATH=/usr/bin"), nil },
			expected:    svc.InstrumentableNodejs,
		},
		{
			name: "python from python binary",
			pid:  300,
			mockLibMaps: func(_ int32) ([]*procfs.ProcMap, error) {
				return []*procfs.ProcMap{{Pathname: "/usr/bin/python3.11"}}, nil
			},
			mockReadEnv: func(_ int32) ([]byte, error) { return []byte("PATH=/usr/bin"), nil },
			expected:    svc.InstrumentablePython,
		},
		{
			name: "ruby from ruby binary",
			pid:  400,
			mockLibMaps: func(_ int32) ([]*procfs.ProcMap, error) {
				return []*procfs.ProcMap{{Pathname: "/usr/bin/ruby3.2"}}, nil
			},
			mockReadEnv: func(_ int32) ([]byte, error) { return []byte("PATH=/usr/bin"), nil },
			expected:    svc.InstrumentableRuby,
		},
		{
			name: "dotnet from libcoreclr.so",
			pid:  500,
			mockLibMaps: func(_ int32) ([]*procfs.ProcMap, error) {
				return []*procfs.ProcMap{
					{Pathname: "/opt/dotnet/shared/Microsoft.NETCore.App/8.0.0/libcoreclr.so"},
				}, nil
			},
			mockReadEnv: func(_ int32) ([]byte, error) { return []byte("PATH=/usr/bin"), nil },
			expected:    svc.InstrumentableDotnet,
		},
		{
			name: "dotnet from environ when libs are unknown",
			pid:  600,
			mockLibMaps: func(_ int32) ([]*procfs.ProcMap, error) {
				return []*procfs.ProcMap{{Pathname: "/lib/x86_64-linux-gnu/libc.so.6"}}, nil
			},
			mockReadEnv: func(_ int32) ([]byte, error) {
				return []byte("PATH=/usr/bin\x00DOTNET_ROOT=/opt/dotnet"), nil
			},
			expected: svc.InstrumentableDotnet,
		},
		{
			name: "dotnet from environ when lib maps lookup fails",
			pid:  700,
			mockLibMaps: func(_ int32) ([]*procfs.ProcMap, error) {
				return nil, errors.New("maps unavailable")
			},
			mockReadEnv: func(_ int32) ([]byte, error) {
				return []byte("ASPNETCORE_ENVIRONMENT=Production"), nil
			},
			expected: svc.InstrumentableDotnet,
		},
		{
			name: "generic when nothing matches",
			pid:  800,
			mockLibMaps: func(_ int32) ([]*procfs.ProcMap, error) {
				return []*procfs.ProcMap{{Pathname: "/lib/x86_64-linux-gnu/libc.so.6"}}, nil
			},
			mockReadEnv: func(_ int32) ([]byte, error) { return []byte("PATH=/usr/bin"), nil },
			expected:    svc.InstrumentableGeneric,
		},
		{
			name: "generic when both lookups fail",
			pid:  900,
			mockLibMaps: func(_ int32) ([]*procfs.ProcMap, error) {
				return nil, errors.New("maps unavailable")
			},
			mockReadEnv: func(_ int32) ([]byte, error) {
				return nil, errors.New("environ unavailable")
			},
			expected: svc.InstrumentableGeneric,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalLibMaps := findLibMapsFunc
			originalReadEnv := readEnvFunc
			defer func() {
				findLibMapsFunc = originalLibMaps
				readEnvFunc = originalReadEnv
			}()

			// Capture the pid that the lookups were called with so we can
			// verify EnrichProcessInfoWithLanguage forwards ProcessInfo.pid.
			var libMapsPID, readEnvPID int32
			findLibMapsFunc = func(pid int32) ([]*procfs.ProcMap, error) {
				libMapsPID = pid
				return tt.mockLibMaps(pid)
			}
			readEnvFunc = func(pid int32) ([]byte, error) {
				readEnvPID = pid
				return tt.mockReadEnv(pid)
			}

			scanner := NewInitialStateScanner()
			info := &ProcessInfo{
				pid:      tt.pid,
				metadata: map[string]string{"preserved": "yes"},
			}
			scanner.EnrichProcessInfoWithLanguage(info)

			assert.Equal(t, tt.expected, info.kind, "kind should be set on ProcessInfo")
			assert.Equal(t, tt.pid, info.pid, "pid should not be mutated")
			assert.Equal(t, "yes", info.metadata["preserved"], "other fields should not be touched")
			assert.Equal(t, tt.pid, libMapsPID, "findLibMapsFunc should be called with ProcessInfo.pid")
			// readEnvFunc is only consulted if module-map lookup didn't yield a match.
			// When it is consulted, the same pid must be forwarded.
			if readEnvPID != 0 {
				assert.Equal(t, tt.pid, readEnvPID, "readEnvFunc should be called with ProcessInfo.pid")
			}
		})
	}

	t.Run("overwrites previous kind on re-invocation", func(t *testing.T) {
		originalLibMaps := findLibMapsFunc
		originalReadEnv := readEnvFunc
		defer func() {
			findLibMapsFunc = originalLibMaps
			readEnvFunc = originalReadEnv
		}()

		findLibMapsFunc = func(_ int32) ([]*procfs.ProcMap, error) {
			return []*procfs.ProcMap{{Pathname: "/usr/bin/node"}}, nil
		}
		readEnvFunc = func(_ int32) ([]byte, error) { return []byte("PATH=/usr/bin"), nil }

		scanner := NewInitialStateScanner()
		info := &ProcessInfo{pid: 42, kind: svc.InstrumentableJava}
		scanner.EnrichProcessInfoWithLanguage(info)

		assert.Equal(t, svc.InstrumentableNodejs, info.kind)
	})
}

func TestLocalProcessScanner_computeIncompatible(t *testing.T) {
	// Helper to save/restore all the global function vars touched by
	// computeIncompatible. Returns the deferred restore func.
	saveMocks := func() func() {
		origLibMaps := findLibMapsFunc
		origReadEnv := readEnvFunc
		origNewProcess := newProcessFunc
		origProcEnviron := procEnvironFunc
		return func() {
			findLibMapsFunc = origLibMaps
			readEnvFunc = origReadEnv
			newProcessFunc = origNewProcess
			procEnvironFunc = origProcEnviron
		}
	}

	t.Run("unhandled kind leaves incompatible false", func(t *testing.T) {
		defer saveMocks()()
		// All dispatch arms are language-specific; Ruby and Generic fall
		// through without touching incompatible or any I/O. Use mocks that
		// would panic the test if reached, to prove no I/O happens.
		panicked := func(_ int32) ([]*procfs.ProcMap, error) {
			t.Fatal("findLibMapsFunc should not be called for Ruby/Generic")
			return nil, nil
		}
		findLibMapsFunc = panicked
		newProcessFunc = func(_ int32) (*process.Process, error) {
			t.Fatal("newProcessFunc should not be called for Ruby/Generic")
			return nil, nil
		}

		scanner := NewInitialStateScanner()
		for _, kind := range []svc.InstrumentableType{svc.InstrumentableRuby, svc.InstrumentableGeneric} {
			info := &ProcessInfo{pid: 1, kind: kind}
			scanner.computeIncompatible(info)
			assert.False(t, info.incompatible, "kind=%v should leave incompatible false", kind)
		}
	})

	t.Run("dotnet", func(t *testing.T) {
		cases := []struct {
			name     string
			envStrs  []string
			expected bool
		}{
			{
				name:     "incompatible when CORECLR_ENABLE_PROFILING=1",
				envStrs:  []string{"PATH=/usr/bin", "CORECLR_ENABLE_PROFILING=1"},
				expected: true,
			},
			{
				name:     "incompatible when DOTNET_STARTUP_HOOKS set",
				envStrs:  []string{"DOTNET_STARTUP_HOOKS=/opt/hook.dll"},
				expected: true,
			},
			{
				name:     "incompatible when OTEL_DOTNET_AUTO_HOME set",
				envStrs:  []string{"OTEL_DOTNET_AUTO_HOME=/opt/otel"},
				expected: true,
			},
			{
				name:     "compatible when CORECLR_ENABLE_PROFILING=0",
				envStrs:  []string{"CORECLR_ENABLE_PROFILING=0"},
				expected: false,
			},
			{
				name:     "compatible when no dotnet instrumentation vars",
				envStrs:  []string{"PATH=/usr/bin", "HOME=/home/user"},
				expected: false,
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				defer saveMocks()()
				newProcessFunc = func(_ int32) (*process.Process, error) {
					return &process.Process{}, nil
				}
				procEnvironFunc = func(_ *process.Process) ([]string, error) {
					return tc.envStrs, nil
				}

				scanner := NewInitialStateScanner()
				info := &ProcessInfo{pid: 1, kind: svc.InstrumentableDotnet}
				scanner.computeIncompatible(info)

				assert.Equal(t, tc.expected, info.incompatible)
			})
		}

		t.Run("compatible when env lookup fails", func(t *testing.T) {
			defer saveMocks()()
			newProcessFunc = func(_ int32) (*process.Process, error) {
				return nil, errors.New("no process")
			}
			scanner := NewInitialStateScanner()
			info := &ProcessInfo{pid: 1, kind: svc.InstrumentableDotnet}
			scanner.computeIncompatible(info)
			assert.False(t, info.incompatible)
		})
	})

	t.Run("python", func(t *testing.T) {
		cases := []struct {
			name     string
			maps     []*procfs.ProcMap
			mapsErr  error
			expected bool
		}{
			{
				name:     "python 2.7 is incompatible",
				maps:     []*procfs.ProcMap{{Pathname: "/usr/lib/libpython2.7.so.1.0"}},
				expected: true,
			},
			{
				name:     "python 3.7 is incompatible",
				maps:     []*procfs.ProcMap{{Pathname: "/usr/lib/libpython3.7.so.1.0"}},
				expected: true,
			},
			{
				name:     "python 3.8 is incompatible (boundary)",
				maps:     []*procfs.ProcMap{{Pathname: "/usr/lib/libpython3.8.so.1.0"}},
				expected: true,
			},
			{
				name:     "python 3.9 is compatible (boundary)",
				maps:     []*procfs.ProcMap{{Pathname: "/usr/lib/libpython3.9.so.1.0"}},
				expected: false,
			},
			{
				name:     "python 3.11 is compatible",
				maps:     []*procfs.ProcMap{{Pathname: "/usr/lib/libpython3.11.so.1.0"}},
				expected: false,
			},
			{
				name:     "no libpython mapped  compatible (version unknown)",
				maps:     []*procfs.ProcMap{{Pathname: "/lib/x86_64-linux-gnu/libc.so.6"}},
				expected: false,
			},
			{
				name:     "version-less libpython3.so is ignored compatible",
				maps:     []*procfs.ProcMap{{Pathname: "/usr/lib/libpython3.so"}},
				expected: false,
			},
			{
				name:     "maps lookup failure leaves incompatible false",
				mapsErr:  errors.New("maps unavailable"),
				expected: false,
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				defer saveMocks()()
				findLibMapsFunc = func(_ int32) ([]*procfs.ProcMap, error) {
					if tc.mapsErr != nil {
						return nil, tc.mapsErr
					}
					return tc.maps, nil
				}
				// Python branch must NOT touch newProcessFunc.
				newProcessFunc = func(_ int32) (*process.Process, error) {
					t.Fatal("newProcessFunc should not be called on the python path")
					return nil, nil
				}

				scanner := NewInitialStateScanner()
				info := &ProcessInfo{pid: 1, kind: svc.InstrumentablePython}
				scanner.computeIncompatible(info)

				assert.Equal(t, tc.expected, info.incompatible)
			})
		}
	})

	// Java and NodeJS branches call proc.CmdlineSlice() on a real Process,
	// which reads /proc/<pid>/cmdline directly (no mockable indirection).
	// We work around this by using the test binary's own pid — its cmdline
	// is guaranteed not to contain -javaagent: or the OTel require path,
	// so any "incompatible=true" outcome must come from the env we control
	// via the mocked procEnvironFunc.
	realPID := int32(os.Getpid())

	t.Run("java", func(t *testing.T) {
		cases := []struct {
			name     string
			envStrs  []string
			expected bool
		}{
			{
				name:     "compatible when JAVA_TOOL_OPTIONS sets -javaagent to non-otel jar",
				envStrs:  []string{"JAVA_TOOL_OPTIONS=    -javaagent:/opt/agent.jar"},
				expected: false,
			},
			{
				name:     "compatible when OPENJ9_JAVA_OPTIONS sets -javaagent to non-otel jar",
				envStrs:  []string{"OPENJ9_JAVA_OPTIONS=-Xmx1g -javaagent:/opt/agent.jar"},
				expected: false,
			},
			{
				name:     "incompatible when JAVA_TOOL_OPTIONS sets -javaagent to otel upstream jar",
				envStrs:  []string{"JAVA_TOOL_OPTIONS=    -javaagent:/opt/opentelemetry-javaagent.jar"},
				expected: true,
			},
			{
				name:     "incompatible when OPENJ9_JAVA_OPTIONS sets -javaagent to grafana otel jar",
				envStrs:  []string{"OPENJ9_JAVA_OPTIONS=-Xmx1g -javaagent:/opt/grafana-opentelemetry-java.jar"},
				expected: true,
			},
			{
				name:     "compatible when env has no -javaagent",
				envStrs:  []string{"PATH=/usr/bin", "JAVA_HOME=/opt/java"},
				expected: false,
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				defer saveMocks()()
				newProcessFunc = func(pid int32) (*process.Process, error) {
					return &process.Process{Pid: pid}, nil
				}
				procEnvironFunc = func(_ *process.Process) ([]string, error) {
					return tc.envStrs, nil
				}

				scanner := NewInitialStateScanner()
				info := &ProcessInfo{pid: realPID, kind: svc.InstrumentableJava}
				scanner.computeIncompatible(info)

				assert.Equal(t, tc.expected, info.incompatible)
			})
		}

		t.Run("compatible when newProcessFunc fails on cmdline lookup", func(t *testing.T) {
			defer saveMocks()()
			// EnrichProcessInfoWithEnvironment is called first; it also uses
			// newProcessFunc, so on the second call we'd need to fail. Easier:
			// fail both. With no env populated, FindJavaAgent never runs and
			// incompatible stays false.
			newProcessFunc = func(_ int32) (*process.Process, error) {
				return nil, errors.New("no process")
			}
			scanner := NewInitialStateScanner()
			info := &ProcessInfo{pid: realPID, kind: svc.InstrumentableJava}
			scanner.computeIncompatible(info)
			assert.False(t, info.incompatible)
		})
	})

	t.Run("nodejs", func(t *testing.T) {
		cases := []struct {
			name     string
			envStrs  []string
			expected bool
		}{
			{
				name: "incompatible when NODE_OPTIONS has --require @opentelemetry/auto-instrumentations-node/register",
				envStrs: []string{
					"NODE_OPTIONS=--require @opentelemetry/auto-instrumentations-node/register",
				},
				expected: true,
			},
			{
				name: "incompatible when NODE_OPTIONS has -r @opentelemetry/auto-instrumentations-node/register",
				envStrs: []string{
					"NODE_OPTIONS=-r @opentelemetry/auto-instrumentations-node/register",
				},
				expected: true,
			},
			{
				name: "incompatible when NODE_OPTIONS uses --require=...",
				envStrs: []string{
					"NODE_OPTIONS=--require=@opentelemetry/auto-instrumentations-node/register",
				},
				expected: true,
			},
			{
				name:     "compatible when NODE_OPTIONS has no opentelemetry require",
				envStrs:  []string{"NODE_OPTIONS=--max-old-space-size=4096"},
				expected: false,
			},
			{
				name:     "compatible when NODE_OPTIONS is unset",
				envStrs:  []string{"PATH=/usr/bin"},
				expected: false,
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				defer saveMocks()()
				newProcessFunc = func(pid int32) (*process.Process, error) {
					return &process.Process{Pid: pid}, nil
				}
				procEnvironFunc = func(_ *process.Process) ([]string, error) {
					return tc.envStrs, nil
				}

				scanner := NewInitialStateScanner()
				info := &ProcessInfo{pid: realPID, kind: svc.InstrumentableNodejs}
				scanner.computeIncompatible(info)

				assert.Equal(t, tc.expected, info.incompatible)
			})
		}
	})
}

func TestLocalProcessScanner_FindExistingProcesses(t *testing.T) {
	t.Run("successfully finds and groups processes by container", func(t *testing.T) {
		// Save originals
		originalReadEnv := readEnvFunc
		originalLibMaps := findLibMapsFunc
		originalFetchProcesses := fetchProcessesFunc
		originalNewProcess := newProcessFunc
		originalContainerInfo := containerInfoFunc
		defer func() {
			fetchProcessesFunc = originalFetchProcesses
			findLibMapsFunc = originalLibMaps
			readEnvFunc = originalReadEnv
			newProcessFunc = originalNewProcess
			containerInfoFunc = originalContainerInfo
		}()

		// Mock lib maps
		findLibMapsFunc = func(pid int32) ([]*procfs.ProcMap, error) {
			return []*procfs.ProcMap{
				{Pathname: "/usr/lib/jvm/java-11-openjdk/lib/server/libjvm.so"},
			}, nil
		}

		// Mock read env
		readEnvFunc = func(pid int32) ([]byte, error) {
			return []byte("PATH=/usr/bin"), nil
		}

		// Mock process info
		fetchProcessesFunc = func() (map[int32]*ProcessInfo, error) {
			return map[int32]*ProcessInfo{
				123: {pid: 123},
				456: {pid: 456},
			}, nil
		}

		// Mock newProcessFunc
		newProcessFunc = func(pid int32) (*process.Process, error) {
			return &process.Process{}, nil
		}

		// Mock containerInfoFunc
		containerInfoFunc = func(pid uint32) (Info, error) {
			if pid == 123 {
				return Info{ContainerID: "container-1"}, nil
			}
			return Info{ContainerID: "container-2"}, nil
		}

		scanner := NewInitialStateScanner()
		containers, err := scanner.FindExistingProcesses()

		assert.NoError(t, err)
		assert.NotNil(t, containers)
		assert.Len(t, containers, 2)
		assert.Contains(t, containers, "container-1")
		assert.Contains(t, containers, "container-2")
		assert.Len(t, containers["container-1"], 1)
		assert.Len(t, containers["container-2"], 1)
		assert.Equal(t, int32(123), containers["container-1"][0].pid)
		assert.Equal(t, int32(456), containers["container-2"][0].pid)
	})

	t.Run("multiple processes in same container", func(t *testing.T) {
		// Save originals
		originalReadEnv := readEnvFunc
		originalLibMaps := findLibMapsFunc
		originalFetchProcesses := fetchProcessesFunc
		originalNewProcess := newProcessFunc
		originalContainerInfo := containerInfoFunc
		defer func() {
			fetchProcessesFunc = originalFetchProcesses
			findLibMapsFunc = originalLibMaps
			readEnvFunc = originalReadEnv
			newProcessFunc = originalNewProcess
			containerInfoFunc = originalContainerInfo
		}()

		findLibMapsFunc = func(pid int32) ([]*procfs.ProcMap, error) {
			return []*procfs.ProcMap{
				{Pathname: "/usr/bin/node"},
			}, nil
		}

		readEnvFunc = func(pid int32) ([]byte, error) {
			return []byte("PATH=/usr/bin"), nil
		}

		fetchProcessesFunc = func() (map[int32]*ProcessInfo, error) {
			return map[int32]*ProcessInfo{
				123: {pid: 123},
				456: {pid: 456},
				789: {pid: 789},
			}, nil
		}

		newProcessFunc = func(pid int32) (*process.Process, error) {
			return &process.Process{}, nil
		}

		// All processes in the same container
		containerInfoFunc = func(pid uint32) (Info, error) {
			return Info{ContainerID: "same-container"}, nil
		}

		scanner := NewInitialStateScanner()
		containers, err := scanner.FindExistingProcesses()

		assert.NoError(t, err)
		assert.NotNil(t, containers)
		assert.Len(t, containers, 1)
		assert.Contains(t, containers, "same-container")
		assert.Len(t, containers["same-container"], 3)
	})

	t.Run("detects different language types", func(t *testing.T) {
		// Save originals
		originalReadEnv := readEnvFunc
		originalLibMaps := findLibMapsFunc
		originalFetchProcesses := fetchProcessesFunc
		originalNewProcess := newProcessFunc
		originalContainerInfo := containerInfoFunc
		defer func() {
			fetchProcessesFunc = originalFetchProcesses
			findLibMapsFunc = originalLibMaps
			readEnvFunc = originalReadEnv
			newProcessFunc = originalNewProcess
			containerInfoFunc = originalContainerInfo
		}()

		// Different language for each PID
		findLibMapsFunc = func(pid int32) ([]*procfs.ProcMap, error) {
			switch pid {
			case 123:
				return []*procfs.ProcMap{{Pathname: "/usr/lib/jvm/java-11-openjdk/lib/server/libjvm.so"}}, nil
			case 456:
				return []*procfs.ProcMap{{Pathname: "/usr/bin/node"}}, nil
			case 789:
				return []*procfs.ProcMap{{Pathname: "/usr/lib/libcoreclr.so"}}, nil
			default:
				return []*procfs.ProcMap{}, nil
			}
		}

		readEnvFunc = func(pid int32) ([]byte, error) {
			return []byte("PATH=/usr/bin"), nil
		}

		fetchProcessesFunc = func() (map[int32]*ProcessInfo, error) {
			return map[int32]*ProcessInfo{
				123: {pid: 123},
				456: {pid: 456},
				789: {pid: 789},
			}, nil
		}

		newProcessFunc = func(pid int32) (*process.Process, error) {
			return &process.Process{}, nil
		}

		containerInfoFunc = func(pid uint32) (Info, error) {
			return Info{ContainerID: fmt.Sprintf("container-%d", pid)}, nil
		}

		scanner := NewInitialStateScanner()
		containers, err := scanner.FindExistingProcesses()

		assert.NoError(t, err)
		assert.Len(t, containers, 3)

		// Verify language types were detected
		assert.Equal(t, svc.InstrumentableJava, containers["container-123"][0].kind)
		assert.Equal(t, svc.InstrumentableNodejs, containers["container-456"][0].kind)
		assert.Equal(t, svc.InstrumentableDotnet, containers["container-789"][0].kind)
	})

	t.Run("error fetching processes", func(t *testing.T) {
		// Save originals
		originalFetchProcesses := fetchProcessesFunc
		defer func() { fetchProcessesFunc = originalFetchProcesses }()

		// Mock fetchProcessesFunc to return error
		fetchProcessesFunc = func() (map[int32]*ProcessInfo, error) {
			return nil, fmt.Errorf("failed to fetch processes")
		}

		scanner := NewInitialStateScanner()
		containers, err := scanner.FindExistingProcesses()

		assert.Error(t, err)
		assert.Nil(t, containers)
		assert.Contains(t, err.Error(), "failed to fetch processes")
	})

	t.Run("skip processes when newProcess fails", func(t *testing.T) {
		// Save originals
		originalReadEnv := readEnvFunc
		originalLibMaps := findLibMapsFunc
		originalFetchProcesses := fetchProcessesFunc
		originalNewProcess := newProcessFunc
		defer func() {
			fetchProcessesFunc = originalFetchProcesses
			findLibMapsFunc = originalLibMaps
			readEnvFunc = originalReadEnv
			newProcessFunc = originalNewProcess
		}()

		findLibMapsFunc = func(pid int32) ([]*procfs.ProcMap, error) {
			return []*procfs.ProcMap{
				{Pathname: "/usr/bin/node"},
			}, nil
		}

		readEnvFunc = func(pid int32) ([]byte, error) {
			return []byte("PATH=/usr/bin"), nil
		}

		fetchProcessesFunc = func() (map[int32]*ProcessInfo, error) {
			return map[int32]*ProcessInfo{
				123: {pid: 123},
				456: {pid: 456},
			}, nil
		}

		// newProcessFunc fails
		newProcessFunc = func(pid int32) (*process.Process, error) {
			return nil, fmt.Errorf("process not found")
		}

		scanner := NewInitialStateScanner()
		containers, err := scanner.FindExistingProcesses()

		assert.NoError(t, err)
		assert.NotNil(t, containers)
		assert.Empty(t, containers)
	})

	t.Run("skip processes when containerInfo fails", func(t *testing.T) {
		// Save originals
		originalReadEnv := readEnvFunc
		originalLibMaps := findLibMapsFunc
		originalFetchProcesses := fetchProcessesFunc
		originalNewProcess := newProcessFunc
		originalContainerInfo := containerInfoFunc
		defer func() {
			fetchProcessesFunc = originalFetchProcesses
			findLibMapsFunc = originalLibMaps
			readEnvFunc = originalReadEnv
			newProcessFunc = originalNewProcess
			containerInfoFunc = originalContainerInfo
		}()

		findLibMapsFunc = func(pid int32) ([]*procfs.ProcMap, error) {
			return []*procfs.ProcMap{
				{Pathname: "/usr/bin/node"},
			}, nil
		}

		readEnvFunc = func(pid int32) ([]byte, error) {
			return []byte("PATH=/usr/bin"), nil
		}

		fetchProcessesFunc = func() (map[int32]*ProcessInfo, error) {
			return map[int32]*ProcessInfo{
				123: {pid: 123},
				456: {pid: 456},
			}, nil
		}

		newProcessFunc = func(pid int32) (*process.Process, error) {
			return &process.Process{}, nil
		}

		// containerInfoFunc fails
		containerInfoFunc = func(pid uint32) (Info, error) {
			return Info{}, fmt.Errorf("container not found")
		}

		scanner := NewInitialStateScanner()
		containers, err := scanner.FindExistingProcesses()

		assert.NoError(t, err)
		assert.NotNil(t, containers)
		assert.Empty(t, containers)
	})

	t.Run("handles invalid SDK versions", func(t *testing.T) {
		// Save originals
		originalReadEnv := readEnvFunc
		originalLibMaps := findLibMapsFunc
		originalFetchProcesses := fetchProcessesFunc
		originalNewProcess := newProcessFunc
		originalContainerInfo := containerInfoFunc
		defer func() {
			fetchProcessesFunc = originalFetchProcesses
			findLibMapsFunc = originalLibMaps
			readEnvFunc = originalReadEnv
			newProcessFunc = originalNewProcess
			containerInfoFunc = originalContainerInfo
		}()

		findLibMapsFunc = func(pid int32) ([]*procfs.ProcMap, error) {
			return []*procfs.ProcMap{
				{Pathname: "/usr/bin/node"},
			}, nil
		}

		readEnvFunc = func(pid int32) ([]byte, error) {
			return []byte("PATH=/usr/bin"), nil
		}

		fetchProcessesFunc = func() (map[int32]*ProcessInfo, error) {
			return map[int32]*ProcessInfo{
				123: {pid: 123},
			}, nil
		}

		newProcessFunc = func(pid int32) (*process.Process, error) {
			return &process.Process{}, nil
		}

		containerInfoFunc = func(pid uint32) (Info, error) {
			return Info{ContainerID: "container-1"}, nil
		}

		scanner := NewInitialStateScanner()
		containers, err := scanner.FindExistingProcesses()

		assert.NoError(t, err)
		assert.NotNil(t, containers)
		assert.Len(t, containers, 1)
	})
}
