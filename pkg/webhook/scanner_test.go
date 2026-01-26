package webhook

import (
	"errors"
	"fmt"
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
	assert.Equal(t, dummySDKVersion, scanner.oldestSDKVersion)
}

func TestLocalProcessScanner_OldestSDKVersion(t *testing.T) {
	tests := []struct {
		name        string
		version     string
		expectError bool
		expectedVer string
	}{
		{
			name:        "no SDK version found",
			version:     dummySDKVersion,
			expectError: true,
			expectedVer: "",
		},
		{
			name:        "valid SDK version",
			version:     "v0.0.3",
			expectError: false,
			expectedVer: "v0.0.3",
		},
		{
			name:        "another valid SDK version",
			version:     "v1.2.5",
			expectError: false,
			expectedVer: "v1.2.5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := &LocalProcessScanner{
				oldestSDKVersion: tt.version,
			}

			ver, err := scanner.OldestSDKVersion()

			if tt.expectError {
				assert.Error(t, err)
				assert.Equal(t, "", ver)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedVer, ver)
			}
		})
	}
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

	t.Run("finds oldest SDK version from multiple processes", func(t *testing.T) {
		// Save originals
		originalReadEnv := readEnvFunc
		originalLibMaps := findLibMapsFunc
		originalFetchProcesses := fetchProcessesFunc
		originalNewProcess := newProcessFunc
		originalProcEnviron := procEnvironFunc
		originalContainerInfo := containerInfoFunc
		defer func() {
			fetchProcessesFunc = originalFetchProcesses
			findLibMapsFunc = originalLibMaps
			readEnvFunc = originalReadEnv
			newProcessFunc = originalNewProcess
			procEnvironFunc = originalProcEnviron
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

		// Mock environment variables for each process with different SDK versions
		mockEnvs := map[int32][]string{
			123: {fmt.Sprintf("%s=v0.0.5", envVarSDKVersion), "PATH=/usr/bin"},
			456: {fmt.Sprintf("%s=v0.0.3", envVarSDKVersion), "PATH=/usr/bin"}, // oldest
			789: {fmt.Sprintf("%s=v0.1.0", envVarSDKVersion), "PATH=/usr/bin"},
		}

		newProcessFunc = func(pid int32) (*process.Process, error) {
			// Return a mock process - the actual process object doesn't matter
			// because we're mocking procEnvironFunc
			return &process.Process{}, nil
		}

		// Mock procEnvironFunc to return different environments based on PID
		procEnvironFunc = func(proc *process.Process) ([]string, error) {
			// Extract PID from the process - in real scenario this would come from proc.Pid()
			// For testing, we track which process we're checking based on call order
			// We'll use a simple counter approach
			for pid, env := range mockEnvs {
				if env != nil {
					result := env
					mockEnvs[pid] = nil // Mark as used
					return result, nil
				}
			}
			return []string{"PATH=/usr/bin"}, nil
		}

		containerInfoFunc = func(pid uint32) (Info, error) {
			return Info{ContainerID: fmt.Sprintf("container-%d", pid)}, nil
		}

		scanner := NewInitialStateScanner()
		containers, err := scanner.FindExistingProcesses()

		assert.NoError(t, err)
		assert.NotNil(t, containers)
		assert.Len(t, containers, 3)

		// Verify the oldest SDK version was found
		oldestVer, err := scanner.OldestSDKVersion()
		assert.NoError(t, err)
		assert.Equal(t, "v0.0.3", oldestVer)

		// Verify all processes were added to containers
		assert.Contains(t, containers, "container-123")
		assert.Contains(t, containers, "container-456")
		assert.Contains(t, containers, "container-789")
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
		// Process should still be added even without valid SDK version
		assert.Len(t, containers, 1)
		// Scanner should still have dummy version since no valid versions found
		assert.Equal(t, dummySDKVersion, scanner.oldestSDKVersion)
	})
}
