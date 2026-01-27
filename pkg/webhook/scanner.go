package webhook

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strings"

	"github.com/prometheus/procfs"
	"github.com/shirou/gopsutil/v3/process"
	"golang.org/x/mod/semver"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
)

type LocalProcessScanner struct {
	logger           *slog.Logger
	oldestSDKVersion string
}

type ProcessInfo struct {
	pid            int32
	metadata       map[string]string
	podLabels      map[string]string
	podAnnotations map[string]string
	env            map[string]string
	kind           svc.InstrumentableType
	containerInfo  *Info
}

// testing related
var (
	fetchProcessesFunc = fetchProcesses
	readEnvFunc        = readEnv
	findLibMapsFunc    = findLibMaps
	newProcessFunc     = process.NewProcess
	procEnvironFunc    = procEnviron
	containerInfoFunc  = containerInfoForPID
)

const (
	dummySDKVersion = "v999.999.999"
)

var (
	rubyModule   = regexp.MustCompile(`^(.*/)?ruby[\d.]*$`)
	pythonModule = regexp.MustCompile(`^(.*/)?python[\d.]*$`)
)

func NewInitialStateScanner() *LocalProcessScanner {
	return &LocalProcessScanner{
		logger:           slog.With("component", "webhook.Scanner"),
		oldestSDKVersion: dummySDKVersion,
	}
}

func (s *LocalProcessScanner) OldestSDKVersion() (string, error) {
	if s.oldestSDKVersion == dummySDKVersion {
		return "", errors.New("no SDK version found in processes")
	}

	return s.oldestSDKVersion, nil
}

func (s *LocalProcessScanner) FindExistingProcesses() (map[string][]*ProcessInfo, error) {
	procs, err := fetchProcessesFunc()
	if err != nil {
		return nil, err
	}

	containers := map[string][]*ProcessInfo{}

	for _, v := range procs {
		s.logger.Debug("found process", "process", v)
		v.kind = findProcLanguageCheap(int32(v.pid))

		proc, err := newProcessFunc(int32(v.pid))
		if err != nil {
			s.logger.Debug("cannot find executable info", "pid", v.pid, "error", err)
			continue
		}
		if env, err := procEnvironFunc(proc); err == nil {
			v.env = envStrsToMap(env)
			if ver, ok := v.env[envVarSDKVersion]; ok && semver.IsValid(ver) {
				if semver.Compare(ver, s.oldestSDKVersion) < 0 {
					s.oldestSDKVersion = ver
				}
			}
		}

		containerInfo, err := containerInfoFunc(uint32(v.pid))
		if err != nil {
			s.logger.Debug("cannot find container info for pid", "pid", v.pid, "error", err)
			continue
		}
		v.containerInfo = &containerInfo
		s.logger.Debug("final process state", "state", v)

		if existing, ok := containers[containerInfo.ContainerID]; ok {
			existing = append(existing, v)
			containers[containerInfo.ContainerID] = existing
		} else {
			containers[containerInfo.ContainerID] = []*ProcessInfo{v}
		}
	}

	return containers, nil
}

func fetchProcesses() (map[int32]*ProcessInfo, error) {
	processes := map[int32]*ProcessInfo{}
	pids, err := process.Pids()
	if err != nil {
		return nil, fmt.Errorf("can't get processes: %w", err)
	}

	for _, pid := range pids {
		processes[pid] = &ProcessInfo{pid: pid}
	}
	return processes, nil
}

func procEnviron(proc *process.Process) ([]string, error) {
	return proc.Environ()
}

func readEnv(pid int32) ([]byte, error) {
	return os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
}

func findProcLanguageCheap(pid int32) svc.InstrumentableType {
	maps, err := findLibMapsFunc(pid)
	if err == nil {
		for _, m := range maps {
			t := instrumentableFromModuleMap(m.Pathname)
			if t != svc.InstrumentableGeneric {
				return t
			}
		}
	}

	bytes, err := readEnvFunc(pid)
	if err != nil {
		return svc.InstrumentableGeneric
	}
	return instrumentableFromEnviron(string(bytes))
}

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

func findLibMaps(pid int32) ([]*procfs.ProcMap, error) {
	proc, err := procfs.NewProc(int(pid))
	if err != nil {
		return nil, err
	}

	return proc.ProcMaps()
}

func envStrsToMap(varsStr []string) map[string]string {
	vars := make(map[string]string, len(varsStr))

	for _, s := range varsStr {
		keyVal := strings.SplitN(s, "=", 2)
		if len(keyVal) < 2 {
			continue
		}
		key := strings.TrimSpace(keyVal[0])
		val := strings.TrimSpace(keyVal[1])

		if key != "" && val != "" {
			vars[key] = val
		}
	}

	return vars
}
