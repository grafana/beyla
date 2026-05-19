package webhook

import (
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strings"

	"github.com/prometheus/procfs"
	"github.com/shirou/gopsutil/v3/process"
	"golang.org/x/mod/semver"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"

	"github.com/grafana/beyla/v3/pkg/webhook/lang"
)

type LocalProcessScanner struct {
	logger            *slog.Logger
	oldestSDKVersion  string
	currentSDKVersion string
}

type ProcessInfo struct {
	pid            int32
	metadata       map[string]string
	podLabels      map[string]string
	podAnnotations map[string]string
	env            map[string]string
	kind           svc.InstrumentableType
	incompatible   bool
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

func NewInitialStateScanner(currentSDKVersion string) *LocalProcessScanner {
	return &LocalProcessScanner{
		logger:            slog.With("component", "webhook.Scanner"),
		oldestSDKVersion:  dummySDKVersion,
		currentSDKVersion: currentSDKVersion,
	}
}

func (s *LocalProcessScanner) OldestSDKVersion() string {
	if s.oldestSDKVersion == dummySDKVersion {
		return s.currentSDKVersion
	}

	return s.oldestSDKVersion
}

func (s *LocalProcessScanner) EnrichProcessInfoWithContainerData(v *ProcessInfo) bool {
	containerInfo, err := containerInfoFunc(uint32(v.pid))
	if err != nil {
		s.logger.Debug("cannot find container info for pid", "pid", v.pid, "error", err)
		return false
	}
	v.containerInfo = &containerInfo

	return true
}

func (s *LocalProcessScanner) computeIncompatibleJava(v *ProcessInfo) {
	s.EnrichProcessInfoWithEnvironment(v)
	if proc, err := newProcessFunc(int32(v.pid)); err == nil {
		if cmdLine, err := proc.CmdlineSlice(); err == nil {
			agent := lang.FindJavaAgent(cmdLine, v.env)

			v.incompatible = (agent != nil)
		}
	}
}

func (s *LocalProcessScanner) computeIncompatiblePython(v *ProcessInfo) {
	if maps, err := findLibMapsFunc(int32(v.pid)); err == nil {
		ver := lang.DetectPythonVersion(maps)

		v.incompatible = (ver != nil) && (ver.Major < 3 || (ver.Major == 3 && ver.Minor <= 8))
	}
}

func (s *LocalProcessScanner) computeIncompatibleNodejs(v *ProcessInfo) {
	s.EnrichProcessInfoWithEnvironment(v)
	if proc, err := newProcessFunc(int32(v.pid)); err == nil {
		if cmdLine, err := proc.CmdlineSlice(); err == nil {
			v.incompatible = lang.HasNodeJSAutoInstrumentation(cmdLine, v.env)
		}
	}
}

func (s *LocalProcessScanner) computeIncompatibleDotnet(v *ProcessInfo) {
	s.EnrichProcessInfoWithEnvironment(v)

	v.incompatible = lang.HasDotnetInstrumentation(v.env)
}

func (s *LocalProcessScanner) computeIncompatible(v *ProcessInfo) {
	switch v.kind {
	case svc.InstrumentableDotnet:
		s.computeIncompatibleDotnet(v)
	case svc.InstrumentableJava:
		s.computeIncompatibleJava(v)
	case svc.InstrumentablePython:
		s.computeIncompatiblePython(v)
	case svc.InstrumentableNodejs:
		s.computeIncompatibleNodejs(v)
	}
}

func (s *LocalProcessScanner) EnrichProcessInfoWithLanguage(v *ProcessInfo) {
	v.kind = findProcLanguageCheap(int32(v.pid))

	s.computeIncompatible(v)
}

func (s *LocalProcessScanner) EnrichProcessInfoWithEnvironment(v *ProcessInfo) bool {
	if v.env != nil {
		return true
	}

	proc, err := newProcessFunc(int32(v.pid))
	if err != nil {
		s.logger.Debug("cannot find executable info", "pid", v.pid, "error", err)
		return false
	}
	if env, err := procEnvironFunc(proc); err == nil {
		v.env = envStrsToMap(env)
		if ver, ok := v.env[envVarSDKVersion]; ok && semver.IsValid(ver) {
			if semver.Compare(ver, s.oldestSDKVersion) < 0 {
				s.oldestSDKVersion = ver
			}
		}
	}

	return true
}

func (s *LocalProcessScanner) EnrichProcessInfo(v *ProcessInfo) bool {
	if !s.EnrichProcessInfoWithContainerData(v) {
		return false
	}

	if !s.EnrichProcessInfoWithEnvironment(v) {
		return false
	}

	s.EnrichProcessInfoWithLanguage(v)

	return true
}

func (s *LocalProcessScanner) FindExistingProcesses() (map[string][]*ProcessInfo, error) {
	procs, err := fetchProcessesFunc()
	if err != nil {
		return nil, err
	}

	containers := map[string][]*ProcessInfo{}

	for _, v := range procs {
		s.logger.Debug("found process", "process", v)
		if !s.EnrichProcessInfo(v) {
			continue
		}
		s.logger.Debug("final process state", "state", v)

		if existing, ok := containers[v.containerInfo.ContainerID]; ok {
			existing = append(existing, v)
			containers[v.containerInfo.ContainerID] = existing
		} else {
			containers[v.containerInfo.ContainerID] = []*ProcessInfo{v}
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
