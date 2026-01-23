package webhook

import (
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strings"

	"github.com/prometheus/procfs"
	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
)

type PID int32

type ProcessInfo struct {
	pid            PID
	ppid           PID
	openPorts      []uint32
	exePath        string
	metadata       map[string]string
	podLabels      map[string]string
	podAnnotations map[string]string
	kind           svc.InstrumentableType
	containerInfo  *Info
	env            map[string]string
}

var (
	rubyModule   = regexp.MustCompile(`^(.*/)?ruby[\d.]*$`)
	pythonModule = regexp.MustCompile(`^(.*/)?python[\d.]*$`)
)

func wslog() *slog.Logger {
	return slog.With("component", "webhook.Scanner")
}

func findExistingProcesses() (map[string][]*ProcessInfo, error) {
	log := wslog()

	procs, err := fetchProcessesWithPorts(log)
	if err != nil {
		return nil, err
	}

	containers := map[string][]*ProcessInfo{}

	for _, v := range procs {
		log.Debug("found process", "process", v)
		v.kind = findProcLanguageCheap(int32(v.pid))

		proc, err := process.NewProcess(int32(v.pid))
		if err != nil {
			log.Debug("cannot find executable info", "pid", v.pid, "error", err)
			continue
		}
		if exePath, err := proc.Exe(); err == nil {
			v.exePath = exePath
		}
		if ppid, err := proc.Parent(); err == nil {
			v.ppid = PID(ppid.Pid)
		}

		if env, err := proc.Environ(); err == nil {
			v.env = envStrsToMap(env)
		}

		containerInfo, err := containerInfoForPID(uint32(v.pid))
		if err != nil {
			log.Debug("cannot find container info for pid", "pid", v.pid, "error", err)
			continue
		}
		v.containerInfo = &containerInfo
		log.Debug("final process state", "state", v)

		if existing, ok := containers[containerInfo.ContainerID]; ok {
			existing = append(existing, v)
			containers[containerInfo.ContainerID] = existing
		} else {
			containers[containerInfo.ContainerID] = []*ProcessInfo{v}
		}
	}

	return containers, nil
}

func fetchProcessesWithPorts(log *slog.Logger) (map[PID]*ProcessInfo, error) {
	processes := map[PID]*ProcessInfo{}
	pids, err := process.Pids()
	if err != nil {
		return nil, fmt.Errorf("can't get processes: %w", err)
	}

	for _, pid := range pids {
		conns, err := net.ConnectionsPid("inet", pid)
		if err != nil {
			log.Debug("can't get connections for process. Skipping", "pid", pid, "error", err)
			continue
		}
		var openPorts []uint32
		for _, conn := range conns {
			openPorts = append(openPorts, conn.Laddr.Port)
		}
		processes[PID(pid)] = &ProcessInfo{pid: PID(pid), openPorts: openPorts}
	}
	return processes, nil
}

func findProcLanguageCheap(pid int32) svc.InstrumentableType {
	maps, err := findLibMaps(pid)
	if err != nil {
		return svc.InstrumentableGeneric
	}

	for _, m := range maps {
		t := instrumentableFromModuleMap(m.Pathname)
		if t != svc.InstrumentableGeneric {
			return t
		}
	}

	bytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
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
