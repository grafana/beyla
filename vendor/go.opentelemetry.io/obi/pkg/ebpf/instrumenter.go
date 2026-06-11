// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/ebpf"

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	v2 "github.com/containers/common/pkg/cgroupv2"
	"github.com/hashicorp/go-version"
	"github.com/prometheus/procfs"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

func ilog() *slog.Logger {
	return slog.With("component", "ebpf.Instrumenter")
}

var findNamespacedPids = procs.FindNamespacedPids

func closeAll(closers []io.Closer) {
	for i := range closers {
		closers[i].Close()
	}
}

func (i *instrumenter) goprobes(p Tracer) error {
	// TODO: not running program if it does not find the required probes
	goProbes := p.GoProbes()

	i.gatherGoOffsets(goProbes)

	closers, err := i.instrumentProbes(i.exe, goProbes)
	if err != nil {
		return err
	}

	i.closables = append(i.closables, closers...)
	p.AddCloser(i.closables...)

	return nil
}

func (i *instrumenter) instrumentProbes(exe *link.Executable, probes map[string][]*ebpfcommon.ProbeDesc) ([]io.Closer, error) {
	log := ilog().With("probes", "instrumentProbes")

	var closers []io.Closer

	for symbolName, probeArray := range probes {
		for _, probe := range probeArray {
			log.Debug("going to instrument function", "function", symbolName, "programs", probe)

			if probe.Skip {
				if probe.Required {
					closeAll(closers)
					return nil, fmt.Errorf("required symbol %q was not resolved", symbolName)
				}
				log.Debug("skipping unresolved optional uprobe", "function", symbolName)
				continue
			}

			cls, err := i.uprobe(exe, probe)

			if err != nil {
				closeAll(cls)

				if probe.Required {
					closeAll(closers)
					if i.metrics != nil {
						i.metrics.InstrumentationError(i.processName, imetrics.InstrumentationErrorAttachingUprobe)
					}
					return nil, fmt.Errorf("instrumenting function %q: %w", symbolName, err)
				}

				// error will be common here since this could be no openssl loaded
				log.Debug("error instrumenting uprobe", "function", symbolName, "error", err)
			} else {
				closers = append(closers, cls...)
			}
		}
	}

	return closers, nil
}

func (i *instrumenter) kprobes(p KprobesTracer) error {
	log := ilog().With("probes", "kprobes")
	for kfunc, kprobes := range p.KProbes() {
		log.Debug("going to add kprobe to function", "function", kfunc, "probes", kprobes)

		if err := i.kprobe(kfunc, kprobes); err != nil {
			if kprobes.Required {
				if i.metrics != nil {
					i.metrics.InstrumentationError(i.processName, imetrics.InstrumentationErrorAttachingKprobe)
				}
				return fmt.Errorf("instrumenting function %q: %w", kfunc, err)
			}

			log.Debug("error instrumenting kprobe", "function", kfunc, "error", err)
		}
		p.AddCloser(i.closables...)
	}

	return nil
}

func (i *instrumenter) kprobe(funcName string, programs ebpfcommon.ProbeDesc) error {
	if programs.Start != nil {
		kp, err := link.Kprobe(funcName, programs.Start, nil)
		if err != nil {
			if i.metrics != nil {
				i.metrics.InstrumentationError(i.processName, imetrics.InstrumentationErrorAttachingKprobe)
			}
			return fmt.Errorf("setting kprobe: %w", err)
		}
		i.closables = append(i.closables, kp)
	}

	if programs.End != nil {
		// The commented code doesn't work on certain kernels. We need to invesigate more to see if it's possible
		// to productize it. Failure says: "neither debugfs nor tracefs are mounted".
		kp, err := link.Kretprobe(funcName, programs.End, nil /*&link.KprobeOptions{RetprobeMaxActive: 1024}*/)
		if err != nil {
			if i.metrics != nil {
				i.metrics.InstrumentationError(i.processName, imetrics.InstrumentationErrorAttachingKprobe)
			}
			return fmt.Errorf("setting kretprobe: %w", err)
		}
		i.closables = append(i.closables, kp)
	}

	return nil
}

type uprobeModule struct {
	lib       string
	instrPath string
	probes    []map[string][]*ebpfcommon.ProbeDesc
}

func (i *instrumenter) uprobeModules(p Tracer, pid app.PID, maps []*procfs.ProcMap, exePath string, exeIno uint64, log *slog.Logger) map[uint64]*uprobeModule {
	modules := map[uint64]*uprobeModule{}

	for lib, pMap := range p.UProbes() {
		baseLib, selected, err := matchVersionedUprobeLibrary(lib, maps)
		if err != nil {
			log.Warn("invalid version annotation for uprobe library", "lib", lib, "error", err)
			continue
		}
		if !selected {
			log.Debug("skipping version-mismatched uprobe library", "lib", lib)
			continue
		}

		lib = baseLib
		log.Debug("finding library", "lib", lib)
		libMap := procs.LibPath(lib, maps)
		instrPath := exePath

		instrumentedIno := exeIno

		if libMap != nil {
			log.Debug("instrumenting library", "lib", lib, "path", libMap.Pathname)
			// we do this to make sure instrumenting something like libssl.so works with Docker
			libInstrPath := fmt.Sprintf("/proc/%d/map_files/%x-%x", pid, libMap.StartAddr, libMap.EndAddr)

			info, err := os.Stat(libInstrPath)
			if err == nil {
				stat, ok := info.Sys().(*syscall.Stat_t)
				if ok {
					// We've already attached probes to this shared library for this executable
					// override the instrumented path to be the shared library
					instrPath = libInstrPath
					instrumentedIno = stat.Ino
					log.Debug("found inode number, recording this instrumentation if successful", "lib", lib, "path", libMap.Pathname, "ino", stat.Ino)
				}
			}
		}

		// We didn't find this library in the shared libraries, look up for the symbols in the executable directly
		if instrumentedIno == exeIno { // default executable instrumented path
			// E.g. NodeJS uses OpenSSL but they ship it as statically linked in the node binary
			log.Debug(lib+" not linked, attempting to instrument executable", "path", instrPath)
		}

		mod, ok := modules[instrumentedIno]
		if ok {
			mod.probes = append(mod.probes, pMap)
		} else {
			modules[instrumentedIno] = &uprobeModule{lib: lib, instrPath: instrPath, probes: []map[string][]*ebpfcommon.ProbeDesc{pMap}}
		}
	}

	return modules
}

// matchVersionedUprobeLibrary reports whether a (possibly annotated) library name should be
// instrumented for the given process.
func matchVersionedUprobeLibrary(name string, maps []*procfs.ProcMap) (string, bool, error) {
	baseName, constraints, hasConstraint, err := parseVersionAnnotation(name)
	if err != nil {
		return "", false, err
	}

	if !hasConstraint {
		return baseName, true, nil
	}

	libMap := procs.LibPath(baseName, maps)
	if libMap == nil {
		return baseName, false, nil
	}

	libVersion, ok := versionFromPath(libMap.Pathname)
	if !ok {
		return baseName, false, nil
	}

	return baseName, constraints.Check(libVersion), nil
}

// parseVersionAnnotation splits a library name that optionally carries a version constraint
// in square brackets, e.g. "_asyncio[>= 3.12]" → baseName="_asyncio", constraint=">=3.12".
// A name without brackets is returned unchanged with hasConstraint=false.
func parseVersionAnnotation(name string) (string, version.Constraints, bool, error) {
	start := strings.LastIndex(name, "[")
	if start < 0 || !strings.HasSuffix(name, "]") {
		return name, nil, false, nil
	}

	baseName := name[:start]
	if baseName == "" {
		return "", nil, false, fmt.Errorf("missing base name in %q", name)
	}

	rawConstraint := strings.TrimSpace(name[start+1 : len(name)-1])
	if rawConstraint == "" {
		return "", nil, false, fmt.Errorf("missing version constraint in %q", name)
	}

	constraints, err := version.NewConstraint(rawConstraint)
	if err != nil {
		return "", nil, false, err
	}

	return baseName, constraints, true, nil
}

// versionRe matches numeric version strings, with or without dots (e.g. "3.11", "311", "3").
var versionRe = regexp.MustCompile(`\d+(?:\.\d+)*`)

// versionFromPath extracts the first recognizable version from a library path by scanning
// each path component from right (most specific) to left (least specific). Dotted versions
// (e.g. "3.11" from "python3.11/") are prioritized over plain numbers (e.g. "311" from
// "cpython-311")
func versionFromPath(path string) (*version.Version, bool) {
	components := strings.Split(path, string(filepath.Separator))
	var dotted, plain []string

	for i := len(components) - 1; i >= 0; i-- {
		for _, m := range versionRe.FindAllString(components[i], -1) {
			if strings.Contains(m, ".") {
				dotted = append(dotted, m)
			} else {
				plain = append(plain, m)
			}
		}
	}

	for _, candidate := range append(dotted, plain...) {
		if v, err := version.NewVersion(candidate); err == nil {
			return v, true
		}
	}

	return nil, false
}

func resolveExePath(pid app.PID) (string, uint64, error) {
	exePath := fmt.Sprintf("/proc/%d/exe", pid)

	info, err := os.Stat(exePath)
	if err != nil {
		return "", 0, err
	}

	stat, ok := info.Sys().(*syscall.Stat_t)

	if !ok {
		return "", 0, errors.New("can't extract executable stats")
	}

	return exePath, stat.Ino, nil
}

func (i *instrumenter) uprobes(pid app.PID, p Tracer) error {
	maps, err := processMaps(pid)
	if err != nil {
		return err
	}
	log := ilog().With("probes", "uprobes")
	if len(maps) == 0 {
		log.Info("didn't find any process maps, not instrumenting shared libraries", "pid", pid)
		return nil
	}

	exePath, exeIno, err := resolveExePath(pid)
	if err != nil {
		return err
	}

	// Group all uprobes by module they should attach to.
	// Eg. node ssl and runtime probes attach to the same binary
	modules := i.uprobeModules(p, pid, maps, exePath, exeIno, log)

	for instrumentedIno, m := range modules {
		// We've already instrumented this module for the executable we have in hand, likely another earlier PID
		if i.hasModule(instrumentedIno) {
			log.Debug("already instrumented module for executable, ignoring...", "path", m.instrPath, "ino", instrumentedIno)
			continue
		}

		// Check if this is a library used by multiple executables. For example, a shared libssl.so between multiple executables.
		if p.AlreadyInstrumentedLib(instrumentedIno) {
			log.Debug("module already instrumented by other processes, incrementing reference count", "lib", m.lib, "path", m.instrPath, "ino", instrumentedIno)
			i.addModule(instrumentedIno)             // remember this mapping for linking/unlinking for this executable instance
			p.AddInstrumentedLibRef(instrumentedIno) // record one more use of this shared library
			continue
		}

		libExe, err := link.OpenExecutable(m.instrPath)
		if err != nil {
			log.Debug("can't open executable for inspection", "error", err)
			continue
		}

		for j := range m.probes {
			if err := gatherOffsets(m.instrPath, m.probes[j], log); err != nil {
				log.Debug("error gathering offsets", "error", err)
				continue
			}

			closers, err := i.instrumentProbes(libExe, m.probes[j])
			if err != nil {
				log.Debug("error instrumenting probes", "error", err)
				continue
			}

			log.Debug("adding module for instrumenter and incrementing reference count", "path", m.instrPath, "ino", instrumentedIno)

			// We bump the count of uses of the underlying shared library with a new executable
			p.RecordInstrumentedLib(instrumentedIno, closers)
			i.addModule(instrumentedIno)
		}
	}

	return nil
}

func (i *instrumenter) usdtProbes(pid app.PID, ns uint32, p Tracer) error {
	usdtTracer, ok := p.(USDTTracer)
	if !ok {
		return nil
	}

	probesByLib := usdtTracer.USDTProbes()
	if len(probesByLib) == 0 {
		return nil
	}

	maps, err := processMaps(pid)
	if err != nil {
		return err
	}
	if len(maps) == 0 {
		ilog().Debug("didn't find any process maps, not instrumenting USDT probes", "pid", pid)
		return nil
	}

	exePath, _, err := resolveExePath(pid)
	if err != nil {
		return err
	}

	var usdtClosers []io.Closer
	for lib, probes := range probesByLib {
		baseLib, selected, err := matchVersionedUprobeLibrary(lib, maps)
		if err != nil {
			ilog().Warn("invalid version annotation for USDT library", "lib", lib, "error", err)
			continue
		}
		if !selected {
			ilog().Debug("skipping version-mismatched USDT library", "lib", lib)
			continue
		}

		instrPath, mappedPath := usdtInstrumentationPath(pid, baseLib, maps, exePath)
		if instrPath == "" {
			ilog().Debug("skipping USDT library not found in process maps", "pid", pid, "lib", baseLib)
			continue
		}

		exe, err := link.OpenExecutable(instrPath)
		if err != nil {
			ilog().Debug("can't open executable for USDT instrumentation", "pid", pid, "path", instrPath, "error", err)
			continue
		}

		elfFile, err := elf.Open(instrPath)
		if err != nil {
			ilog().Debug("can't open ELF for USDT inspection", "pid", pid, "path", instrPath, "error", err)
			continue
		}

		for _, probe := range probes {
			closers, err := i.instrumentUSDTProbe(exe, elfFile, pid, ns, maps, mappedPath, probe)
			if err != nil {
				if probe.Required {
					elfFile.Close()
					closeAll(usdtClosers)
					return err
				}
				ilog().Debug("error instrumenting optional USDT probe",
					"pid", pid,
					"lib", baseLib,
					"provider", probe.Provider,
					"name", probe.Name,
					"error", err,
				)
				continue
			}
			i.closables = append(i.closables, closers...)
			usdtClosers = append(usdtClosers, closers...)
		}

		elfFile.Close()
	}

	p.AddCloser(usdtClosers...)
	return nil
}

func usdtInstrumentationPath(pid app.PID, lib string, maps []*procfs.ProcMap, exePath string) (string, string) {
	libMap := procs.LibPath(lib, maps)
	if libMap == nil {
		if lib == "" {
			return exePath, ""
		}
		return "", ""
	}

	libInstrPath := fmt.Sprintf("/proc/%d/map_files/%x-%x", pid, libMap.StartAddr, libMap.EndAddr)
	if _, err := os.Stat(libInstrPath); err == nil {
		return libInstrPath, libMap.Pathname
	}
	return libMap.Pathname, libMap.Pathname
}

func (i *instrumenter) instrumentUSDTProbe(
	exe *link.Executable,
	elfFile *elf.File,
	pid app.PID,
	ns uint32,
	maps []*procfs.ProcMap,
	mappedPath string,
	probe *ebpfcommon.USDTProbeDesc,
) ([]io.Closer, error) {
	if probe.Program == nil || probe.SpecsMap == nil || probe.IPMap == nil || probe.SpecManager == nil {
		return nil, errors.New("USDT probe is missing program, maps, or spec manager")
	}

	targets, err := collectUSDTTargets(elfFile, pid, maps, mappedPath, probe.Provider, probe.Name)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("USDT probe %s:%s not found", probe.Provider, probe.Name)
	}

	closers := make([]io.Closer, 0, len(targets))
	for _, target := range targets {
		specID, err := probe.SpecManager.ID(target.SpecKey, obiUSDTMaxSpecCnt)
		if err != nil {
			closeAll(closers)
			return nil, err
		}
		if err := probe.SpecsMap.Put(specID, target.Spec); err != nil {
			closeAll(closers)
			return nil, fmt.Errorf("updating USDT spec map: %w", err)
		}
		ipMapPIDs := usdtIPMapPIDs(pid)
		for _, mapPID := range ipMapPIDs {
			ipKey := obiUSDTIPKey{
				PID:       uint32(mapPID),
				Namespace: ns,
				IP:        target.AbsIP,
			}
			if err := probe.IPMap.Put(ipKey, specID); err != nil {
				closeAll(closers)
				return nil, fmt.Errorf("updating USDT IP map: %w", err)
			}
		}

		ilog().Debug("instrumenting USDT probe",
			"pid", pid,
			"namespace", ns,
			"ip_map_pids", ipMapPIDs,
			"provider", probe.Provider,
			"name", probe.Name,
			"spec_id", specID,
			"rel_ip", fmt.Sprintf("%#x", target.RelIP),
			"abs_ip", fmt.Sprintf("%#x", target.AbsIP),
			"sema_off", fmt.Sprintf("%#x", target.SemaOff),
		)

		up, err := exe.Uprobe("", probe.Program, &link.UprobeOptions{
			Address:      target.RelIP,
			PID:          int(pid),
			RefCtrOffset: target.SemaOff,
		})
		if err != nil {
			closeAll(closers)
			return nil, fmt.Errorf("attaching USDT probe %s:%s at %#x: %w", probe.Provider, probe.Name, target.RelIP, err)
		}
		closers = append(closers, up)
	}

	return closers, nil
}

func usdtIPMapPIDs(pid app.PID) []app.PID {
	pids := []app.PID{pid}
	seen := map[app.PID]struct{}{
		pid: {},
	}

	namespacedPIDs, err := findNamespacedPids(pid)
	if err != nil {
		ilog().Debug("can't read namespaced PIDs for USDT IP map", "pid", pid, "error", err)
		return pids
	}

	for _, nsPID := range namespacedPIDs {
		if _, ok := seen[nsPID]; ok {
			continue
		}
		seen[nsPID] = struct{}{}
		pids = append(pids, nsPID)
	}

	return pids
}

func (i *instrumenter) uprobe(exe *link.Executable, probe *ebpfcommon.ProbeDesc) ([]io.Closer, error) {
	var closers []io.Closer

	if probe.Start != nil {
		up, err := exe.Uprobe("", probe.Start, &link.UprobeOptions{
			Address: probe.StartOffset,
		})
		if err != nil {
			if i.metrics != nil {
				i.metrics.InstrumentationError(i.processName, imetrics.InstrumentationErrorAttachingUprobe)
			}
			return closers, fmt.Errorf("setting uprobe (offset): %w", err)
		}

		closers = append(closers, up)
	}

	if probe.End != nil {
		if len(probe.ReturnOffsets) == 0 {
			if i.metrics != nil {
				i.metrics.InstrumentationError(i.processName, imetrics.InstrumentationErrorAttachingUprobe)
			}
			return closers, errors.New("setting uretprobe (attaching to offset): missing return offsets")
		}

		for _, offset := range probe.ReturnOffsets {
			up, err := exe.Uprobe("", probe.End, &link.UprobeOptions{
				Address: offset,
			})
			if err != nil {
				if i.metrics != nil {
					i.metrics.InstrumentationError(i.processName, imetrics.InstrumentationErrorAttachingUprobe)
				}
				return closers, fmt.Errorf("setting uretprobe (attaching to offset): %w", err)
			}

			closers = append(closers, up)
		}
	}

	return closers, nil
}

func (i *instrumenter) sockfilters(p Tracer) error {
	for _, filter := range p.SocketFilters() {
		fd, err := attachSocketFilter(filter)
		if err != nil {
			if i.metrics != nil {
				i.metrics.InstrumentationError(i.processName, imetrics.InstrumentationErrorAttachingSockFilter)
			}
			return fmt.Errorf("attaching socket filter: %w", i.handleSockFilterErr(err, filter))
		}

		p.AddCloser(&ebpfcommon.Filter{Fd: fd})
	}

	return nil
}

func (i *instrumenter) handleSockFilterErr(originalErr error, filter *ebpf.Program) error {
	if !errors.Is(originalErr, unix.ENOMEM) {
		return originalErr
	}
	info, err := filter.Info()
	if err != nil {
		return fmt.Errorf("getting program info: %w", originalErr)
	}
	jitedSize, err := info.JitedSize()
	if err != nil {
		return fmt.Errorf("getting jited size: %w", originalErr)
	}
	return fmt.Errorf("%s, socket filter has a jited size of %d, consider increasing the value net.core.optmem_max kernel parameter to be larger then the program jited size, this will not affect existing sockets but only future ones created", originalErr.Error(), jitedSize)
}

func attachSocketFilter(filter *ebpf.Program) (int, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err == nil {
		ssoErr := syscall.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ATTACH_BPF, filter.FD())
		if ssoErr != nil {
			return -1, ssoErr
		}
		return fd, nil
	}

	return -1, err
}

func (i *instrumenter) sockmsgs(p Tracer) error {
	for _, sockmsg := range p.SockMsgs() {
		slog.Info("Attaching sock msgs")
		err := link.RawAttachProgram(link.RawAttachProgramOptions{
			Target:  sockmsg.MapFD,
			Program: sockmsg.Program,
			Attach:  sockmsg.AttachAs,
		})
		if err != nil {
			if i.metrics != nil {
				i.metrics.InstrumentationError(i.processName, imetrics.InstrumentationErrorAttachingSockMsg)
			}
			return fmt.Errorf("attaching sock_msg program: %w", err)
		}

		p.AddCloser(&sockmsg)
	}

	return nil
}

func (i *instrumenter) sockops(p Tracer) error {
	for _, sockops := range p.SockOps() {
		cgroupPath, err := getCgroupPath()
		if err != nil {
			if i.metrics != nil {
				i.metrics.InstrumentationError(i.processName, imetrics.InstrumentationErrorCgroupNotFound)
			}
			slog.Warn("could not get cgroup path (missing cgroup v2?), using best-effort TC tracking", "error", err)
			return nil
		}

		slog.Info("Attaching sock ops", "path", cgroupPath)

		sockops.SockopsCgroup, err = link.AttachCgroup(link.CgroupOptions{
			Path:    cgroupPath,
			Attach:  sockops.AttachAs,
			Program: sockops.Program,
		})
		if err != nil {
			if i.metrics != nil {
				i.metrics.InstrumentationError(i.processName, imetrics.InstrumentationErrorAttachingCgroup)
			}
			slog.Warn("could not attach sockops program, using best-effort TC tracking", "error", err)
			return nil
		}

		p.AddCloser(&sockops)
	}

	return nil
}

func (i *instrumenter) tracepoints(p KprobesTracer) error {
	for sfunc, sprobes := range p.Tracepoints() {
		slog.Debug("going to add syscall", "function", sfunc, "probes", sprobes)

		if err := i.tracepoint(sfunc, sprobes); err != nil {
			if i.metrics != nil {
				i.metrics.InstrumentationError(i.processName, imetrics.InstrumentationErrorInvalidTracepoint)
			}
			return fmt.Errorf("instrumenting function %q: %w", sfunc, err)
		}
		p.AddCloser(i.closables...)
	}

	return nil
}

func (i *instrumenter) tracepoint(funcName string, programs ebpfcommon.ProbeDesc) error {
	if programs.Start != nil {
		if !strings.Contains(funcName, "/") {
			if i.metrics != nil {
				i.metrics.InstrumentationError(i.processName, imetrics.InstrumentationErrorInvalidTracepoint)
			}
			return errors.New("invalid tracepoint type, must contain / in the name to separate the type and function name")
		}
		parts := strings.Split(funcName, "/")
		kp, err := link.Tracepoint(parts[0], parts[1], programs.Start, nil)
		if err != nil {
			if i.metrics != nil {
				i.metrics.InstrumentationError(i.processName, imetrics.InstrumentationErrorInvalidTracepoint)
			}
			return fmt.Errorf("setting syscall: %w", err)
		}
		i.closables = append(i.closables, kp)
	}

	return nil
}

func (i *instrumenter) iters(p Tracer) error {
	for _, iter := range p.Iters() {
		slog.Debug("Attaching iterator", "program", iter.Program.String())

		lnk, err := link.AttachIter(link.IterOptions{
			Program: iter.Program,
		})
		if err != nil {
			if i.metrics != nil {
				i.metrics.InstrumentationError(i.processName, imetrics.InstrumentationErrorAttachingIter)
			}
			return fmt.Errorf("attaching iterator: %w", err)
		}
		iter.Link = lnk

		p.AddCloser(iter.Link)
	}

	return nil
}

func (i *instrumenter) tracing(p Tracer) error {
	for _, tracing := range p.Tracing() {
		slog.Debug("Attaching tracing program", "program", tracing.Program.String(), "attachAs", tracing.AttachAs)

		lnk, err := link.AttachTracing(link.TracingOptions{
			Program:    tracing.Program,
			AttachType: tracing.AttachAs,
		})
		if err != nil {
			if i.metrics != nil {
				i.metrics.InstrumentationError(i.processName, imetrics.InstrumentationErrorAttachingTracing)
			}
			return fmt.Errorf("attaching tracing program: %w", err)
		}
		tracing.Link = lnk

		p.AddCloser(tracing.Link)
	}

	return nil
}

func (i *instrumenter) hasModule(ino uint64) bool {
	slog.Debug("looking up module", "instrumenter", i, "ino", ino)
	_, ok := i.modules[ino]
	return ok
}

func (i *instrumenter) addModule(ino uint64) {
	slog.Debug("remembering module for", "instrumenter", i, "ino", ino)
	i.modules[ino] = struct{}{}
}

func isLittleEndian() bool {
	var a uint16 = 1

	return *(*byte)(unsafe.Pointer(&a)) == 1
}

func htons(a uint16) uint16 {
	if isLittleEndian() {
		var arr [2]byte
		binary.LittleEndian.PutUint16(arr[:], a)
		return binary.BigEndian.Uint16(arr[:])
	}
	return a
}

func processMaps(pid app.PID) ([]*procfs.ProcMap, error) {
	return procs.FindLibMaps(pid)
}

func getCgroupPath() (string, error) {
	cgroupPath := "/sys/fs/cgroup"

	enabled, err := v2.Enabled()
	if !enabled {
		if _, pathErr := os.Stat(filepath.Join(cgroupPath, "unified")); pathErr == nil {
			slog.Debug("discovered hybrid cgroup hierarchy, will attempt to attach sockops")
			return filepath.Join(cgroupPath, "unified"), nil
		}
		return "", errors.New("failed to find unified cgroup hierarchy: sockops cannot be used with cgroups v1")
	}

	return cgroupPath, err
}

func symbolNames(m map[string][]*ebpfcommon.ProbeDesc, matcher ebpfcommon.SymbolMatcher) []string {
	keys := make([]string, 0, len(m))
	seen := map[string]struct{}{}

	for name, probes := range m {
		for _, probe := range probes {
			if probe.SymbolMatcher != matcher {
				continue
			}
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			keys = append(keys, name)
		}
	}

	return keys
}

func gatherOffsets(instrPath string, probes map[string][]*ebpfcommon.ProbeDesc, log *slog.Logger) error {
	elfFile, err := elf.Open(instrPath)
	if err != nil {
		return fmt.Errorf("failed to open elf file %s: %w", instrPath, err)
	}

	defer elfFile.Close()

	return gatherOffsetsImpl(elfFile, probes, instrPath, log)
}

func gatherOffsetsImpl(elfFile *elf.File, probes map[string][]*ebpfcommon.ProbeDesc,
	instrPath string, log *slog.Logger,
) error {
	exactSyms, err := procs.FindExeSymbols(elfFile, symbolNames(probes, ebpfcommon.SymbolMatcherExact))
	if err != nil {
		return fmt.Errorf("failed to lookup symbols for %s: %w", instrPath, err)
	}

	substringSyms, err := procs.FindExeSymbolsBySubstring(elfFile, symbolNames(probes, ebpfcommon.SymbolMatcherContains))
	if err != nil {
		return fmt.Errorf("failed to lookup symbols by substring for %s: %w", instrPath, err)
	}

	for symbolName, probeArray := range probes {
		for _, probe := range probeArray {
			syms := exactSyms
			if probe.SymbolMatcher == ebpfcommon.SymbolMatcherContains {
				syms = substringSyms
			}

			sym, ok := syms[symbolName]

			if !ok {
				probe.Skip = true
				if probe.Required {
					return fmt.Errorf("required symbol %s not found in %s", symbolName, instrPath)
				}
				log.Debug("skipping unresolved optional uprobe", "symbol", symbolName, "path", instrPath)
				continue
			}

			probe.Skip = false
			probe.StartOffset = sym.Off
			progData := readSymbolData(&sym)

			if progData == nil {
				log.Debug("error reading symbol data", "symbol", symbolName, "path", instrPath)
				continue
			}

			returns, err := goexec.FindReturnOffsets(sym.Off, progData)
			applyResolvedSymbolOffsets(probe, sym, returns, err, symbolName, instrPath, log)
			log.Debug("resolved uprobe symbol",
				"requested_symbol", symbolName,
				"matched_symbol", sym.Name,
				"path", instrPath,
				"offset", sym.Off,
				"offset_hex", fmt.Sprintf("0x%x", sym.Off),
				"size", sym.Len,
			)
		}
	}

	return nil
}

func applyResolvedSymbolOffsets(
	probe *ebpfcommon.ProbeDesc,
	sym procs.Sym,
	returnOffsets []uint64,
	returnErr error,
	symbolName string,
	instrPath string,
	log *slog.Logger,
) {
	probe.StartOffset = sym.Off
	if returnErr != nil {
		log.Debug("error finding return offsets", "symbol", symbolName, "path", instrPath, "matched_symbol", sym.Name, "error", returnErr)
		return
	}
	probe.ReturnOffsets = returnOffsets
}

func (i *instrumenter) gatherGoOffsets(goProbes map[string][]*ebpfcommon.ProbeDesc) {
	log := ilog().With("probes", "gatherGoOffsets")

	for symbolName, descs := range goProbes {
		offs, ok := i.offsets.Funcs[symbolName]

		if !ok {
			// the program function is not in the detected offsets. Ignoring
			log.Debug("ignoring function", "function", symbolName)
			continue
		}

		for _, probe := range descs {
			probe.StartOffset = offs.Start
			probe.ReturnOffsets = offs.Returns
		}
	}
}

func readSymbolData(sym *procs.Sym) []byte {
	if sym.Prog == nil {
		return nil
	}

	data := make([]byte, sym.Len)

	_, err := sym.Prog.ReadAt(data, int64(sym.Off-sym.Prog.Off))
	if err != nil {
		fmt.Printf("Error loading symbol data: %v\n", err)
		return nil
	}

	return data
}
