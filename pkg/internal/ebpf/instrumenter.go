//go:build linux

package ebpf

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	v2 "github.com/containers/common/pkg/cgroupv2"
	"github.com/prometheus/procfs"
	"golang.org/x/sys/unix"

	ebpfcommon "github.com/grafana/beyla/pkg/internal/ebpf/common"
	"github.com/grafana/beyla/pkg/internal/exec"
	"github.com/grafana/beyla/pkg/internal/goexec"
)

func ilog() *slog.Logger {
	return slog.With("component", "ebpf.Instrumenter")
}

func (i *instrumenter) goprobes(p Tracer) error {
	log := ilog().With("probes", "goprobes")
	// TODO: not running program if it does not find the required probes
	for funcName, funcPrograms := range p.GoProbes() {
		offs, ok := i.offsets.Funcs[funcName]
		for _, funcProgram := range funcPrograms {
			if !ok {
				// the program function is not in the detected offsets. Ignoring
				log.Debug("ignoring function", "function", funcName)
				continue
			}
			log.Debug("going to instrument function", "function", funcName, "offsets", offs, "programs", funcProgram)
			if err := i.goprobe(ebpfcommon.Probe{
				Offsets:  offs,
				Programs: funcProgram,
			}); err != nil {
				return fmt.Errorf("instrumenting function %q: %w", funcName, err)
			}
			p.AddCloser(i.closables...)
		}
	}

	return nil
}

func (i *instrumenter) goprobe(probe ebpfcommon.Probe) error {
	// Attach BPF programs as start and return probes
	if probe.Programs.Start != nil {
		up, err := i.exe.Uprobe("", probe.Programs.Start, &link.UprobeOptions{
			Address: probe.Offsets.Start,
		})
		if err != nil {
			return fmt.Errorf("setting uprobe: %w", err)
		}
		i.closables = append(i.closables, up)
	}

	if probe.Programs.End != nil {
		// Go won't work with Uretprobes because of the way Go manages the stack. We need to set uprobes just before the return
		// values: https://github.com/iovisor/bcc/issues/1320
		for _, ret := range probe.Offsets.Returns {
			urp, err := i.exe.Uprobe("", probe.Programs.End, &link.UprobeOptions{
				Address: ret,
			})
			if err != nil {
				return fmt.Errorf("setting uretprobe: %w", err)
			}
			i.closables = append(i.closables, urp)
		}
	}

	return nil
}

func (i *instrumenter) kprobes(p KprobesTracer) error {
	log := ilog().With("probes", "kprobes")
	for kfunc, kprobes := range p.KProbes() {
		log.Debug("going to add kprobe to function", "function", kfunc, "probes", kprobes)

		if err := i.kprobe(kfunc, kprobes); err != nil {
			if kprobes.Required {
				return fmt.Errorf("instrumenting function %q: %w", kfunc, err)
			}

			log.Debug("error instrumenting kprobe", "function", kfunc, "error", err)
		}
		p.AddCloser(i.closables...)
	}

	return nil
}

func (i *instrumenter) kprobe(funcName string, programs ebpfcommon.FunctionPrograms) error {
	if programs.Start != nil {
		kp, err := link.Kprobe(funcName, programs.Start, nil)
		if err != nil {
			return fmt.Errorf("setting kprobe: %w", err)
		}
		i.closables = append(i.closables, kp)
	}

	if programs.End != nil {
		// The commented code doesn't work on certain kernels. We need to invesigate more to see if it's possible
		// to productize it. Failure says: "neither debugfs nor tracefs are mounted".
		kp, err := link.Kretprobe(funcName, programs.End, nil /*&link.KprobeOptions{RetprobeMaxActive: 1024}*/)
		if err != nil {
			return fmt.Errorf("setting kretprobe: %w", err)
		}
		i.closables = append(i.closables, kp)
	}

	return nil
}

type uprobeModule struct {
	lib       string
	instrPath string
	probes    []ebpfcommon.FunctionPrograms
}

func (i *instrumenter) uprobeModules(p Tracer, pid int32, maps []*procfs.ProcMap, exePath string, exeIno uint64, log *slog.Logger) map[uint64]*uprobeModule {
	modules := map[uint64]*uprobeModule{}

	for lib, pArray := range p.UProbes() {
		log.Debug("finding library", "lib", lib)
		libMap := exec.LibPath(lib, maps)
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
			log.Debug(fmt.Sprintf("%s not linked, attempting to instrument executable", lib), "path", instrPath)
		}

		mod, ok := modules[instrumentedIno]
		if ok {
			mod.probes = append(mod.probes, pArray...)
		} else {
			modules[instrumentedIno] = &uprobeModule{lib: lib, instrPath: instrPath, probes: pArray}
		}
	}

	return modules
}

func resolveExePath(pid int32) (string, uint64, error) {
	exePath := fmt.Sprintf("/proc/%d/exe", pid)

	info, err := os.Stat(exePath)

	if err != nil {
		return "", 0, err
	}

	stat, ok := info.Sys().(*syscall.Stat_t)

	if !ok {
		return "", 0, fmt.Errorf("can't extract executable stats")
	}

	return exePath, stat.Ino, nil
}

func (i *instrumenter) uprobes(pid int32, p Tracer) error {
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
			p.RecordInstrumentedLib(instrumentedIno) // record one more use of this shared library
			continue
		}

		if err := gatherOffsets(m.instrPath, m.probes, log); err != nil {
			return err
		}

		libExe, err := link.OpenExecutable(m.instrPath)

		if err != nil {
			return err
		}

		for j := range m.probes {
			probe := &m.probes[j]

			log.Debug("going to instrument function", "function", probe.SymbolName, "programs", probe)

			err := i.uprobe(p, instrumentedIno, libExe, probe)

			if err != nil {
				if probe.Required {
					return fmt.Errorf("instrumenting function %q: %w", probe.SymbolName, err)
				}

				// error will be common here since this could be no openssl loaded
				log.Debug("error instrumenting uprobe", "function", probe.SymbolName, "error", err)
			}
		}

		log.Debug("adding module for instrumenter and incrementing reference count", "path", m.instrPath, "ino", instrumentedIno)

		// We bump the count of uses of the underlying shared library with a new executable
		p.RecordInstrumentedLib(instrumentedIno)
		i.addModule(instrumentedIno)
	}

	return nil
}

func attachToOffsets(p Tracer, instrumentedIno uint64, exe *link.Executable, probe *ebpfcommon.FunctionPrograms) error {
	if probe.Start != nil {
		up, err := exe.Uprobe("", probe.Start, &link.UprobeOptions{
			Address: probe.StartOffset,
		})

		if err != nil {
			return fmt.Errorf("setting uprobe (offset): %w", err)
		}

		p.AddModuleCloser(instrumentedIno, up)
	}

	if probe.End != nil {
		if len(probe.ReturnOffsets) == 0 {
			return fmt.Errorf("setting uretprobe (attaching to offset): missing return offsets")
		}

		for _, offset := range probe.ReturnOffsets {
			up, err := exe.Uprobe("", probe.End, &link.UprobeOptions{
				Address: offset,
			})

			if err != nil {
				return fmt.Errorf("setting uretprobe (attaching to offset): %w", err)
			}

			p.AddModuleCloser(instrumentedIno, up)
		}
	}

	return nil
}

func attachToSymbolName(p Tracer, instrumentedIno uint64, exe *link.Executable, probe *ebpfcommon.FunctionPrograms) error {
	if probe.Start != nil {
		up, err := exe.Uprobe(probe.SymbolName, probe.Start, nil)

		if err != nil {
			return fmt.Errorf("setting uprobe: %w", err)
		}

		p.AddModuleCloser(instrumentedIno, up)
	}

	if probe.End != nil {

		up, err := exe.Uretprobe(probe.SymbolName, probe.End, nil)

		if err != nil {
			return fmt.Errorf("setting uretprobe: %w", err)
		}
		p.AddModuleCloser(instrumentedIno, up)
	}

	return nil
}

func (i *instrumenter) uprobe(p Tracer, instrumentedIno uint64, exe *link.Executable, probe *ebpfcommon.FunctionPrograms) error {
	if probe.AttachToOffsets {
		return attachToOffsets(p, instrumentedIno, exe, probe)
	}

	return attachToSymbolName(p, instrumentedIno, exe, probe)
}

func (i *instrumenter) sockfilters(p Tracer) error {
	for _, filter := range p.SocketFilters() {
		fd, err := attachSocketFilter(filter)
		if err != nil {
			return fmt.Errorf("attaching socket filter: %w", err)
		}

		p.AddCloser(&ebpfcommon.Filter{Fd: fd})
	}

	return nil
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
			return fmt.Errorf("error getting cgroup path for sockops: %w", err)
		}

		slog.Info("Attaching sock ops", "path", cgroupPath)

		sockops.SockopsCgroup, err = link.AttachCgroup(link.CgroupOptions{
			Path:    cgroupPath,
			Attach:  sockops.AttachAs,
			Program: sockops.Program,
		})

		if err != nil {
			return fmt.Errorf("attaching sockops program: %w", err)
		}

		p.AddCloser(&sockops)
	}

	return nil
}

func (i *instrumenter) tracepoints(p KprobesTracer) error {
	for sfunc, sprobes := range p.Tracepoints() {
		slog.Debug("going to add syscall", "function", sfunc, "probes", sprobes)

		if err := i.tracepoint(sfunc, sprobes); err != nil {
			return fmt.Errorf("instrumenting function %q: %w", sfunc, err)
		}
		p.AddCloser(i.closables...)
	}

	return nil
}

func (i *instrumenter) tracepoint(funcName string, programs ebpfcommon.FunctionPrograms) error {
	if programs.Start != nil {
		if !strings.Contains(funcName, "/") {
			return fmt.Errorf("invalid tracepoint type, must contain / in the name to separate the type and function name")
		}
		parts := strings.Split(funcName, "/")
		kp, err := link.Tracepoint(parts[0], parts[1], programs.Start, nil)
		if err != nil {
			return fmt.Errorf("setting syscall: %w", err)
		}
		i.closables = append(i.closables, kp)
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

func processMaps(pid int32) ([]*procfs.ProcMap, error) {
	return exec.FindLibMaps(pid)
}

func getCgroupPath() (string, error) {
	cgroupPath := "/sys/fs/cgroup"

	enabled, err := v2.Enabled()
	if !enabled {
		cgroupPath = filepath.Join(cgroupPath, "unified")
	}
	return cgroupPath, err
}

func symbolNames(m []ebpfcommon.FunctionPrograms) []string {
	keys := make([]string, 0, len(m))

	for i := range m {
		if m[i].AttachToOffsets {
			keys = append(keys, m[i].SymbolName)
		}
	}

	return keys
}

func gatherOffsets(instrPath string, probes []ebpfcommon.FunctionPrograms, log *slog.Logger) error {
	elfFile, err := elf.Open(instrPath)

	if err != nil {
		return fmt.Errorf("failed to open elf file %s: %w", instrPath, err)
	}

	defer elfFile.Close()

	syms, err := exec.FindExeSymbols(elfFile, symbolNames(probes))

	if err != nil {
		return fmt.Errorf("failed to lookup symbols for %s: %w", instrPath, err)
	}

	for i := range probes {
		probe := &probes[i]

		if !probe.AttachToOffsets {
			continue
		}

		sym, ok := syms[probe.SymbolName]

		if !ok {
			continue
		}

		progData := readSymbolData(&sym)

		if progData == nil {
			return fmt.Errorf("error reading symbol data for %s (%s)", probe.SymbolName, instrPath)
		}

		returns, err := goexec.FindReturnOffssets(sym.Off, progData)

		if err != nil {
			log.Debug("Error finding return offsets", "symbol", sym)
			continue
		}

		probe.StartOffset = sym.Off
		probe.ReturnOffsets = returns
	}

	return nil
}

func readSymbolData(sym *exec.Sym) []byte {
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
