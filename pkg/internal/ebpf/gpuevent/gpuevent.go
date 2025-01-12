package gpuevent

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/ianlancetaylor/demangle"
	"github.com/prometheus/procfs"

	"github.com/grafana/beyla/pkg/beyla"
	"github.com/grafana/beyla/pkg/config"
	ebpfcommon "github.com/grafana/beyla/pkg/internal/ebpf/common"
	"github.com/grafana/beyla/pkg/internal/exec"
	"github.com/grafana/beyla/pkg/internal/goexec"
	"github.com/grafana/beyla/pkg/internal/imetrics"
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/svc"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type gpu_kernel_launch_t -target amd64,arm64 bpf ../../../../bpf/gpuevent.c -- -I../../../../bpf/headers
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type gpu_kernel_launch_t -target amd64,arm64 bpf_debug ../../../../bpf/gpuevent.c -- -I../../../../bpf/headers -DBPF_DEBUG

// Hold onto Linux inode numbers of files that are already instrumented, e.g. libssl.so.3
var instrumentedLibs = make(ebpfcommon.InstrumentedLibsT)
var libsMux sync.Mutex

type pidKey struct {
	Pid int32
	Ns  uint32
}

var pidMap = map[pidKey]uint64{}
var symbolsMap = map[uint64]map[int64]string{}
var baseMap = map[pidKey]uint64{}

type GPUKernelLaunchInfo bpfGpuKernelLaunchT

// TODO: We have a way to bring ELF file information to this Tracer struct
// via the newNonGoTracersGroup / newNonGoTracersGroupUProbes functions. Now,
// we need to figure out how to pass it to the SharedRingbuf.. not sure if thats
// possible
type Tracer struct {
	pidsFilter ebpfcommon.ServiceFilter
	cfg        *beyla.Config
	metrics    imetrics.Reporter
	bpfObjects bpfObjects
	closers    []io.Closer
	log        *slog.Logger
}

func New(cfg *beyla.Config, metrics imetrics.Reporter) *Tracer {
	log := slog.With("component", "gpuevent.Tracer")

	return &Tracer{
		log:        log,
		cfg:        cfg,
		metrics:    metrics,
		pidsFilter: ebpfcommon.CommonPIDsFilter(&cfg.Discovery),
	}
}

func (p *Tracer) AllowPID(pid, ns uint32, svc *svc.Attrs) {
	p.pidsFilter.AllowPID(pid, ns, svc, ebpfcommon.PIDTypeKProbes)
}

func (p *Tracer) BlockPID(pid, ns uint32) {
	p.pidsFilter.BlockPID(pid, ns)
}

func (p *Tracer) Load() (*ebpf.CollectionSpec, error) {
	loader := loadBpf
	if p.cfg.EBPF.BpfDebug {
		loader = loadBpf_debug
	}

	return loader()
}

func (p *Tracer) Constants() map[string]any {
	m := make(map[string]any, 2)

	// The eBPF side does some basic filtering of events that do not belong to
	// processes which we monitor. We filter more accurately in the userspace, but
	// for performance reasons we enable the PID based filtering in eBPF.
	if !p.cfg.Discovery.SystemWide && !p.cfg.Discovery.BPFPidFilterOff {
		m["filter_pids"] = int32(1)
	} else {
		m["filter_pids"] = int32(0)
	}

	return m
}

func (p *Tracer) RegisterOffsets(fileInfo *exec.FileInfo, _ *goexec.Offsets) {
	p.ProcessBinary(fileInfo)
}

func (p *Tracer) ProcessBinary(fileInfo *exec.FileInfo) {
	if fileInfo == nil || fileInfo.ELF == nil {
		p.log.Error("Empty fileinfo for Cuda")
	} else {
		ProcessCudaFileInfo(fileInfo)
	}
}

func (p *Tracer) BpfObjects() any {
	return &p.bpfObjects
}

func (p *Tracer) AddCloser(c ...io.Closer) {
	p.closers = append(p.closers, c...)
}

func (p *Tracer) GoProbes() map[string][]*ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) KProbes() map[string]ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) Tracepoints() map[string]ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) UProbes() map[string]map[string][]*ebpfcommon.ProbeDesc {
	return map[string]map[string][]*ebpfcommon.ProbeDesc{
		"libcudart.so": {
			"cudaLaunchKernel": {{
				Start: p.bpfObjects.HandleCudaLaunch,
			}},
		},
	}
}

func (p *Tracer) SetupTailCalls() {}

func (p *Tracer) SocketFilters() []*ebpf.Program {
	return nil
}

func (p *Tracer) SockMsgs() []ebpfcommon.SockMsg { return nil }

func (p *Tracer) SockOps() []ebpfcommon.SockOps { return nil }

func (p *Tracer) RecordInstrumentedLib(id uint64, closers []io.Closer) {
	libsMux.Lock()
	defer libsMux.Unlock()

	module := instrumentedLibs.AddRef(id)

	if len(closers) > 0 {
		module.Closers = append(module.Closers, closers...)
	}

	p.log.Debug("Recorded instrumented Lib", "ino", id, "module", module)
}

func (p *Tracer) AddInstrumentedLibRef(id uint64) {
	p.RecordInstrumentedLib(id, nil)
}

func (p *Tracer) UnlinkInstrumentedLib(id uint64) {
	libsMux.Lock()
	defer libsMux.Unlock()

	module, err := instrumentedLibs.RemoveRef(id)

	p.log.Debug("Unlinking instrumented lib - before state", "ino", id, "module", module)

	if err != nil {
		p.log.Debug("Error unlinking instrumented lib", "ino", id, "error", err)
	}
}

func (p *Tracer) AlreadyInstrumentedLib(id uint64) bool {
	libsMux.Lock()
	defer libsMux.Unlock()

	module := instrumentedLibs.Find(id)

	p.log.Debug("checking already instrumented Lib", "ino", id, "module", module)
	return module != nil
}

func (p *Tracer) Run(ctx context.Context, eventsChan chan<- []request.Span) {
	ebpfcommon.ForwardRingbuf(
		&p.cfg.EBPF,
		p.bpfObjects.Rb,
		&ebpfcommon.IdentityPidsFilter{},
		p.processCudaEvent,
		p.log,
		p.metrics,
		append(p.closers, &p.bpfObjects)...,
	)(ctx, eventsChan)
}

func (p *Tracer) processCudaEvent(_ *config.EBPFTracer, record *ringbuf.Record, _ ebpfcommon.ServiceFilter) (request.Span, bool, error) {
	return ReadGPUKernelLaunchIntoSpan(record)
}

func ReadGPUKernelLaunchIntoSpan(record *ringbuf.Record) (request.Span, bool, error) {
	var event GPUKernelLaunchInfo
	if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
		return request.Span{}, true, err
	}

	// Log the GPU Kernel Launch event
	slog.Debug("GPU Kernel Launch", "event", event)

	// Find the symbol for the kernel launch
	symbol, ok := symForAddr(int32(event.PidInfo.UserPid), event.PidInfo.Ns, event.KernFuncOff)
	if !ok {
		return request.Span{}, true, fmt.Errorf("failed to find symbol for kernel launch at address %d", event.KernFuncOff)
	}

	//slog.Info("GPU event", "cudaKernel", symToName(symbol))

	return request.Span{
		Type:   request.EventTypeGPUKernelLaunch,
		Method: symToName(symbol),
		Path:   callStack(&event),
	}, false, nil
}

func callStack(event *GPUKernelLaunchInfo) string {
	if event.UstackSz > 1 {
		cs := []string{}

		for i := 1; i < int(event.UstackSz); i++ {
			addr := event.Ustack[i]
			if addr != 0 {
				symbol, ok := symForAddr(int32(event.PidInfo.UserPid), event.PidInfo.Ns, event.KernFuncOff)
				if !ok {
					symbol = "<unknown>"
				} else {
					symbol = symToName(symbol)
				}

				cs = append(cs, symbol)
			}
		}

		return strings.Join(cs, " <- ")
	}

	return ""
}

func ProcessCudaLibFileInfo(info *exec.FileInfo, lib string, maps []*procfs.ProcMap) (map[int64]string, bool) {
	cudaMap := exec.LibExecPath(lib, maps)

	if cudaMap == nil {
		return nil, false
	}

	instrPath := fmt.Sprintf("/proc/%d/map_files/%x-%x", info.Pid, cudaMap.StartAddr, cudaMap.EndAddr)

	var ELF *elf.File
	var err error

	if ELF, err = elf.Open(instrPath); err != nil {
		slog.Error("can't open ELF file in", "file", instrPath, "error", err)
	}

	symAddr, err := FindSymbolAddresses(ELF)
	if err != nil {
		slog.Error("failed to find symbol addresses", "error", err)
		return nil, false
	}

	return symAddr, true
}

func ProcessCudaFileInfo(info *exec.FileInfo) {
	if _, ok := symbolsMap[info.Ino]; ok {
		EstablishCudaPID(uint32(info.Pid), info)
		return
	}

	maps, err := exec.FindLibMaps(int32(info.Pid))
	if err != nil {
		slog.Error("failed to find pid maps", "error", err)
		return
	}

	symAddr, ok := ProcessCudaLibFileInfo(info, "libtorch_cuda.so", maps)

	if !ok {
		symAddr, ok = ProcessCudaLibFileInfo(info, "libcudart.so", maps)

		if !ok {
			return
		}
	}

	slog.Info("Processing cuda symbol map for", "inode", info.Ino)

	symbolsMap[info.Ino] = symAddr
	EstablishCudaPID(uint32(info.Pid), info)
}

func EstablishCudaPID(pid uint32, fi *exec.FileInfo) {
	base, err := execBase(pid, fi)
	if err != nil {
		slog.Error("Error finding base map image", "error", err)
		return
	}

	allPids, err := exec.FindNamespacedPids(int32(pid))

	if err != nil {
		slog.Error("Error finding namespaced pids", "error", err)
		return
	}

	for _, p := range allPids {
		k := pidKey{Pid: int32(p), Ns: fi.Ns}
		baseMap[k] = base
		pidMap[k] = fi.Ino
		slog.Info("Setting pid map", "pid", pid, "base", base)
	}
}

func RemoveCudaPID(pid uint32, fi *exec.FileInfo) {
	k := pidKey{Pid: int32(pid), Ns: fi.Ns}
	delete(baseMap, k)
	delete(pidMap, k)
}

func symToName(sym string) string {
	if cleanName, err := demangle.ToString(sym); err == nil {
		return cleanName
	}

	return sym
}

func execBase(pid uint32, fi *exec.FileInfo) (uint64, error) {
	maps, err := exec.FindLibMaps(int32(pid))
	if err != nil {
		return 0, err
	}

	baseMap := exec.LibExecPath("libtorch_cuda.so", maps)
	if baseMap == nil {
		slog.Info("can't find libtorch_cuda.so in maps")
		baseMap = exec.LibExecPath(fi.CmdExePath, maps)
		if baseMap == nil {
			return 0, errors.New("can't find executable in maps, this is a bug")
		}
	}

	return uint64(baseMap.StartAddr), nil
}

func symForAddr(pid int32, ns uint32, off uint64) (string, bool) {
	k := pidKey{Pid: pid, Ns: ns}

	fInfo, ok := pidMap[k]
	if !ok {
		slog.Warn("Can't find pid info for cuda", "pid", pid, "ns", ns)
		return "", false
	}
	syms, ok := symbolsMap[fInfo]
	if !ok {
		slog.Warn("Can't find symbols for ino", "ino", fInfo)
		return "", false
	}

	base, ok := baseMap[k]
	if !ok {
		slog.Warn("Can't find basemap")
		return "", false
	}

	sym, ok := syms[int64(off)-int64(base)]
	return sym, ok
}

func collectSymbols(f *elf.File, syms []elf.Symbol, addressToName map[int64]string) {
	for _, s := range syms {
		if elf.ST_TYPE(s.Info) != elf.STT_FUNC {
			// Symbol not associated with a function or other executable code.
			continue
		}

		address := int64(s.Value)
		//fmt.Printf("Name: %s, address: %d\n", s.Name, address)
		// Loop over ELF segments.
		for _, prog := range f.Progs {
			// Skip uninteresting segments.
			if prog.Type != elf.PT_LOAD || (prog.Flags&elf.PF_X) == 0 {
				continue
			}

			if prog.Vaddr <= s.Value && s.Value < (prog.Vaddr+prog.Memsz) {
				address = int64(s.Value) - int64(prog.Vaddr)
				//fmt.Printf("\t->Name: %s, address: %d, vaddr: %d\n", s.Name, address, prog.Vaddr)
				break
			}
		}
		addressToName[address] = s.Name
	}
}

// returns a map of symbol addresses to names
func FindSymbolAddresses(f *elf.File) (map[int64]string, error) {
	addressToName := map[int64]string{}
	syms, err := f.Symbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, err
	}

	collectSymbols(f, syms, addressToName)

	dynsyms, err := f.DynamicSymbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, err
	}

	collectSymbols(f, dynsyms, addressToName)

	return addressToName, nil
}
