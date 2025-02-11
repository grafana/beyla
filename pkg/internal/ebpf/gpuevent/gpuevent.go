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

	"github.com/grafana/beyla/v2/pkg/beyla"
	"github.com/grafana/beyla/v2/pkg/config"
	ebpfcommon "github.com/grafana/beyla/v2/pkg/internal/ebpf/common"
	"github.com/grafana/beyla/v2/pkg/internal/exec"
	"github.com/grafana/beyla/v2/pkg/internal/goexec"
	"github.com/grafana/beyla/v2/pkg/internal/imetrics"
	"github.com/grafana/beyla/v2/pkg/internal/request"
	"github.com/grafana/beyla/v2/pkg/internal/svc"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type gpu_kernel_launch_t -type gpu_malloc_t -target amd64,arm64 bpf ../../../../bpf/gpuevent.c -- -I../../../../bpf/headers
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type gpu_kernel_launch_t -type gpu_malloc_t -target amd64,arm64 bpf_debug ../../../../bpf/gpuevent.c -- -I../../../../bpf/headers -DBPF_DEBUG

const EventTypeKernelLaunch = 1 // EVENT_GPU_KERNEL_LAUNCH
const EventTypeMalloc = 2       // EVENT_GPU_MALLOC

type pidKey struct {
	Pid int32
	Ns  uint32
}

type modInfo struct {
	base uint64
	end  uint64
	ino  uint64
}

type moduleOffsets map[uint64]*SymbolTree

type GPUKernelLaunchInfo bpfGpuKernelLaunchT
type GPUMallocInfo bpfGpuMallocT

// TODO: We have a way to bring ELF file information to this Tracer struct
// via the newNonGoTracersGroup / newNonGoTracersGroupUProbes functions. Now,
// we need to figure out how to pass it to the SharedRingbuf.. not sure if thats
// possible
type Tracer struct {
	pidsFilter       ebpfcommon.ServiceFilter
	cfg              *beyla.Config
	metrics          imetrics.Reporter
	bpfObjects       bpfObjects
	closers          []io.Closer
	log              *slog.Logger
	instrumentedLibs ebpfcommon.InstrumentedLibsT
	libsMux          sync.Mutex
	pidMap           map[pidKey]uint64
	symbolsMap       map[uint64]moduleOffsets
	baseMap          map[pidKey][]modInfo
}

func New(cfg *beyla.Config, metrics imetrics.Reporter) *Tracer {
	log := slog.With("component", "gpuevent.Tracer")

	return &Tracer{
		log:              log,
		cfg:              cfg,
		metrics:          metrics,
		pidsFilter:       ebpfcommon.CommonPIDsFilter(&cfg.Discovery),
		instrumentedLibs: make(ebpfcommon.InstrumentedLibsT),
		libsMux:          sync.Mutex{},
		pidMap:           map[pidKey]uint64{},
		symbolsMap:       map[uint64]moduleOffsets{},
		baseMap:          map[pidKey][]modInfo{},
	}
}

func (p *Tracer) AllowPID(pid, ns uint32, svc *svc.Attrs) {
	p.pidsFilter.AllowPID(pid, ns, svc, ebpfcommon.PIDTypeKProbes)
}

func (p *Tracer) BlockPID(pid, ns uint32) {
	p.pidsFilter.BlockPID(pid, ns)
	p.removeCudaPID(pid, ns)
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
		p.processCudaFileInfo(fileInfo)
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
			"cudaMalloc": {{
				Start: p.bpfObjects.HandleCudaMalloc,
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
	p.libsMux.Lock()
	defer p.libsMux.Unlock()

	module := p.instrumentedLibs.AddRef(id)

	if len(closers) > 0 {
		module.Closers = append(module.Closers, closers...)
	}

	p.log.Debug("Recorded instrumented Lib", "ino", id, "module", module)
}

func (p *Tracer) AddInstrumentedLibRef(id uint64) {
	p.RecordInstrumentedLib(id, nil)
}

func (p *Tracer) UnlinkInstrumentedLib(id uint64) {
	p.libsMux.Lock()
	defer p.libsMux.Unlock()

	delete(p.symbolsMap, id)

	module, err := p.instrumentedLibs.RemoveRef(id)

	p.log.Debug("Unlinking instrumented lib - before state", "ino", id, "module", module)

	if err != nil {
		p.log.Debug("Error unlinking instrumented lib", "ino", id, "error", err)
	}
}

func (p *Tracer) AlreadyInstrumentedLib(id uint64) bool {
	p.libsMux.Lock()
	defer p.libsMux.Unlock()

	module := p.instrumentedLibs.Find(id)

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
	var eventType uint8

	// we read the type first, depending on the type we decide what kind of record we have
	err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &eventType)
	if err != nil {
		return request.Span{}, true, err
	}

	switch eventType {
	case EventTypeKernelLaunch:
		return p.readGPUKernelLaunchIntoSpan(record)
	case EventTypeMalloc:
		return p.readGPUMallocIntoSpan(record)
	default:
		p.log.Error("unknown cuda event")
	}

	return request.Span{}, false, nil
}

func (p *Tracer) readGPUMallocIntoSpan(record *ringbuf.Record) (request.Span, bool, error) {
	var event GPUMallocInfo
	if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
		return request.Span{}, true, err
	}

	// Log the GPU Kernel Launch event
	p.log.Debug("GPU Malloc", "event", event)

	return request.Span{
		Type:          request.EventTypeGPUMalloc,
		ContentLength: int64(event.Size),
	}, false, nil
}

func (p *Tracer) readGPUKernelLaunchIntoSpan(record *ringbuf.Record) (request.Span, bool, error) {
	var event GPUKernelLaunchInfo
	if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
		return request.Span{}, true, err
	}

	// Log the GPU Kernel Launch event
	p.log.Info("GPU Kernel Launch", "event", event)

	// Find the symbol for the kernel launch
	symbol, ok := p.symForAddr(int32(event.PidInfo.UserPid), event.PidInfo.Ns, event.KernFuncOff)
	if !ok {
		return request.Span{}, true, fmt.Errorf("failed to find symbol for kernel launch at address %d, pid %d", event.KernFuncOff, event.PidInfo.UserPid)
	}

	return request.Span{
		Type:   request.EventTypeGPUKernelLaunch,
		Method: p.symToName(symbol),
		Path:   p.callStack(&event),
	}, false, nil
}

func (p *Tracer) callStack(event *GPUKernelLaunchInfo) string {
	if event.UstackSz > 1 {
		cs := []string{}

		for i := 0; i < int(event.UstackSz); i++ {
			addr := event.Ustack[i]
			if addr != 0 {
				symbol, ok := p.symForAddr(int32(event.PidInfo.UserPid), event.PidInfo.Ns, addr)
				if ok {
					symbol = p.symToName(symbol)
					cs = append(cs, symbol)
				}
			}
		}

		return strings.Join(cs, ";")
	}

	return ""
}

func (p *Tracer) processCudaLibFileInfo(info *exec.FileInfo, lib string, maps []*procfs.ProcMap, symMods moduleOffsets) (*SymbolTree, *procfs.ProcMap, bool) {
	cudaMap := exec.LibPathPlain(lib, maps)

	if cudaMap == nil {
		return nil, nil, false
	}

	if _, ok := symMods[cudaMap.Inode]; ok {
		return nil, cudaMap, false
	}

	instrPath := fmt.Sprintf("/proc/%d/map_files/%x-%x", info.Pid, cudaMap.StartAddr, cudaMap.EndAddr)

	var ELF *elf.File
	var err error

	if ELF, err = elf.Open(instrPath); err != nil {
		p.log.Error("can't open ELF file in", "file", instrPath, "error", err)
	}

	p.log.Debug("Processing symbols", "path", cudaMap.Pathname)

	symAddr, err := p.findSymbolAddresses(ELF)
	if err != nil {
		p.log.Error("failed to find symbol addresses", "error", err)
		return nil, nil, false
	}

	return symAddr, cudaMap, true
}

func (p *Tracer) discoverModule(info *exec.FileInfo, maps []*procfs.ProcMap, symModules moduleOffsets, path string) *procfs.ProcMap {
	symAddr, mod, ok := p.processCudaLibFileInfo(info, path, maps, symModules)
	if ok {
		symModules[mod.Inode] = symAddr
	}

	return mod
}

func (p *Tracer) processCudaFileInfo(info *exec.FileInfo) {
	maps, err := exec.FindLibMaps(int32(info.Pid))
	if err != nil {
		p.log.Error("failed to find pid maps", "error", err)
		return
	}

	p.log.Info("Processing CUDA symbols for", "pid", info.Pid, "ns", info.Ns)

	disovered := []*procfs.ProcMap{}
	symModules, ok := p.symbolsMap[info.Ino]
	if !ok {
		symModules = moduleOffsets{}
	}

	p.log.Debug("Sym modules have", "count", len(symModules))

	if mod := p.discoverModule(info, maps, symModules, info.CmdExePath); mod != nil {
		disovered = append(disovered, mod)
	}

	if mod := p.discoverModule(info, maps, symModules, "libtorch_cuda.so"); mod != nil {
		disovered = append(disovered, mod)
	}

	for _, m := range maps {
		if strings.Contains(m.Pathname, "/vllm") {
			if mod := p.discoverModule(info, maps, symModules, m.Pathname); mod != nil {
				disovered = append(disovered, mod)
			}
		}
		if strings.Contains(m.Pathname, "/ggml") {
			if mod := p.discoverModule(info, maps, symModules, m.Pathname); mod != nil {
				disovered = append(disovered, mod)
			}
		}
	}

	p.log.Debug("Processing cuda symbol map for", "inode", info.Ino)
	for k := range symModules {
		p.log.Debug("Found symbols for", "inode", k)
	}

	p.log.Debug("Sym modules have", "count", len(symModules))

	p.symbolsMap[info.Ino] = symModules
	if len(disovered) > 0 {
		p.establishCudaPID(uint32(info.Pid), info, disovered)
	}
}

func (p *Tracer) establishCudaPID(pid uint32, fi *exec.FileInfo, mods []*procfs.ProcMap) {
	bases, err := p.modulesAddressInfos(pid, mods)
	if err != nil {
		p.log.Error("Error finding base map image", "error", err)
		return
	}

	allPids, err := exec.FindNamespacedPids(int32(pid))

	if err != nil {
		p.log.Error("Error finding namespaced pids", "error", err)
		return
	}

	for _, nsPid := range allPids {
		k := pidKey{Pid: int32(nsPid), Ns: fi.Ns}
		p.baseMap[k] = bases
		p.pidMap[k] = fi.Ino
		p.log.Debug("Setting pid map", "pid", pid, "bases", bases)
	}
}

func (p *Tracer) removeCudaPID(pid uint32, ns uint32) {
	k := pidKey{Pid: int32(pid), Ns: ns}
	delete(p.baseMap, k)
	delete(p.pidMap, k)
}

func (p *Tracer) symToName(sym string) string {
	if cleanName, err := demangle.ToString(sym); err == nil {
		return cleanName
	}

	return sym
}

func (p *Tracer) modulesAddressInfos(pid uint32, mods []*procfs.ProcMap) ([]modInfo, error) {
	res := []modInfo{}

	for _, mod := range mods {
		res = append(res, modInfo{
			base: uint64(mod.StartAddr),
			end:  uint64(mod.EndAddr),
			ino:  mod.Inode,
		})
	}

	p.log.Debug("added", "mods", res, "pid", pid)

	if len(res) == 0 {
		return nil, errors.New("can't find any CUDA libraries in path")
	}

	return res, nil
}

func (p *Tracer) symForAddr(pid int32, ns uint32, off uint64) (string, bool) {
	k := pidKey{Pid: pid, Ns: ns}

	fInfo, ok := p.pidMap[k]
	if !ok {
		p.log.Warn("Can't find pid info for cuda", "pid", pid, "ns", ns)
		return "", false
	}
	syms, ok := p.symbolsMap[fInfo]
	if !ok {
		p.log.Warn("Can't find symbols for ino", "ino", fInfo)
		return "", false
	}

	base, ok := p.baseMap[k]
	if !ok {
		p.log.Warn("Can't find basemap")
		return "", false
	}

	for i := range base {
		m := &base[i]
		if off > m.base && off < m.end {
			modSyms, ok := syms[m.ino]
			if ok {
				res := modSyms.Search(off - m.base)
				if len(res) > 0 {
					return res[0].Symbol, true
				}
				return "", false
			} else {
				p.log.Warn("Can't find mod sym for", "ino", m.ino)
			}
		}
	}

	return "", false
}

func (p *Tracer) collectSymbols(f *elf.File, syms []elf.Symbol, tree *SymbolTree) {
	for _, s := range syms {
		if elf.ST_TYPE(s.Info) != elf.STT_FUNC {
			// Symbol not associated with a function or other executable code.
			continue
		}

		address := s.Value
		// Loop over ELF segments.
		for _, prog := range f.Progs {
			// Skip uninteresting segments.
			if prog.Type != elf.PT_LOAD || (prog.Flags&elf.PF_X) == 0 {
				continue
			}

			if prog.Vaddr <= s.Value && s.Value < (prog.Vaddr+prog.Memsz) {
				address = s.Value - prog.Vaddr
				break
			}
		}
		if address != 0 {
			tree.Insert(Symbol{Low: address, High: address + s.Size, Symbol: s.Name})
		}
	}
}

// returns a map of symbol addresses to names
func (p *Tracer) findSymbolAddresses(f *elf.File) (*SymbolTree, error) {
	t := SymbolTree{}
	syms, err := f.Symbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, err
	}

	p.collectSymbols(f, syms, &t)

	dynsyms, err := f.DynamicSymbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, err
	}

	p.collectSymbols(f, dynsyms, &t)

	return &t, nil
}
