package ebpf

import (
	"context"
	"debug/gosym"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"

	"github.com/grafana/beyla/v2/pkg/beyla"
	common "github.com/grafana/beyla/v2/pkg/internal/ebpf/common"
	convenience "github.com/grafana/beyla/v2/pkg/internal/ebpf/convenience"
	"github.com/grafana/beyla/v2/pkg/internal/exec"
	"github.com/grafana/beyla/v2/pkg/internal/goexec"
	"github.com/grafana/beyla/v2/pkg/internal/request"
	"github.com/grafana/beyla/v2/pkg/internal/svc"
	"github.com/grafana/beyla/v2/pkg/pipe/msg"
)

const PinInternal = ebpf.PinType(100)

var loadMux sync.Mutex

var internalMaps = make(map[string]*ebpf.Map)
var internalMapsMux sync.Mutex

func ptlog() *slog.Logger { return slog.With("component", "ebpf.ProcessTracer") }

type instrumenter struct {
	exe       *link.Executable
	closables []io.Closer
	modules   map[uint64]struct{}
}

func roundToNearestMultiple(x, n uint32) uint32 {
	if x < n {
		return n
	}

	if x%n == 0 {
		return x
	}

	return (x + n/2) / n * n
}

// RingBuf map types must be a multiple of os.Getpagesize()
func alignMaxEntriesIfRingBuf(m *ebpf.MapSpec) {
	if m.Type == ebpf.RingBuf {
		m.MaxEntries = roundToNearestMultiple(m.MaxEntries, uint32(os.Getpagesize()))
	}
}

// sets up internal maps and ensures sane max entries values
func resolveMaps(spec *ebpf.CollectionSpec) (*ebpf.CollectionOptions, error) {
	collOpts := ebpf.CollectionOptions{MapReplacements: map[string]*ebpf.Map{}}

	internalMapsMux.Lock()
	defer internalMapsMux.Unlock()

	for k, v := range spec.Maps {
		alignMaxEntriesIfRingBuf(v)

		if v.Pinning != PinInternal {
			continue
		}

		v.Pinning = ebpf.PinNone
		internalMap := internalMaps[k]

		var err error

		if internalMap == nil {
			internalMap, err = ebpf.NewMap(v)

			if err != nil {
				return nil, fmt.Errorf("failed to load shared map: %w", err)
			}

			internalMaps[k] = internalMap
			runtime.SetFinalizer(internalMap, (*ebpf.Map).Close)
		}

		collOpts.MapReplacements[k] = internalMap
	}

	return &collOpts, nil
}

func NewProcessTracer(cfg *beyla.Config, tracerType ProcessTracerType, programs []Tracer) *ProcessTracer {
	return &ProcessTracer{
		Programs:        programs,
		SystemWide:      cfg.Discovery.SystemWide,
		Type:            tracerType,
		Instrumentables: map[uint64]*instrumenter{},
		Instrumented:    map[FileID]struct{}{},
	}
}

func (pt *ProcessTracer) Run(ctx context.Context, out *msg.Queue[[]request.Span]) {
	pt.log = ptlog().With("type", pt.Type)

	pt.log.Debug("starting process tracer")
	// Searches for traceable functions
	trcrs := pt.Programs

	wg := sync.WaitGroup{}

	for _, t := range trcrs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			t.Run(ctx, out)
		}()
	}

	<-ctx.Done()

	wg.Wait()
}

func (pt *ProcessTracer) loadSpec(p Tracer) (*ebpf.CollectionSpec, error) {
	spec, err := p.Load()
	if err != nil {
		return nil, fmt.Errorf("loading eBPF program: %w", err)
	}
	if err := convenience.RewriteConstants(spec, p.Constants()); err != nil {
		return nil, fmt.Errorf("rewriting BPF constants definition: %w", err)
	}

	return spec, nil
}

func (pt *ProcessTracer) loadAndAssign(p Tracer) error {
	spec, err := pt.loadSpec(p)

	if err != nil {
		return err
	}

	collOpts, err := resolveMaps(spec)

	if err != nil {
		return err
	}

	collOpts.Programs = ebpf.ProgramOptions{LogSizeStart: 640 * 1024}

	return spec.LoadAndAssign(p.BpfObjects(), collOpts)
}

func (pt *ProcessTracer) loadTracer(p Tracer, log *slog.Logger) error {
	plog := log.With("program", reflect.TypeOf(p))
	plog.Debug("loading eBPF program", "type", pt.Type)

	err := pt.loadAndAssign(p)

	if err != nil && strings.Contains(err.Error(), "unknown func bpf_probe_write_user") {
		plog.Warn("Failed to enable Go write memory distributed tracing context-propagation on a " +
			"Linux Kernel without write memory support. " +
			"To avoid seeing this message, please ensure you have correctly mounted /sys/kernel/security. " +
			"and ensure beyla has the SYS_ADMIN linux capability. " +
			"For more details set BEYLA_LOG_LEVEL=DEBUG.")

		common.IntegrityModeOverride = true
		err = pt.loadAndAssign(p)
	}

	if err != nil {
		printVerifierErrorInfo(err)
		return fmt.Errorf("loading and assigning BPF objects: %w", err)
	}

	// Setup any tail call jump tables
	p.SetupTailCalls()

	i := instrumenter{} // dummy instrumenter to setup the kprobes, socket filters and tracepoint probes

	// Kprobes to be used for native instrumentation points
	if err := i.kprobes(p); err != nil {
		printVerifierErrorInfo(err)
		return err
	}

	// Tracepoints support
	if err := i.tracepoints(p); err != nil {
		printVerifierErrorInfo(err)
		return err
	}

	// Sock filters support
	if err := i.sockfilters(p); err != nil {
		printVerifierErrorInfo(err)
		return err
	}

	// Sock_msg support
	if err := i.sockmsgs(p); err != nil {
		printVerifierErrorInfo(err)
		return err
	}

	// Sockops support
	if err := i.sockops(p); err != nil {
		printVerifierErrorInfo(err)
		return err
	}

	return nil
}

func (pt *ProcessTracer) loadTracers() error {
	loadMux.Lock()
	defer loadMux.Unlock()

	var log = ptlog()

	for _, p := range pt.Programs {
		if err := pt.loadTracer(p, log); err != nil {
			return err
		}
	}

	btf.FlushKernelSpec()

	return nil
}

func (pt *ProcessTracer) Init() error {
	return pt.loadTracers()
}

type probeDescMap map[string][]*common.ProbeDesc
type uProbes map[string]probeDescMap

func (pt *ProcessTracer) gatherGoProbes() probeDescMap {
	start := time.Now()

	defer func() {
		elapsed := time.Since(start)
		fmt.Printf("gatherGoProbes %v us\n", elapsed.Microseconds())
	}()

	ret := probeDescMap{}

	for _, p := range pt.Programs {
		for sym, probeDesc := range p.GoProbes() {
			ret[sym] = append(ret[sym], probeDesc...)
		}
	}

	return ret
}

func (pt *ProcessTracer) gatherUProbes() uProbes {
	start := time.Now()

	defer func() {
		elapsed := time.Since(start)
		fmt.Printf("gatherUProbes %v us\n", elapsed.Microseconds())
	}()

	ret := uProbes{}

	for _, p := range pt.Programs {
		for binFile, probes := range p.UProbes() {
			target, ok := ret[binFile]

			if !ok {
				target = map[string][]*common.ProbeDesc{}
				ret[binFile] = target
			}

			for sym, probeDesc := range probes {
				target[sym] = append(target[sym], probeDesc...)
			}
		}
	}

	return ret
}

func resolveGoSymTable(ctx *exec.ElfContext) (*gosym.Table, error) {
	shstrtab := ctx.Sections[ctx.Hdr.Shstrndx]
	shstrtabData := ctx.Data[shstrtab.Offset:]

	var pclndat []byte
	var runtimeText uint64

	for _, sec := range ctx.Sections {
		name := exec.GetCString(shstrtabData, sec.Name)

		if name == ".gopclntab" {
			pclndat = ctx.Data[sec.Offset:]
			ptrSize := uint32(pclndat[7])

			switch ptrSize {
			case 4:
				runtimeText = uint64(*exec.ReadStruct[uint32](pclndat, int(8+2*ptrSize)))
			case 8:
				runtimeText = *exec.ReadStruct[uint64](pclndat, int(8+2*ptrSize))
			default:
				return nil, fmt.Errorf("unknown pointer size")
			}
		} else if runtimeText == 0 && name == ".text" {
			runtimeText = sec.Addr
		}
	}

	if runtimeText == 0 {
		return nil, fmt.Errorf("could not find text section")
	}

	pcln := gosym.NewLineTable(pclndat, runtimeText)
	return gosym.NewTable(nil, pcln)
}

func (pt *ProcessTracer) resolveGoProbesOffsets(file *exec.FileInfo, probes probeDescMap) error {
	start := time.Now()

	defer func() {
		elapsed := time.Since(start)
		fmt.Printf("resolveGoProbesOffsets took %v us\n", elapsed.Microseconds())
	}()

	ctx, err := exec.NewElfContext(file.File, file.Size)

	if err != nil {
		return err
	}

	defer ctx.Close()

	symTab, err := resolveGoSymTable(ctx)

	if err != nil {
		return fmt.Errorf("error loading go sym table: %w", err)
	}

	for _, f := range symTab.Funcs {
		probeDescArray, ok := probes[f.Name]

		if !ok {
			continue
		}

		var fileOffset uint64

		found := false

		for _, seg := range ctx.Segments {
			if seg.Type == 1 && f.Value >= seg.Vaddr && f.Value < seg.Vaddr+seg.Filesz {
				offsetInSegment := f.Value - seg.Vaddr
				fileOffset = seg.Offset + offsetInSegment
				found = true
				break
			}
		}

		size := f.End - f.Value

		if !found || fileOffset+size > uint64(len(ctx.Data)) {
			continue
		}

		returns := []uint64{}

		code := ctx.Data[fileOffset : fileOffset+size]

		for j, b := range code {
			if b == 0xC3 {
				returns = append(returns, uint64(j))
			}
		}

		for i := range probeDescArray {
			probeDescArray[i].StartOffset = fileOffset
			probeDescArray[i].ReturnOffsets = returns
		}
	}

	return nil
}

func (pt *ProcessTracer) resolveUProbeOffsets(filePath string, probes probeDescMap) error {
	start := time.Now()

	defer func() {
		elapsed := time.Since(start)
		fmt.Printf("resolveUProbeOffsets took %v us\n", elapsed.Microseconds())
	}()

	file, err := os.Open(filePath)

	if err != nil {
		return fmt.Errorf("failed to open '%s': %w", filePath, err)
	}

	defer file.Close()

	info, err := file.Stat()

	if err != nil {
		return fmt.Errorf("failed to stat '%s': %w", filePath, err)
	}

	ctx, err := exec.NewElfContext(file, info.Size())

	if err != nil {
		return err
	}

	defer ctx.Close()

	for _, sec := range ctx.Sections {
		if sec.Type != exec.SYMTAB && sec.Type != exec.DYNSYM {
			continue
		}

		strtab := ctx.Sections[sec.Link]
		strs := ctx.Data[strtab.Offset:]

		symCount := int(sec.Size / sec.Entsize)

		for i := 0; i < symCount; i++ {
			sym := exec.ReadStruct[exec.Elf64_Sym](ctx.Data, int(sec.Offset)+i*int(sec.Entsize))

			if sym == nil || exec.SymType(sym.Info) != exec.STT_FUNC || sym.Size == 0 || sym.Value == 0 {
				continue
			}

			var fileOffset uint64

			found := false

			for _, seg := range ctx.Segments {
				if seg.Type == 1 && sym.Value >= seg.Vaddr && sym.Value < seg.Vaddr+seg.Filesz {
					offsetInSegment := sym.Value - seg.Vaddr
					fileOffset = seg.Offset + offsetInSegment
					found = true
					break
				}
			}

			if !found || fileOffset+sym.Size > uint64(len(ctx.Data)) {
				continue
			}

			name := exec.GetCStringUnsafe(strs, sym.Name)

			probeDescArray, ok := probes[name]

			if !ok {
				continue
			}

			returns := []uint64{}

			code := ctx.Data[fileOffset : fileOffset+sym.Size]

			for j, b := range code {
				if b == 0xC3 {
					returns = append(returns, uint64(j))
				}
			}

			for i := range probeDescArray {
				probeDescArray[i].StartOffset = fileOffset
				probeDescArray[i].ReturnOffsets = returns
			}
		}
	}

	return nil
}

func (pt *ProcessTracer) NewExecutable(exe *link.Executable, ie *Instrumentable) error {
	i := instrumenter{
		exe:     exe,
		modules: map[uint64]struct{}{},
	}

	fmt.Printf("New executable for: %v\n", ie.Type)

	if ie.Type == svc.InstrumentableGolang {
		//TODO check for goproxy
		offsets, err := goexec.StructMemberOffsets(ie.FileInfo)

		if err != nil {
			return fmt.Errorf("failed to load go offsets: %w", err)
		}

		for _, p := range pt.Programs {
			p.RegisterOffsets(ie.FileInfo, &offsets)
		}

		goProbes := pt.gatherGoProbes()

		if len(goProbes) == 0 {
			fmt.Errorf("no Go probes to instrument")
		}

		if err := pt.resolveGoProbesOffsets(ie.FileInfo, goProbes); err != nil {
			return fmt.Errorf("error resolving Go probes offset: %w", err)
		}

		closers, err := i.instrumentProbes(exe, goProbes)

		if err != nil {
			printVerifierErrorInfo(err)
			return fmt.Errorf("Failed to attach go probes: %w", err)
		}

		// TODO revisit this closable mess
		i.closables = append(i.closables, closers...)

		for _, p := range pt.Programs {
			p.AddCloser(i.closables...)
		}
	}

	uProbes := pt.gatherUProbes()

	fmt.Printf("uProbes: %v\n", uProbes)

	libMaps, err := exec.FindLibMaps(ie.FileInfo.Pid)

	if err != nil {
		return fmt.Errorf("error loading process mappings: %w", err)
	}

	//FIXME we need to try to instrument the shared library first, but if it
	//fails, we need to try the same symbol in the main binary in case it's
	//been statically linked
	for _, m := range libMaps {
		if len(m.Pathname) == 0 {
			continue
		}

		fileID := FileID{Dev: m.Dev, Ino: m.Inode, Pid: ie.FileInfo.Pid}

		if _, ok := pt.Instrumented[fileID]; ok {
			continue
		}

		baseName := filepath.Base(m.Pathname)

		uProbe, ok := uProbes[baseName]

		if !ok {
			continue
		}

		absPath := fmt.Sprintf("/proc/%d/root%s", ie.FileInfo.Pid, m.Pathname)

		pt.resolveUProbeOffsets(absPath, uProbe)

		closers, err := i.instrumentProbes(exe, uProbe)

		if err != nil {
			printVerifierErrorInfo(err)
			return fmt.Errorf("Failed to attach go probes: %w", err)
		}

		// TODO revisit this closable mess
		i.closables = append(i.closables, closers...)

		for _, p := range pt.Programs {
			p.AddCloser(i.closables...)
		}

		pt.Instrumented[fileID] = struct{}{}
	}

	pt.Instrumentables[ie.FileInfo.Ino] = &i

	return nil
}

func (pt *ProcessTracer) UnlinkExecutable(info *exec.FileInfo) {
	if i, ok := pt.Instrumentables[info.Ino]; ok {
		for _, c := range i.closables {
			if err := c.Close(); err != nil {
				pt.log.Debug("Unable to close on unlink", "closable", c)
			}
		}
		for ino := range i.modules {
			for _, p := range pt.Programs {
				p.UnlinkInstrumentedLib(ino)
			}
		}
		delete(pt.Instrumentables, info.Ino)
	} else {
		pt.log.Warn("Unable to find executable to unlink", "info", info)
	}
}

func printVerifierErrorInfo(err error) {
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		_, _ = fmt.Fprintf(os.Stderr, "Error Log:\n %v\n", strings.Join(ve.Log, "\n"))
	}
}

func RunUtilityTracer(p UtilityTracer) error {
	i := instrumenter{}
	plog := ptlog()
	plog.Debug("loading independent eBPF program")
	spec, err := p.Load()
	if err != nil {
		return fmt.Errorf("loading eBPF program: %w", err)
	}

	collOpts, err := resolveMaps(spec)
	if err != nil {
		return err
	}

	if err := spec.LoadAndAssign(p.BpfObjects(), collOpts); err != nil {
		printVerifierErrorInfo(err)
		return fmt.Errorf("loading and assigning BPF objects: %w", err)
	}

	if err := i.kprobes(p); err != nil {
		printVerifierErrorInfo(err)
		return err
	}

	if err := i.tracepoints(p); err != nil {
		printVerifierErrorInfo(err)
		return err
	}

	go p.Run(context.Background())

	btf.FlushKernelSpec()

	return nil
}
