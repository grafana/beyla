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
	closables []io.Closer
	modules   map[uint64]struct{}
}

type processBinary struct {
	Dev     uint64
	Ino     uint64
	Path    string
	UProbes probeDescMap
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

func resolveMainBinary(ie *Instrumentable) (*processBinary, error) {
	realPath, err := os.Readlink(ie.FileInfo.ProExeLinkPath)

	if err != nil {
		return nil, err
	}

	return &processBinary{
		Dev:     ie.FileInfo.Dev,
		Ino:     ie.FileInfo.Ino,
		Path:    realPath,
		UProbes: probeDescMap{},
	}, nil
}

func NewProcessTracer(cfg *beyla.Config, tracerType ProcessTracerType, programs []Tracer) *ProcessTracer {
	return &ProcessTracer{
		log:             ptlog().With("type", tracerType),
		Programs:        programs,
		SystemWide:      cfg.Discovery.SystemWide,
		Type:            tracerType,
		Instrumentables: map[uint64]*instrumenter{},
		Bins:            common.InstrumentedBins{},
	}
}

func (pt *ProcessTracer) Run(ctx context.Context, out *msg.Queue[[]request.Span]) {
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
	ret := probeDescMap{}

	for _, p := range pt.Programs {
		for sym, probeDesc := range p.GoProbes() {
			ret[sym] = append(ret[sym], probeDesc...)
		}
	}

	return ret
}

func (pt *ProcessTracer) gatherUProbes() uProbes {
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

func (pt *ProcessTracer) resolveGoProbesOffsets(ctx *exec.ElfContext, probes probeDescMap) error {
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

		code := ctx.Data[fileOffset : fileOffset+size]

		returns, err := goexec.FindReturnOffsets(fileOffset, code)

		if err != nil {
			return fmt.Errorf("failed to parse return offsets for probe '%s': %w", f.Name, err)
		}

		for i := range probeDescArray {
			probeDescArray[i].StartOffset = fileOffset
			probeDescArray[i].ReturnOffsets = returns
		}
	}

	return nil
}

func openElf(filePath string) (*exec.ElfContext, *os.File, error) {
	file, err := os.Open(filePath)

	if err != nil {
		return nil, nil, fmt.Errorf("failed to open '%s': %w", filePath, err)
	}

	info, err := file.Stat()

	if err != nil {
		file.Close()
		return nil, nil, fmt.Errorf("failed to stat '%s': %w", filePath, err)
	}

	ctx, err := exec.NewElfContext(file, info.Size())

	if err != nil {
		file.Close()
		return nil, nil, err
	}

	return ctx, file, nil
}

func resolveUProbeOffsets(filePath string, probes probeDescMap) error {
	ctx, file, err := openElf(filePath)

	if err != nil {
		return fmt.Errorf("failed open ELF file '%s': %w", filePath, err)
	}

	defer file.Close()
	defer ctx.Close()

	return resolveUProbeOffsetsELF(ctx, probes)
}

// nolint:cyclop
func resolveUProbeOffsetsELF(ctx *exec.ElfContext, probes probeDescMap) error {
	for _, sec := range ctx.Sections {
		if sec.Type != exec.SHT_SYMTAB && sec.Type != exec.SHT_DYNSYM {
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

			code := ctx.Data[fileOffset : fileOffset+sym.Size]

			returns, err := goexec.FindReturnOffsets(fileOffset, code)

			if err != nil {
				return fmt.Errorf("failed to parse return offsets for probe '%s': %w", name, err)
			}

			for i := range probeDescArray {
				probeDescArray[i].StartOffset = fileOffset
				probeDescArray[i].ReturnOffsets = returns
			}
		}
	}

	return nil
}

// TODO move to common place alongside tcUtil ones
func findIf[T any](s []T, pred func(T) bool) *T {
	for i := range s {
		if pred(s[i]) {
			return &s[i]
		}
	}

	return nil
}

// nolint: cyclop
func gatherProcessBinaries(ie *Instrumentable) ([]processBinary, error) {
	mainBinary, err := resolveMainBinary(ie)

	if err != nil {
		return nil, fmt.Errorf("unable to resolve main binary: %w", err)
	}

	libMaps, err := exec.FindLibMaps(ie.FileInfo.Pid)

	if err != nil {
		return nil, fmt.Errorf("error loading process mappings: %w", err)
	}

	if len(libMaps) == 0 {
		return nil, fmt.Errorf("no binaries found")
	}

	binaries := make([]processBinary, 0, len(libMaps))
	binaries = append(binaries, *mainBinary)

	lastDev := uint64(0)
	lastIno := uint64(0)

	for _, m := range libMaps {
		if m.Dev == 0 || m.Inode == 0 {
			// not a file
			continue
		}

		if m.Perms == nil || !m.Perms.Execute {
			// not executable
			continue
		}

		if m.Dev == lastDev && m.Inode == lastIno {
			continue
		}

		if m.Dev == mainBinary.Dev && m.Inode == mainBinary.Ino {
			// already added main binary explicitly above
			continue
		}

		lastDev = m.Dev
		lastIno = m.Inode

		binaries = append(binaries, processBinary{Dev: m.Dev,
			Ino: m.Inode, Path: m.Pathname, UProbes: probeDescMap{}})
	}

	return binaries, nil
}

func (pt *ProcessTracer) alreadyInstrumentedBin(id uint64) bool {
	module := pt.Bins.Find(id)

	pt.log.Debug("checking already instrumented bin", "ino", id, "module", module)
	return module != nil
}

func (pt *ProcessTracer) addInstrumentedBinRef(id uint64) {
	pt.recordInstrumentedBin(id, nil)
}

func (pt *ProcessTracer) recordInstrumentedBin(id uint64, closers []io.Closer) {
	module := pt.Bins.AddRef(id)

	if len(closers) > 0 {
		module.Closers = append(module.Closers, closers...)
	}

	pt.log.Debug("Recorded instrumented bin", "ino", id, "module", module)
}

func (pt *ProcessTracer) unlinkInstrumentedBin(id uint64) {
	module, err := pt.Bins.RemoveRef(id)

	pt.log.Debug("Unlinking instrumented bin - before state", "ino", id, "module", module)

	if err != nil {
		pt.log.Debug("Error unlinking instrumented bin", "ino", id, "error", err)
	}
}

func (pt *ProcessTracer) attachGoProbes(ie *Instrumentable, i *instrumenter) error {
	if ie.Type != svc.InstrumentableGolang {
		return nil
	}

	if pt.alreadyInstrumentedBin(ie.FileInfo.Ino) {
		return nil
	}

	ctx, err := exec.NewElfContext(ie.FileInfo.File, ie.FileInfo.Size)

	if err != nil {
		return fmt.Errorf("failed to open elf context for '%s': %w", ie.FileInfo.ProExeLinkPath, err)
	}

	defer ctx.Close()

	if err := goexec.IsSupportedGoBinary(ctx); err != nil {
		return err
	}

	offsets, err := goexec.StructMemberOffsets(ie.FileInfo)

	if err != nil {
		return fmt.Errorf("failed to load go offsets: %w", err)
	}

	for _, p := range pt.Programs {
		p.RegisterOffsets(ie.FileInfo, &offsets)
	}

	goProbes := pt.gatherGoProbes()

	if len(goProbes) == 0 {
		return fmt.Errorf("no Go probes to instrument")
	}

	if err := pt.resolveGoProbesOffsets(ctx, goProbes); err != nil {
		return fmt.Errorf("error resolving Go probes offset: %w", err)
	}

	exe, err := link.OpenExecutable(ie.FileInfo.ProExeLinkPath)

	if err != nil {
		return fmt.Errorf("failed to open executable: %w", err)
	}

	closers, err := i.instrumentProbes(exe, goProbes)

	if err != nil {
		printVerifierErrorInfo(err)
		return fmt.Errorf("failed to attach go probes: %w", err)
	}

	i.addModule(ie.FileInfo.Ino)
	pt.recordInstrumentedBin(ie.FileInfo.Ino, closers)
	pt.Instrumentables[ie.FileInfo.Ino] = i

	return nil
}

// assigns uprobes to binaries, or to the main binary in case static linkage
// is suspected
func resolveBinProbes(uProbes uProbes, binaries []processBinary) {
	if len(binaries) == 0 {
		return
	}

	// the process main binary is always first
	mainBinary := &binaries[0]

	// if a shared library is not present, reassign its uprobes to the main
	// binary in case they are statically linked
	for fileName, uProbe := range uProbes {
		binary := findIf(binaries, func(p processBinary) bool {
			return strings.HasPrefix(filepath.Base(p.Path), fileName)
		})

		if binary == nil {
			binary = mainBinary
		}

		for k, v := range uProbe {
			binary.UProbes[k] = v
		}
	}
}

func (pt *ProcessTracer) attachUProbes(ie *Instrumentable, i *instrumenter) error {
	uProbes := pt.gatherUProbes()

	if len(uProbes) == 0 {
		return nil
	}

	binaries, err := gatherProcessBinaries(ie)

	if err != nil {
		return err
	}

	if len(binaries) == 0 {
		return fmt.Errorf("no binaries to instrument")
	}

	resolveBinProbes(uProbes, binaries)

	binAbsPath := func(b *processBinary) string {
		return fmt.Sprintf("/proc/%d/root%s", ie.FileInfo.Pid, b.Path)
	}

	for _, binary := range binaries {
		if len(binary.UProbes) == 0 {
			continue
		}

		if pt.alreadyInstrumentedBin(binary.Ino) {
			pt.log.Debug("module already instrumented by other processes, incrementing reference count",
				"path", binary.Path, "ino", binary.Ino)

			i.addModule(binary.Ino)
			pt.addInstrumentedBinRef(binary.Ino)
			continue
		}

		absPath := binAbsPath(&binary)

		targetExe, err := link.OpenExecutable(absPath)

		if err != nil {
			return fmt.Errorf("failed to open binary %s: %w", absPath, err)
		}

		if err := resolveUProbeOffsets(absPath, binary.UProbes); err != nil {
			return fmt.Errorf("failed to resolve uprobe offsets: %w", err)
		}

		closers, err := i.instrumentProbes(targetExe, binary.UProbes)

		if err != nil {
			printVerifierErrorInfo(err)
			return fmt.Errorf("failed to attach uprobes: %w", err)
		}

		i.addModule(binary.Ino)
		pt.recordInstrumentedBin(binary.Ino, closers)
	}

	pt.Instrumentables[ie.FileInfo.Ino] = i

	return nil
}

func (pt *ProcessTracer) NewExecutable(ie *Instrumentable) error {
	i := instrumenter{
		modules: map[uint64]struct{}{},
	}

	if pt.Type == Go {
		if err := pt.attachGoProbes(ie, &i); err != nil {
			return fmt.Errorf("failed to attach Go probes: %w", err)
		}
	} else {
		if err := pt.attachUProbes(ie, &i); err != nil {
			return fmt.Errorf("failed to attach uprobes: %w", err)
		}
	}

	return nil
}

func (pt *ProcessTracer) UnlinkExecutable(info *exec.FileInfo) {
	if i, ok := pt.Instrumentables[info.Ino]; ok {
		for ino := range i.modules {
			pt.unlinkInstrumentedBin(ino)
		}

		// if all references to this executables are gone, we can delete the
		// instrumentable (i.e. if all instances of this executable are dead)
		if pt.Bins.Find(info.Ino) == nil {
			delete(pt.Instrumentables, info.Ino)
		}
	} else {
		pt.log.Warn("Unable to find executable to unlink",
			"path", info.CmdExePath,
			"pid", info.Pid,
			"inode", info.Ino)
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
