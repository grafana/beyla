// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package runtime // import "go.opentelemetry.io/obi/pkg/internal/cpython/runtime"

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"math"
	"os"

	"github.com/prometheus/procfs"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

// frameOwnerNone never matches a frame owner: 3.11 has no C-stack shim frames.
const frameOwnerNone = 0xff

const (
	typeBasicSizeOffset = 32
	// PyBaseExceptionObject.traceback, after PyObject_HEAD, dict, args and notes.
	exceptionTracebackOffset = 40
	// PyCompactUnicodeObject adds utf8_length and utf8 to PyASCIIObject on 3.12+.
	compactUnicodeExtra = 16
	// _PyInterpreterFrame fields fit in 80 bytes on 3.11+.
	interpreterFrameReadSize = 80
	// PyFrameObject.f_frame on 3.11+.
	frameObjectFrameOffset = 24
	// _PyErr_StackItem.exc_value and previous_item on 3.11+; 3.9 and 3.10
	// also keep the type and traceback.
	errItemValueOffset    = 0
	errItemPreviousOffset = 8
)

// ExceptionLayout holds the CPython offsets and object addresses of one process
// that the exception probe and the symbolizer read. It mirrors python_exception_proc_t.
type ExceptionLayout struct {
	Minor     uint8
	TypeFlags uint8

	MainInterpreter    uint64
	CodeType           uint64
	UnicodeType        uint64
	TupleType          uint64
	StopIteration      uint64
	StopAsyncIteration uint64
	GeneratorExit      uint64

	TstateInterp       uint8
	TstateFrame        uint8
	CFrameCurrentFrame uint8
	FrameIsCFrame      bool
	FrameCode          uint8
	FramePrevious      uint8
	FrameInstr         uint8
	FrameOwner         uint8
	FrameOwnerCStack   uint8

	CodeAdaptive    uint16
	CodeFilename    uint8
	CodeName        uint8
	CodeLinetable   uint8
	CodeFirstlineno uint8

	TupleItems         uint8
	UnicodeASCIIData   uint8
	UnicodeCompactData uint8
	ExceptionTraceback uint8

	FrameReadSize    uint8
	FrameLastiInt    bool
	FrameLastiBytes  bool
	FrameObjectFrame uint8

	TstateExcInfo   uint8
	ErrItemValue    uint8
	ErrItemPrevious uint8

	interpretersMain uint64
}

// ExceptionTarget locates the _PyErr_SetObject entry of one process.
type ExceptionTarget struct {
	ProbeOffset uint64
	Layout      ExceptionLayout
	attachment  *os.File
}

// AttachmentPath returns a stable path for link.OpenExecutable.
func (t *ExceptionTarget) AttachmentPath() string {
	return fmt.Sprintf("/proc/self/fd/%d", t.attachment.Fd())
}

// Close releases the mapped object after attachment finishes.
func (t *ExceptionTarget) Close() error {
	return t.attachment.Close()
}

// debugExceptionFields holds the positions of the _Py_DebugOffsets fields the
// exception probe uses, and the C-stack frame owner and PyThreadState.exc_info,
// which _Py_DebugOffsets does not publish; all are fixed per minor.
type debugExceptionFields struct {
	size                                                   int
	interpretersHead, tstateInterp, tstateFrame            int
	framePrevious, frameCode, frameInstr, frameOwner       int
	codeFilename, codeName, codeLinetable, codeFirstlineno int
	codeAdaptive, tupleItems, unicodeASCIISize             int
	frameOwnerCStack, tstateExcInfo                        uint8
}

var exceptionSymbols = []string{
	"_PyRuntime", "Py_Version", "PyCode_Type", "PyUnicode_Type", "PyTuple_Type",
	"PyExc_StopIteration", "PyExc_StopAsyncIteration", "PyExc_GeneratorExit",
	"_PyErr_SetObject.part.0", "_PyErr_SetObject", "PyErr_SetObject", "PyErr_SetString", "_PyErr_SetString",
}

// ResolveExceptionTarget finds the CPython runtime mapped by one process and
// the layout the exception probe needs.
func ResolveExceptionTarget(pid app.PID) (*ExceptionTarget, error) {
	startTime, err := ProcessStartTime(pid)
	if err != nil {
		return nil, err
	}
	proc, err := procfs.NewProc(int(pid))
	if err != nil {
		return nil, err
	}
	maps, err := proc.ProcMaps()
	if err != nil {
		return nil, fmt.Errorf("reading CPython process maps: %w", err)
	}
	objects, err := runtimeObjectCandidates(pid, maps)
	if err != nil {
		return nil, err
	}

	target, err := resolveRuntimeObjectCandidates(pid, objects, func(object *procfs.ProcMap) (*ExceptionTarget, error) {
		return resolveExceptionObject(pid, maps, object)
	})
	if err != nil {
		return nil, err
	}
	currentStartTime, err := ProcessStartTime(pid)
	if err != nil {
		_ = target.Close()
		return nil, err
	}
	if currentStartTime != startTime {
		_ = target.Close()
		return nil, errProcessReplaced
	}
	return target, nil
}

func resolveExceptionObject(pid app.PID, maps []*procfs.ProcMap, object *procfs.ProcMap) (*ExceptionTarget, error) {
	opened, err := openMappedELF(pid, object)
	if err != nil {
		return nil, err
	}
	target, err := analyzeExceptionObject(pid, maps, object, opened.elf)
	if err != nil {
		_ = opened.file.Close()
		return nil, err
	}
	target.attachment = opened.file
	return target, nil
}

func analyzeExceptionObject(pid app.PID, maps []*procfs.ProcMap, object *procfs.ProcMap, file *elf.File) (*ExceptionTarget, error) {
	if !supportedELF(file) {
		return nil, errUnsupportedLayout
	}
	symbols, err := procs.FindExeSymbols(file, exceptionSymbols, elf.STT_OBJECT, elf.STT_FUNC)
	if err != nil {
		return nil, fmt.Errorf("reading CPython symbols: %w", err)
	}
	anchor, ok := runtimeAnchor(file, symbols)
	if !ok {
		return nil, errRuntimeNotFound
	}

	version, freeThreaded, _, err := runtimeVersionFromELF(file, &elfAnalysis{
		anchor: anchor, versionAddress: symbols["Py_Version"].Value,
	})
	if err != nil {
		return nil, err
	}
	parsed := versionFromHex(version)
	if freeThreaded || parsed.major != 3 {
		return nil, fmt.Errorf("%w: CPython %s", errUnsupportedLayout, parsed)
	}
	layout, err := exceptionLayout(file, anchor, version)
	if err != nil {
		return nil, err
	}
	probe, err := errSetObjectOffset(file, symbols)
	if err != nil {
		return nil, err
	}
	bias, err := procs.FindMappingLoadBias(maps, file.Progs, object.Dev, object.Inode)
	if err != nil {
		return nil, err
	}
	if err := resolveExceptionAddresses(&layout, pid, bias, anchor, symbols); err != nil {
		return nil, err
	}
	return &ExceptionTarget{ProbeOffset: probe, Layout: layout}, nil
}

func exceptionLayout(file *elf.File, anchor uint64, version uint32) (ExceptionLayout, error) {
	parsed := versionFromHex(version)
	newest, known := supportedVersions[fmt.Sprintf("%d.%d", parsed.major, parsed.minor)]
	if !known || parsed.releaseLevel != cpythonReleaseLevelFinal || parsed.micro > newest {
		return ExceptionLayout{}, fmt.Errorf("%w: CPython %s exception layout", errUnsupportedLayout, parsed)
	}
	typeFlags, ok := layoutOffsets.Find("PyTypeObject", "tp_flags", parsed.String())
	if !ok || typeFlags > math.MaxUint8 {
		return ExceptionLayout{}, fmt.Errorf("%w: CPython %s type flags offset", errUnsupportedLayout, parsed)
	}
	minor := parsed.minor
	if minor >= 9 && minor <= 12 {
		layout, err := legacyExceptionLayout(parsed)
		layout.TypeFlags = uint8(typeFlags)
		return layout, err
	}
	positions, err := loadDebugExceptionPositions(parsed)
	if err != nil {
		return ExceptionLayout{}, err
	}
	debug, err := readVirtualBytes(file, anchor, uint64(positions.size))
	if err != nil {
		return ExceptionLayout{}, err
	}
	layout, err := debugExceptionLayout(debug, minor, positions)
	layout.TypeFlags = uint8(typeFlags)
	return layout, err
}

// debugExceptionLayout reads the offsets CPython 3.13+ publishes at the start of _PyRuntime.
func debugExceptionLayout(debug []byte, minor uint8, positions debugExceptionFields) (ExceptionLayout, error) {
	var invalid bool
	field := func(position int, limit uint64) uint64 {
		value := binary.LittleEndian.Uint64(debug[position:])
		invalid = invalid || value > limit
		return value
	}
	byteField := func(position int) uint8 {
		return uint8(field(position, math.MaxUint8))
	}

	unicodeASCII := uint8(field(positions.unicodeASCIISize, math.MaxUint8-compactUnicodeExtra))
	layout := ExceptionLayout{
		Minor:              minor,
		TstateInterp:       byteField(positions.tstateInterp),
		TstateFrame:        byteField(positions.tstateFrame),
		FrameCode:          byteField(positions.frameCode),
		FramePrevious:      byteField(positions.framePrevious),
		FrameInstr:         byteField(positions.frameInstr),
		FrameOwner:         byteField(positions.frameOwner),
		FrameOwnerCStack:   positions.frameOwnerCStack,
		CodeAdaptive:       uint16(field(positions.codeAdaptive, math.MaxUint16)),
		CodeFilename:       byteField(positions.codeFilename),
		CodeName:           byteField(positions.codeName),
		CodeLinetable:      byteField(positions.codeLinetable),
		CodeFirstlineno:    byteField(positions.codeFirstlineno),
		TupleItems:         byteField(positions.tupleItems),
		UnicodeASCIIData:   unicodeASCII,
		UnicodeCompactData: unicodeASCII + compactUnicodeExtra,
		ExceptionTraceback: exceptionTracebackOffset,
		FrameReadSize:      interpreterFrameReadSize,
		FrameObjectFrame:   frameObjectFrameOffset,
		TstateExcInfo:      positions.tstateExcInfo,
		ErrItemValue:       errItemValueOffset,
		ErrItemPrevious:    errItemPreviousOffset,
		interpretersMain:   binary.LittleEndian.Uint64(debug[positions.interpretersHead:]) + debugOffsets.InterpretersMainDelta,
	}
	if invalid || layout.TstateInterp == 0 || layout.TstateFrame == 0 || layout.CodeAdaptive == 0 {
		return ExceptionLayout{}, fmt.Errorf("%w: invalid CPython debug offsets", errUnsupportedLayout)
	}
	return layout, nil
}

// errSetObjectOffset prefers GCC's split body, which optimized callers can
// enter directly with the same arguments. Stripped builds derive the hidden
// setter from the exported stubs.
func errSetObjectOffset(file *elf.File, symbols map[string]procs.Sym) (uint64, error) {
	for _, name := range []string{"_PyErr_SetObject.part.0", "_PyErr_SetObject"} {
		if symbol, ok := symbols[name]; ok && symbol.Prog != nil {
			return symbol.Off, nil
		}
	}
	setObject, ok := symbols["PyErr_SetObject"]
	if !ok {
		return 0, fmt.Errorf("%w: missing PyErr_SetObject", errUnsupportedLayout)
	}
	var callers []procs.Sym
	for _, name := range []string{"PyErr_SetString", "_PyErr_SetString"} {
		if symbol, ok := symbols[name]; ok {
			callers = append(callers, symbol)
		}
	}
	return deriveErrSetObject(file, setObject, callers)
}

// resolveExceptionAddresses applies the load bias and reads the pointers that
// only the running process knows.
func resolveExceptionAddresses(layout *ExceptionLayout, pid app.PID, bias, anchor uint64, symbols map[string]procs.Sym) error {
	address := func(name string) uint64 {
		if symbol, ok := symbols[name]; ok && symbol.Value != 0 {
			return bias + symbol.Value
		}
		return 0
	}
	memory := remotememory.NewProcessVirtualMemory(libpf.PID(pid))
	pointer := func(at uint64) uint64 {
		if at == 0 {
			return 0
		}
		return memory.Uint64(libpf.Address(at))
	}

	layout.CodeType = address("PyCode_Type")
	layout.UnicodeType = address("PyUnicode_Type")
	layout.TupleType = address("PyTuple_Type")
	layout.StopIteration = pointer(address("PyExc_StopIteration"))
	layout.StopAsyncIteration = pointer(address("PyExc_StopAsyncIteration"))
	layout.GeneratorExit = pointer(address("PyExc_GeneratorExit"))
	layout.MainInterpreter = pointer(bias + anchor + layout.interpretersMain)

	if layout.CodeType == 0 || layout.UnicodeType == 0 || layout.TupleType == 0 ||
		layout.StopIteration == 0 || layout.StopAsyncIteration == 0 || layout.GeneratorExit == 0 ||
		layout.MainInterpreter == 0 {
		return fmt.Errorf("%w: missing CPython exception objects", errUnsupportedLayout)
	}
	// On 3.11+ PyCode_Type.tp_basicsize is offsetof(PyCodeObject, co_code_adaptive).
	if basicSize := pointer(layout.CodeType + typeBasicSizeOffset); layout.CodeAdaptive != 0 && basicSize != uint64(layout.CodeAdaptive) {
		return fmt.Errorf("%w: PyCodeObject size %d, expected %d", errUnsupportedLayout, basicSize, layout.CodeAdaptive)
	}
	return nil
}
