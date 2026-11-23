// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"

import (
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/cilium/ebpf/link"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	cpythonruntime "go.opentelemetry.io/obi/pkg/internal/cpython/runtime"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/uprobe"
)

type pythonExceptionProcess struct {
	service *exec.FileInfo
	links   []io.Closer
}

// pythonExceptionController attaches the _PyErr_SetObject probe to each Python
// process that captures exceptions, so other processes sharing libpython never trap.
type pythonExceptionController struct {
	tracer    *Tracer
	resolve   func(app.PID) (*cpythonruntime.ExceptionTarget, error)
	mu        sync.Mutex
	processes map[app.PID]pythonExceptionProcess
	closed    bool
}

func newPythonExceptionController(tracer *Tracer) *pythonExceptionController {
	if !tracer.exceptionsEnabled() {
		return nil
	}
	return &pythonExceptionController{
		tracer:    tracer,
		resolve:   cpythonruntime.ResolveExceptionTarget,
		processes: map[app.PID]pythonExceptionProcess{},
	}
}

func (p *Tracer) exceptionsEnabled() bool {
	return p.cfg.ExceptionsEnabled() && p.cfg.Logs.Enabled()
}

func (c *pythonExceptionController) allow(pid app.PID, service *exec.FileInfo) {
	if c == nil || service.SDKLanguage() != svc.InstrumentablePython ||
		!service.ServiceAttrs().Exceptions.Enabled || !service.ServiceAttrs().Exceptions.Python.IsEnabled() {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	if existing, ok := c.processes[pid]; ok {
		if existing.service == service {
			return
		}
		c.detachLocked(pid)
	}

	links, err := c.attach(pid)
	if err != nil {
		c.tracer.log.Debug("Python exception capture unavailable", "pid", pid, "error", err)
		return
	}
	c.processes[pid] = pythonExceptionProcess{service: service, links: links}
}

func (c *pythonExceptionController) attach(pid app.PID) ([]io.Closer, error) {
	if c.tracer.bpfObjects.PythonExceptionProcs == nil {
		return nil, errors.New("exception maps are not loaded")
	}
	target, err := c.resolve(pid)
	if err != nil {
		return nil, err
	}
	defer target.Close()

	if err := c.tracer.bpfObjects.PythonExceptionProcs.Put(uint32(pid), pythonExceptionProc(&target.Layout)); err != nil {
		return nil, fmt.Errorf("storing the Python layout: %w", err)
	}
	executable, err := link.OpenExecutable(target.AttachmentPath())
	if err != nil {
		return nil, errors.Join(err, c.tracer.bpfObjects.PythonExceptionProcs.Delete(uint32(pid)))
	}

	attached, err := uprobe.Attach(executable, target.AttachmentPath(),
		c.tracer.bpfObjects.ObiUprobePythonErrSetObject,
		uprobe.Options{Addresses: []uint64{target.ProbeOffset}, PID: uint32(pid)})
	if err != nil {
		return nil, errors.Join(err, c.tracer.bpfObjects.PythonExceptionProcs.Delete(uint32(pid)))
	}
	c.tracer.log.Debug("Python exception capture attached", "pid", pid,
		"version", fmt.Sprintf("3.%d", target.Layout.Minor), "offset", fmt.Sprintf("%#x", target.ProbeOffset))
	return []io.Closer{attached}, nil
}

func closePythonExceptionLinks(closers []io.Closer) {
	for _, closer := range closers {
		_ = closer.Close()
	}
}

func (c *pythonExceptionController) block(pid app.PID) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.detachLocked(pid)
}

func (c *pythonExceptionController) close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	for pid := range c.processes {
		c.detachLocked(pid)
	}
}

func (c *pythonExceptionController) detachLocked(pid app.PID) {
	process, ok := c.processes[pid]
	if !ok {
		return
	}
	closePythonExceptionLinks(process.links)
	_ = c.tracer.bpfObjects.PythonExceptionProcs.Delete(uint32(pid))
	delete(c.processes, pid)
}

func pythonExceptionProc(layout *cpythonruntime.ExceptionLayout) BpfPythonExceptionProcT {
	proc := BpfPythonExceptionProcT{
		MainInterp:         layout.MainInterpreter,
		CodeType:           layout.CodeType,
		UnicodeType:        layout.UnicodeType,
		TupleType:          layout.TupleType,
		StopIteration:      layout.StopIteration,
		StopAsyncIteration: layout.StopAsyncIteration,
		GeneratorExit:      layout.GeneratorExit,
		CodeAdaptive:       layout.CodeAdaptive,
		TypeFlags:          layout.TypeFlags,
		TstateInterp:       layout.TstateInterp,
		TstateFrame:        layout.TstateFrame,
		CframeCurrentFrame: layout.CFrameCurrentFrame,
		FrameCode:          layout.FrameCode,
		FramePrevious:      layout.FramePrevious,
		FrameInstr:         layout.FrameInstr,
		FrameOwner:         layout.FrameOwner,
		FrameOwnerCstack:   layout.FrameOwnerCStack,
		TupleItems:         layout.TupleItems,
		ExceptionTraceback: layout.ExceptionTraceback,
		FrameReadSize:      layout.FrameReadSize,
		FrameObjectFrame:   layout.FrameObjectFrame,
		TstateExcInfo:      layout.TstateExcInfo,
		ErrItemValue:       layout.ErrItemValue,
		ErrItemPrevious:    layout.ErrItemPrevious,
		FrameIsCframe:      boolByte(layout.FrameIsCFrame),
		FrameLastiInt:      boolByte(layout.FrameLastiInt),
		FrameLastiBytes:    boolByte(layout.FrameLastiBytes),
	}
	proc.Layout.Minor = layout.Minor
	proc.Layout.CodeFilename = layout.CodeFilename
	proc.Layout.CodeName = layout.CodeName
	proc.Layout.CodeLinetable = layout.CodeLinetable
	proc.Layout.CodeFirstlineno = layout.CodeFirstlineno
	proc.Layout.UnicodeAsciiData = layout.UnicodeASCIIData
	proc.Layout.UnicodeCompactData = layout.UnicodeCompactData
	return proc
}

func boolByte(value bool) uint8 {
	if value {
		return 1
	}
	return 0
}
