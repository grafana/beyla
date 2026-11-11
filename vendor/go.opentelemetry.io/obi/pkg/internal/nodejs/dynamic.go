// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejs // import "go.opentelemetry.io/obi/pkg/internal/nodejs"

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/gobwas/glob"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/agentctl"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

type DynamicRegistry struct {
	ctx     context.Context
	timeout time.Duration
	mu      sync.Mutex
	targets map[app.PID]*DynamicTarget
	symbols *agentctl.Catalog
}

func NewDynamicRegistry(ctx context.Context, cfg config.DynamicInstrumentationConfig, events *ebpfcommon.EBPFEventContext) *DynamicRegistry {
	r := &DynamicRegistry{ctx: ctx, timeout: cfg.RequestTimeout, targets: map[app.PID]*DynamicTarget{}, symbols: agentctl.NewCatalog(cfg)}
	events.RegisterInternalEventHandler(nodeDynamicReadyEvent, r.handleReady)
	return r
}

func (r *DynamicRegistry) Target(pid app.PID, tracer *ebpf.ProcessTracer) *DynamicTarget {
	r.mu.Lock()
	defer r.mu.Unlock()
	start, _ := procs.StartTime(pid)
	if prior := r.targets[pid]; prior != nil && prior.start == start && prior.tracer == tracer {
		return prior
	}
	t := &DynamicTarget{ctx: r.ctx, timeout: r.timeout, pid: pid, start: start, tracer: tracer, symbols: r.symbols, cookies: map[string]uint64{}}
	_, _ = rand.Read(t.session[:])
	r.targets[pid] = t
	return t
}

func (r *DynamicRegistry) Remove(pid app.PID) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.targets, pid)
	r.symbols.Remove(pid)
}

func (r *DynamicRegistry) handleReady(record *ringbuf.Record) error {
	data := record.RawSample
	if len(data) < 40 {
		return errors.New("short Node dynamic agent announcement")
	}
	pid := app.PID(binary.LittleEndian.Uint32(data[4:8]))
	port := binary.LittleEndian.Uint32(data[8:12])
	if port == 0 || port > 65535 {
		return errors.New("invalid Node dynamic agent port")
	}
	r.mu.Lock()
	target := r.targets[pid]
	r.mu.Unlock()
	if target == nil {
		return nil
	}
	target.mu.Lock()
	defer target.mu.Unlock()
	target.port = port
	copy(target.token[:], data[16:32])
	target.revision = binary.LittleEndian.Uint64(data[32:40])
	return nil
}

type DynamicTarget struct {
	ctx                          context.Context
	timeout                      time.Duration
	pid                          app.PID
	start                        uint64
	tracer                       *ebpf.ProcessTracer
	mu                           sync.Mutex
	port                         uint32
	token, session, claimedToken [16]byte
	revision, observed           uint64
	rpcMu, probesMu, symbolsMu   sync.Mutex
	symbols                      *agentctl.Catalog
	cookies                      map[string]uint64
}

func (t *DynamicTarget) LiveSymbolsChanged() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	changed := t.observed != t.revision
	t.observed = t.revision
	return changed
}

func (t *DynamicTarget) ResolveLiveSymbols(pid app.PID, pattern string) ([]string, error) {
	if pid != t.pid {
		return nil, errors.New("node target PID mismatch")
	}
	matcher, err := glob.Compile(pattern)
	if err != nil {
		return nil, err
	}
	t.symbolsMu.Lock()
	defer t.symbolsMu.Unlock()
	t.mu.Lock()
	revision := t.revision
	t.mu.Unlock()
	if revision == 0 {
		return nil, errors.New("node dynamic agent is not ready; nodejs.enabled must be true")
	}
	names, cached := t.symbols.Get(pid, t.start, revision)
	if !cached {
		names, err = t.command(t.ctx, agentctl.List, "", 0)
		if err != nil {
			return nil, err
		}
		t.symbols.Put(pid, t.start, revision, names)
	}
	var matched []string
	for _, name := range names {
		if name == pattern || matcher.Match(name) {
			matched = append(matched, name)
		}
	}
	if len(matched) == 0 && pattern != "*" {
		return nil, fmt.Errorf("no loaded CommonJS function matches %q", pattern)
	}
	return matched, nil
}

func (t *DynamicTarget) command(parent context.Context, operation byte, name string, cookie uint64) ([]string, error) {
	t.rpcMu.Lock()
	defer t.rpcMu.Unlock()
	start, err := procs.StartTime(t.pid)
	if err != nil {
		return nil, err
	}
	if start != t.start {
		return nil, errors.New("node target process identity changed")
	}
	ctx, cancel := context.WithTimeout(parent, t.timeout)
	defer cancel()
	t.mu.Lock()
	port, token := t.port, t.token
	t.mu.Unlock()
	if t.claimedToken != token {
		if _, err := agentctl.Exchange(ctx, t.pid, port, token, t.session, agentctl.Claim, "", 0); err != nil {
			return nil, err
		}
		t.claimedToken = token
	}
	return agentctl.Exchange(ctx, t.pid, port, token, t.session, operation, name, cookie)
}

func (t *DynamicTarget) AttachLiveSpan(pid app.PID, _ uint32, span *config.CustomSpanSpec, cookie uint64, id string, generation uint64) (io.Closer, error) {
	if pid != t.pid {
		return nil, errors.New("node target PID mismatch")
	}
	if !span.IsFunctionSpan() {
		return nil, errors.New("node probes require function_span")
	}
	for _, attr := range span.Attrs {
		if !attr.Type.IsString() {
			return nil, errors.New("node arguments are captured as strings")
		}
	}
	t.probesMu.Lock()
	defer t.probesMu.Unlock()
	name := span.FunctionSymbol()
	prior := t.cookies[name]
	registration, err := t.tracer.RegisterNodeSpan(pid, span, cookie, id, generation)
	if err != nil {
		return nil, err
	}
	if _, err := t.command(t.ctx, agentctl.Attach, name, cookie); err != nil {
		_ = registration.Close()
		rollback := context.WithoutCancel(t.ctx)
		_, detachErr := t.command(rollback, agentctl.Detach, "", cookie)
		if prior != 0 {
			_, restoreErr := t.command(rollback, agentctl.Attach, name, prior)
			err = errors.Join(err, restoreErr)
		}
		return nil, errors.Join(err, detachErr)
	}
	t.cookies[name] = cookie
	return &nodeDynamicProbe{target: t, cookie: cookie, name: name, registration: registration}, nil
}

type nodeDynamicProbe struct {
	target       *DynamicTarget
	cookie       uint64
	name         string
	registration io.Closer
	once         sync.Once
	err          error
}

func (p *nodeDynamicProbe) Invocations() (uint64, error) {
	return p.registration.(interface{ Invocations() (uint64, error) }).Invocations()
}

func (p *nodeDynamicProbe) Close() error {
	p.target.probesMu.Lock()
	defer p.target.probesMu.Unlock()
	_, remoteErr := p.target.command(context.WithoutCancel(p.target.ctx), agentctl.Detach, "", p.cookie)
	if start, err := procs.StartTime(p.target.pid); errors.Is(err, os.ErrNotExist) || (err == nil && start != p.target.start) {
		remoteErr = nil
	}
	if remoteErr == nil && p.target.cookies[p.name] == p.cookie {
		delete(p.target.cookies, p.name)
	}
	p.once.Do(func() { p.err = p.registration.Close() })
	return errors.Join(remoteErr, p.err)
}
