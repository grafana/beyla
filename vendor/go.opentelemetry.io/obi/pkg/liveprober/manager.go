// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package liveprober // import "go.opentelemetry.io/obi/pkg/liveprober"

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
)

var (
	ErrConflict   = errors.New("probe generation conflict")
	ErrNotReady   = errors.New("target PID has not been discovered by OBI")
	ErrTargetGone = errors.New("target process identity changed")
)

// TargetTracer is the small slice of the resident OBI tracer needed for
// entry-only live probes. The interface permits manager tests without BPF.
type TargetTracer interface {
	AttachLiveSpan(app.PID, uint32, *config.CustomSpanSpec, uint64, string, uint64) (io.Closer, error)
}

type ProbeSpec struct {
	Generation uint64 `json:"generation"`
	PID        int    `json:"pid"`
	Offset     Offset `json:"offset"`
	SpanName   string `json:"span_name"`
	TTLSeconds uint32 `json:"ttl_seconds"`
}

// Offset accepts numeric JSON as well as the 0x string used by the existing
// probe catalog. Responses always encode it as a JSON number.
type Offset uint64

func (o *Offset) UnmarshalJSON(data []byte) error {
	if len(data) == 0 {
		return errors.New("empty offset")
	}
	if data[0] != '"' {
		var number uint64
		if err := json.Unmarshal(data, &number); err != nil {
			return err
		}
		*o = Offset(number)
		return nil
	}
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	base := 10
	if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
		base = 16
		value = value[2:]
	}
	number, err := strconv.ParseUint(value, base, 64)
	if err != nil {
		return err
	}
	*o = Offset(number)
	return nil
}

type ProbeState struct {
	ProbeSpec
	Status    string `json:"status"`
	LinkID    string `json:"link_id"`
	LastError string `json:"last_error,omitempty"`
}

type target struct {
	service  func() svc.Attrs
	tracer   TargetTracer
	ns       uint32
	identity processIdentity
}

type attachment struct {
	cookie uint64
	state  ProbeState
	link   io.Closer
	timer  *time.Timer
}

type Manager struct {
	symbols        SymbolResolver
	rules          map[string]ruleState
	matches        map[int]ProcessMatcher
	services       map[int]svc.UID
	dynamic        map[dynamicKey]*dynamicAttachment
	patches        map[patchKey]*patchAttachment
	suppressed     map[dynamicKey]bool
	changed        chan struct{}
	updated        chan struct{}
	requestTimeout time.Duration
	maxProbes      int
	metrics        imetrics.Reporter
	closed         bool

	mu             sync.Mutex
	targets        map[int]target
	probes         map[string]*attachment
	lastGeneration map[string]uint64
	nextCookie     uint64
	identity       func(int) (processIdentity, error)
}

func New() *Manager {
	return &Manager{
		metrics: imetrics.NoopReporter{},
		rules:   map[string]ruleState{}, matches: map[int]ProcessMatcher{}, services: map[int]svc.UID{},
		dynamic: map[dynamicKey]*dynamicAttachment{}, patches: map[patchKey]*patchAttachment{}, suppressed: map[dynamicKey]bool{},
		changed: make(chan struct{}, 1), updated: make(chan struct{}), maxProbes: 1024, requestTimeout: 10 * time.Second,

		targets:        make(map[int]target),
		probes:         make(map[string]*attachment),
		lastGeneration: make(map[string]uint64),
		identity:       readProcessIdentity,
	}
}

func (m *Manager) RegisterTarget(pid int, ns uint32, tracer TargetTracer, service func() svc.Attrs) error {
	start, err := m.identity(pid)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errors.New("dynamic instrumentation is shutting down")
	}
	if prior, ok := m.targets[pid]; ok && prior.identity != start {
		m.detachTargetLocked(pid, "target_gone")
	}
	m.targets[pid] = target{tracer: tracer, ns: ns, identity: start, service: service}
	err = m.reconcileLocked()
	m.notifyLocked()
	return err
}

func (m *Manager) UnregisterTarget(pid int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.detachTargetLocked(pid, "target_gone")
	delete(m.targets, pid)
	delete(m.matches, pid)
	delete(m.services, pid)
	for key := range m.suppressed {
		if key.pid == pid {
			delete(m.suppressed, key)
		}
	}
	m.notifyLocked()
}

func (m *Manager) detachTargetLocked(pid int, status string) {
	for key := range m.dynamic {
		if key.pid == pid {
			_ = m.removeDynamicLocked(key)
		}
	}
	for key := range m.patches {
		if key.pid == pid {
			_ = m.removePatchLocked(key)
		}
	}
	for _, a := range m.probes {
		if a.state.PID != pid || a.state.Status != "attached" {
			continue
		}
		if a.timer != nil {
			a.timer.Stop()
		}
		if err := a.link.Close(); err != nil {
			a.state.LastError = err.Error()
		}
		m.metrics.DynamicProbeInvocations(a.cookie, nil)
		a.state.Status = status
	}
}

func (m *Manager) Apply(id string, spec ProbeSpec) (ProbeState, error) {
	if err := validateSpec(id, spec); err != nil {
		return ProbeState{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ProbeState{}, errors.New("dynamic instrumentation is shutting down")
	}
	if a, ok := m.probes[id]; ok {
		if spec.Generation == a.state.Generation && spec == a.state.ProbeSpec {
			return a.state, nil
		}
		if spec.Generation <= a.state.Generation {
			return a.state, fmt.Errorf("%w: current generation is %d", ErrConflict, a.state.Generation)
		}
	} else if spec.Generation <= m.lastGeneration[id] {
		return ProbeState{}, fmt.Errorf("%w: last generation is %d", ErrConflict, m.lastGeneration[id])
	}
	bound, ok := m.targets[spec.PID]
	if !ok {
		return ProbeState{}, ErrNotReady
	}
	start, err := m.identity(spec.PID)
	if err != nil || start != bound.identity {
		return ProbeState{}, ErrTargetGone
	}
	span := &config.CustomSpanSpec{
		Name: spec.SpanName,
		On:   config.CustomSpanTarget{FunctionNoRet: fmt.Sprintf("0x%x", spec.Offset)},
	}
	m.nextCookie++
	cookie := m.nextCookie
	link, err := bound.tracer.AttachLiveSpan(app.PID(spec.PID), bound.ns, span, cookie, id, spec.Generation)
	if err != nil {
		return ProbeState{}, err
	}

	state := ProbeState{ProbeSpec: spec, Status: "attached", LinkID: fmt.Sprintf("attach-%d", cookie)}
	newAttachment := &attachment{state: state, link: link, cookie: cookie}
	if spec.TTLSeconds != 0 {
		newAttachment.timer = time.AfterFunc(time.Duration(spec.TTLSeconds)*time.Second, func() {
			m.expire(id, spec.Generation)
		})
	}
	if old, ok := m.probes[id]; ok {
		if old.timer != nil {
			old.timer.Stop()
		}
		if old.state.Status == "attached" {
			m.metrics.DynamicProbeInvocations(old.cookie, nil)
			if err := old.link.Close(); err != nil {
				newAttachment.state.LastError = "old link close: " + err.Error()
			}
		}
	}
	m.probes[id] = newAttachment
	m.reportInvocationsLocked(cookie, spec.PID, span.TargetIdentifier(), link)
	m.lastGeneration[id] = spec.Generation
	return newAttachment.state, nil
}

func validateSpec(id string, spec ProbeSpec) error {
	if id == "" || strings.ContainsAny(id, "/\\") {
		return errors.New("invalid probe ID")
	}
	if spec.Generation == 0 {
		return errors.New("generation must be positive")
	}
	if spec.PID <= 0 {
		return errors.New("PID must be positive")
	}
	if spec.Offset == 0 {
		return errors.New("offset must be positive")
	}
	if spec.SpanName == "" {
		return errors.New("span_name is required")
	}
	return nil
}

func (m *Manager) expire(id string, generation uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.probes[id]
	if !ok || a.state.Generation != generation {
		return
	}
	if err := a.link.Close(); err != nil {
		a.state.LastError = err.Error()
	}
	m.metrics.DynamicProbeInvocations(a.cookie, nil)
	a.state.Status = "expired"
	a.timer = nil
}

func (m *Manager) Delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.probes[id]
	if !ok {
		return nil
	}
	if a.timer != nil {
		a.timer.Stop()
	}
	if a.state.Status == "attached" {
		if err := a.link.Close(); err != nil {
			a.state.LastError = err.Error()
			m.metrics.DynamicProbeInvocations(a.cookie, nil)
			a.state.Status = "error"
			return err
		}
	}
	m.metrics.DynamicProbeInvocations(a.cookie, nil)
	delete(m.probes, id)
	return nil
}

func (m *Manager) Snapshot() map[string]ProbeState {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]ProbeState, len(m.probes))
	for id, a := range m.probes {
		out[id] = a.state
	}
	return out
}

func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	var err error
	for key := range m.dynamic {
		err = errors.Join(err, m.removeDynamicLocked(key))
	}
	for id, a := range m.probes {
		if a.timer != nil {
			a.timer.Stop()
		}
		if a.state.Status == "attached" {
			err = errors.Join(err, a.link.Close())
		}
		m.metrics.DynamicProbeInvocations(a.cookie, nil)
		delete(m.probes, id)
	}
	clear(m.rules)
	clear(m.targets)
	clear(m.matches)
	clear(m.services)
	clear(m.suppressed)
	clear(m.lastGeneration)
	m.notifyLocked()
	return err
}

type processIdentity struct {
	startTime uint64
	device    uint64
	inode     uint64
}

// Combine process birth time with executable identity to detect PID reuse and exec.
func readProcessIdentity(pid int) (processIdentity, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return processIdentity{}, err
	}
	end := strings.LastIndexByte(string(data), ')')
	if end < 0 {
		return processIdentity{}, errors.New("malformed process stat")
	}
	fields := strings.Fields(string(data[end+1:]))
	if len(fields) <= 19 {
		return processIdentity{}, errors.New("short process stat")
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return processIdentity{}, err
	}
	executable, err := os.Stat(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return processIdentity{}, err
	}
	stat, ok := executable.Sys().(*syscall.Stat_t)
	if !ok {
		return processIdentity{}, errors.New("executable identity unavailable")
	}
	return processIdentity{startTime: start, device: stat.Dev, inode: stat.Ino}, nil
}
