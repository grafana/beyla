// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package uprobe attaches userspace probes as uprobe_multi links where the
// running kernel supports them, and as perf events everywhere else.
package uprobe // import "go.opentelemetry.io/obi/pkg/internal/ebpf/uprobe"

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

const traceFSShutdownTimeoutMultiplier = 3

var (
	traceFSFallbackUsed atomic.Bool
	multiDisabled       atomic.Bool
)

// EffectiveShutdownTimeout allows extra time for tracefs uprobes to be removed.
// this is trully only needed for kernels 5.15 - 5.19. earlier than 5.15 allow us to
// use the PMU for uprobes without SYS_ADMIN and after 5.19 we can use whole group
// delete of the tracefs probes on shutdown. 6.6+ supports uprobe_multi, so we don't
// even need these tracefs legacy uprobes.
func EffectiveShutdownTimeout(configured time.Duration) time.Duration {
	if traceFSFallbackUsed.Load() {
		return traceFSShutdownTimeoutMultiplier * configured
	}
	return configured
}

// ConfigureMulti disables uprobe_multi for subsequent loads and attachments. It's meant
// for testing only.
func ConfigureMulti(disabled bool) {
	multiDisabled.Store(disabled)
}

func multiSupported() bool {
	return !multiDisabled.Load() && kernelSupportsMulti()
}

// one kernel decision shared by load-time attach types and attach-time links
var kernelSupportsMulti = sync.OnceValue(func() bool {
	if err := features.HaveBPFLinkUprobeMulti(); err != nil {
		slog.Info("attaching uprobes as perf events, the kernel has no uprobe_multi links", "reason", err)
		return false
	}
	if !multiFiltersByProcess() {
		slog.Info("attaching uprobes as perf events, the kernel filters uprobe_multi links by thread")
		return false
	}
	slog.Info("attaching uprobes as uprobe_multi links")
	return true
})

// multiFiltersByProcess reports whether a PID-scoped link fires on every thread
// of that process. Kernels before 6.10 (6.6.35 in stable) compared the probed
// thread against the one named at attach time, so hits from every other thread
// were dropped. The fix also rejects a negative PID with EINVAL, which is how
// libbpf tells the two apart: kernels without it look the PID up and answer
// ESRCH. See Linux 46ba0e49b642 and 04d939a2ab22
func multiFiltersByProcess() bool {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "obi_probe_upm_pid",
		Type:         ebpf.Kprobe,
		AttachType:   ebpf.AttachTraceUprobeMulti,
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
		License:      "Dual MIT/GPL",
	})
	if err != nil {
		slog.Debug("cannot probe uprobe_multi PID filtering", "error", err)
		return false
	}
	defer prog.Close()

	exe, err := link.OpenExecutable("/proc/self/exe")
	if err != nil {
		slog.Debug("cannot probe uprobe_multi PID filtering", "error", err)
		return false
	}

	// the address is never read: both kernels answer before they look at it
	l, err := exe.UprobeMulti(nil, prog, &link.UprobeMultiOptions{
		Addresses: []uint64{1},
		PID:       math.MaxUint32,
	})
	if err == nil {
		l.Close()
		slog.Debug("the kernel accepted a uprobe_multi link with a negative PID")
		return false
	}
	return errors.Is(err, unix.EINVAL)
}

// PrepareSpecs sets the uprobe_multi attach type before load, the kernel checks it at attach
func PrepareSpecs(spec *ebpf.CollectionSpec) {
	if !multiSupported() {
		return
	}
	markMultiPrograms(spec)
}

func markMultiPrograms(spec *ebpf.CollectionSpec) {
	tailCallTargets := progArrayContents(spec)
	twins := map[string]bool{}
	for _, name := range uprobePrograms(spec) {
		prog := spec.Programs[name]
		if tailCallTargets[name] || !hasMultiTwins(spec, prog) {
			continue
		}
		retargetProgArrays(spec, prog, twins)
		prog.AttachType = ebpf.AttachTraceUprobeMulti
	}
}

func uprobePrograms(spec *ebpf.CollectionSpec) []string {
	names := make([]string, 0, len(spec.Programs))
	for name, prog := range spec.Programs {
		if prog.Type == ebpf.Kprobe && prog.AttachType == ebpf.AttachNone && isUprobeSection(prog.SectionName) {
			names = append(names, name)
		}
	}
	return names
}

func isUprobeSection(name string) bool {
	return name == "uprobe" || name == "uretprobe" ||
		strings.HasPrefix(name, "uprobe/") || strings.HasPrefix(name, "uretprobe/")
}

func progArrayContents(spec *ebpf.CollectionSpec) map[string]bool {
	targets := map[string]bool{}
	for _, m := range spec.Maps {
		if m.Type != ebpf.ProgramArray {
			continue
		}
		for _, kv := range m.Contents {
			targets[progArrayEntry(kv.Value)] = true
		}
	}
	return targets
}

func progArrayEntry(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case *ebpf.ProgramSpec:
		return v.Name
	}
	return ""
}

// the kernel rejects tail calls between programs with different attach types,
// so multi programs use a twin of every prog array, declared next to it in C
const uprobeMultiSuffix = "_um"

func referencedProgArrays(spec *ebpf.CollectionSpec, prog *ebpf.ProgramSpec) []string {
	var tables []string
	for _, ins := range prog.Instructions {
		if m, ok := spec.Maps[ins.Reference()]; ok && m.Type == ebpf.ProgramArray {
			tables = append(tables, ins.Reference())
		}
	}
	return tables
}

func hasMultiTwins(spec *ebpf.CollectionSpec, prog *ebpf.ProgramSpec) bool {
	for _, table := range referencedProgArrays(spec, prog) {
		if _, ok := spec.Maps[table+uprobeMultiSuffix]; !ok {
			return false
		}
	}
	return true
}

func retargetProgArrays(spec *ebpf.CollectionSpec, prog *ebpf.ProgramSpec, twins map[string]bool) {
	for i, ins := range prog.Instructions {
		table := ins.Reference()
		if m, ok := spec.Maps[table]; !ok || m.Type != ebpf.ProgramArray {
			continue
		}
		prog.Instructions[i] = ins.WithReference(uprobeMultiTwin(spec, table, twins))
	}
}

// uprobeMultiTwin fills the twin prog array with uprobe_multi copies of the programs
func uprobeMultiTwin(spec *ebpf.CollectionSpec, table string, twins map[string]bool) string {
	twinName := table + uprobeMultiSuffix
	if twins[twinName] {
		return twinName
	}
	twins[twinName] = true
	twin := spec.Maps[twinName]
	if twin == nil {
		// a clone reached a table nobody twinned: leave it, the kernel refuses the load
		return table
	}
	for i, kv := range twin.Contents {
		if target := progArrayEntry(kv.Value); target != "" {
			twin.Contents[i] = ebpf.MapKV{Key: kv.Key, Value: uprobeMultiClone(spec, target, twins)}
		}
	}
	return twinName
}

func uprobeMultiClone(spec *ebpf.CollectionSpec, name string, twins map[string]bool) string {
	cloneName := name + uprobeMultiSuffix
	if _, ok := spec.Programs[cloneName]; ok {
		return cloneName
	}
	original, ok := spec.Programs[name]
	if !ok {
		return name
	}
	clone := original.Copy()
	clone.Name = cloneName
	clone.AttachType = ebpf.AttachTraceUprobeMulti
	spec.Programs[cloneName] = clone
	retargetProgArrays(spec, clone, twins)
	return cloneName
}

type Options struct {
	Addresses    []uint64
	RefCtrOffset uint64
	PID          uint32
	Return       bool
}

// Attach uses one uprobe_multi link, or perf events where the kernel refuses it with EINVAL.
// A perf uprobe denied with EACCES is retried through tracefs.
func Attach(exe *link.Executable, path string, prog *ebpf.Program, opts Options) (io.Closer, error) {
	if len(opts.Addresses) == 0 {
		return nil, errors.New("attaching uprobe: no addresses")
	}
	if !multiSupported() {
		return attachLegacy(exe, path, prog, opts)
	}
	closer, multiErr := attachMulti(exe, prog, opts)
	if multiErr == nil {
		return closer, nil
	}
	if !errors.Is(multiErr, unix.EINVAL) {
		return nil, multiErr
	}
	closer, err := attachLegacy(exe, path, prog, opts)
	if err != nil {
		return nil, errors.Join(multiErr, err)
	}
	return closer, nil
}

func attachMulti(exe *link.Executable, prog *ebpf.Program, opts Options) (io.Closer, error) {
	multiOpts := multiOptions(opts)
	if opts.Return {
		return exe.UretprobeMulti(nil, prog, multiOpts)
	}
	return exe.UprobeMulti(nil, prog, multiOpts)
}

func multiOptions(opts Options) *link.UprobeMultiOptions {
	multiOpts := &link.UprobeMultiOptions{Addresses: opts.Addresses, PID: opts.PID}
	if opts.RefCtrOffset != 0 {
		multiOpts.RefCtrOffsets = make([]uint64, len(opts.Addresses))
		for i := range multiOpts.RefCtrOffsets {
			multiOpts.RefCtrOffsets[i] = opts.RefCtrOffset
		}
	}
	return multiOpts
}

func attachLegacy(exe *link.Executable, path string, prog *ebpf.Program, opts Options) (io.Closer, error) {
	return attachWithTraceFSFallback(
		func() (io.Closer, error) { return attachPerfEvents(exe, prog, opts) },
		func() (io.Closer, error) { return attachTraceFS(path, prog, opts) },
	)
}

func attachPerfEvents(exe *link.Executable, prog *ebpf.Program, opts Options) (io.Closer, error) {
	links := make(perfEventLinks, 0, len(opts.Addresses))
	for _, address := range opts.Addresses {
		perfOpts := &link.UprobeOptions{Address: address, PID: int(opts.PID), RefCtrOffset: opts.RefCtrOffset}
		var (
			l   link.Link
			err error
		)
		if opts.Return {
			l, err = exe.Uretprobe("", prog, perfOpts)
		} else {
			l, err = exe.Uprobe("", prog, perfOpts)
		}
		if err != nil {
			_ = links.Close()
			return nil, fmt.Errorf("attaching uprobe at %#x: %w", address, err)
		}
		links = append(links, l)
	}
	if len(links) == 1 {
		return links[0], nil
	}
	return links, nil
}

var traceFSFallbackLog = sync.OnceFunc(func() {
	slog.Info("attached uprobe through tracefs because PMU access was denied")
})

var traceFSErrorFallbackLog sync.Once

func attachWithTraceFSFallback(
	attachPerf func() (io.Closer, error),
	attachTraceFS func() (io.Closer, error),
) (io.Closer, error) {
	closer, err := attachPerf()
	if err == nil || !errors.Is(err, unix.EACCES) {
		return closer, err
	}

	slog.Debug("failed to use uprobe with PMU, likely no SYS_ADMIN capability provided, trying tracefs attach", "error", err)

	closer, traceFSErr := attachTraceFS()
	if traceFSErr != nil {
		traceFSErrorFallbackLog.Do(func() {
			slog.Error(
				"cannot attach tracefs based uprobe, maybe CAP_DAC_OVERRIDE is missing or tracefs/debugfs is not mounted",
				"error", traceFSErr,
			)
		})
		return nil, errors.Join(err, traceFSErr)
	}
	traceFSFallbackUsed.Store(true)
	traceFSFallbackLog()
	return closer, nil
}

type perfEventLinks []io.Closer

// the kernel waits for RCU grace periods per perf event released, so the events
// of one attachment are released together rather than one after another
func (l perfEventLinks) Close() error {
	errs := make([]error, len(l))
	var wg sync.WaitGroup
	for i, lk := range l {
		wg.Go(func() { errs[i] = lk.Close() })
	}
	wg.Wait()
	return errors.Join(errs...)
}
