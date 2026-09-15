// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"context"
	"log/slog"
	"time"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process/processcontext"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	execpkg "go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/ebpf"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/procs"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

func pclog() *slog.Logger {
	return slog.With("component", "ProcessContextDecorator")
}

func ProcessContextDecoratorProvider(
	pollInterval time.Duration,
	input, output *msg.Queue[[]Event[ebpf.Instrumentable]],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		pcd := processContextDecorator{
			in:           input.Subscribe(msg.SubscriberName("ProcessContextDecorator")),
			out:          output,
			log:          pclog(),
			pollInterval: pollInterval,
			tracked:      make(map[app.PID]*processEntry),
		}
		return pcd.decorate, nil
	}
}

// processEntry holds per-process state needed for polling.
type processEntry struct {
	fi          *execpkg.FileInfo
	contextInfo processcontext.Info
}

// processContextDecorator enriches discovered processes with context information
// shared by applications through the OTEL_CTX environment mapping, allowing services
// to export resource attributes and metadata without direct instrumentation.
//
// Enrichment is attempted immediately on process creation and then repeated on
// every poll tick to handle SDKs that register the mapping after startup and to
// pick up context updates published by the process over its lifetime.
type processContextDecorator struct {
	in           <-chan []Event[ebpf.Instrumentable]
	out          *msg.Queue[[]Event[ebpf.Instrumentable]]
	log          *slog.Logger
	pollInterval time.Duration
	tracked      map[app.PID]*processEntry
}

func (pcd *processContextDecorator) decorate(ctx context.Context) {
	defer pcd.out.Close()

	var tickerC <-chan time.Time
	if pcd.pollInterval > 0 {
		ticker := time.NewTicker(pcd.pollInterval)
		defer ticker.Stop()
		tickerC = ticker.C
	}

	pcd.log.Debug("starting node")
	for {
		select {
		case <-ctx.Done():
			pcd.log.Debug("context done, stopping node")
			return
		case evs, ok := <-pcd.in:
			if !ok {
				pcd.log.Debug("input channel closed, stopping node")
				return
			}
			for i := range evs {
				ev := &evs[i]
				switch ev.Type {
				case EventCreated:
					pcd.handleCreated(ev)
				case EventDeleted:
					delete(pcd.tracked, ev.Obj.FileInfo.Pid())
				}
			}
			pcd.out.SendCtx(ctx, evs)
		case <-tickerC:
			pcd.poll()
		}
	}
}

// handleCreated registers the process and attempts an immediate enrichment.
func (pcd *processContextDecorator) handleCreated(ev *Event[ebpf.Instrumentable]) {
	pid := ev.Obj.FileInfo.Pid()
	entry := &processEntry{fi: ev.Obj.FileInfo}
	pcd.tracked[pid] = entry
	pcd.pollEntry(pid, entry)
}

// poll checks all tracked processes for new or updated process context.
func (pcd *processContextDecorator) poll() {
	for pid, entry := range pcd.tracked {
		pcd.pollEntry(pid, entry)
	}
}

// pollEntry locates the OTEL_CTX mapping and resolves its latest resource attributes.
func (pcd *processContextDecorator) pollEntry(pid app.PID, entry *processEntry) {
	mappingAddr, _ := pcd.findOTELContextMapping(pid)
	rm := remotememory.NewProcessVirtualMemory(libpf.PID(pid))
	entry.contextInfo = processcontext.Resolve(
		uint64(mappingAddr), libpf.PID(pid), rm, entry.contextInfo, nil)
	pcd.applyContext(entry.fi, entry.contextInfo)
}

func (pcd *processContextDecorator) findOTELContextMapping(pid app.PID) (libpf.Address, bool) {
	maps, err := procs.FindLibMaps(pid)
	if err != nil {
		pcd.log.Debug("failed to read process maps", "pid", pid, "error", err)
		return 0, false
	}

	for _, m := range maps {
		if processcontext.IsContextMapping(m.Perms.Execute, m.Pathname) {
			return libpf.Address(m.StartAddr), true
		}
	}
	return 0, false
}

func (pcd *processContextDecorator) applyContext(fi *execpkg.FileInfo, info processcontext.Info) {
	for _, kv := range info.ResourceAttrs.ToSlice() {
		if kv.Value.Type() != attribute.STRING {
			pcd.log.Debug("attribute value is not a string type", "type", kv.Value.Type())
			continue
		}
		if value := kv.Value.AsString(); value != "" {
			pcd.addAttribute(fi, attr.Name(kv.Key), value)
		}
	}
}

func (pcd *processContextDecorator) addAttribute(fi *execpkg.FileInfo, key attr.Name, value string) {
	svcAttrs := fi.ServiceAttrs()

	m := svcAttrs.Metadata
	if m == nil {
		m = make(map[attr.Name]string)
	}
	m[key] = value
	fi.SetMetadata(m)

	// Populate service UID from process context attributes, but only if not
	// already explicitly set. This allows process-level metadata to establish
	// the service identity while preserving any explicit configuration.
	if key == attr.ServiceName && svcAttrs.UID.Name == "" {
		uid := svcAttrs.UID
		uid.Name = value
		fi.SetUID(uid)
	} else if key == attr.ServiceNamespace && svcAttrs.UID.Namespace == "" {
		uid := svcAttrs.UID
		uid.Namespace = value
		fi.SetUID(uid)
	}
}
