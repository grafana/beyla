// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/processcontext"
	"go.opentelemetry.io/ebpf-profiler/remotememory"

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
	fi              *execpkg.FileInfo
	mappingAddr     libpf.Address
	lastPublishedAt uint64
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

// pollEntry locates the OTEL_CTX mapping if needed and reads any new context.
func (pcd *processContextDecorator) pollEntry(pid app.PID, entry *processEntry) {
	if entry.mappingAddr == 0 {
		addr, ok := pcd.findOTELContextMapping(pid)
		if !ok {
			return
		}
		entry.mappingAddr = addr
	}

	rm := remotememory.NewProcessVirtualMemory(libpf.PID(pid))
	info, err := processcontext.Read(entry.mappingAddr, rm, entry.lastPublishedAt, 0)
	switch {
	case err == nil:
		if info.Context == nil {
			return
		}
		pcd.applyContext(entry.fi, info)
		entry.lastPublishedAt = info.PublishedAtNs
	case errors.Is(err, processcontext.ErrNoUpdate), errors.Is(err, processcontext.ErrConcurrentUpdate):
		// No change or transient update in progress; retry on next tick.
	case errors.Is(err, processcontext.ErrInvalidContext):
		// Mapping may have disappeared; re-scan on next tick.
		entry.mappingAddr = 0
	default:
		pcd.log.Debug("failed to read ProcessContext", "pid", pid, "error", err)
	}
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
	if res := info.Context.GetResource(); res != nil {
		for _, kv := range res.GetAttributes() {
			if kv == nil || kv.Key == "" {
				continue
			}
			av := kv.GetValue()
			if av == nil {
				continue
			}
			strVal := av.GetStringValue()
			if strVal == "" {
				if av.Value != nil {
					pcd.log.Debug("attribute value is not a string type", "type", av.Value)
				}
				continue
			}
			pcd.addAttribute(fi, attr.Name(kv.Key), strVal)
		}
	}

	for _, kv := range info.Context.GetAttributes() {
		if kv == nil || kv.Key == "" {
			continue
		}
		av := kv.GetValue()
		if av == nil {
			continue
		}
		strVal := av.GetStringValue()
		if strVal == "" {
			if av.Value != nil {
				pcd.log.Debug("attribute value is not a string type", "type", av.Value)
			}
			continue
		}
		pcd.addAttribute(fi, attr.Name(kv.Key), strVal)
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
