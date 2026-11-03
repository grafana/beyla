// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package peer // import "go.opentelemetry.io/obi/pkg/metadata/peer"

import (
	"context"
	"maps"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

type processKey struct {
	pid   int32
	start uint64
}

type processInventory struct {
	mu        sync.Mutex
	processes map[processKey]*exec.FileInfo
	changed   chan struct{}
}

// This code here keeps an inventory of local servers, e.g. processes that we are instrumenting that are listeners
// on certain ports.
func runInventory(ctx context.Context, events <-chan exec.ProcessEvent, store *localStore, interval time.Duration) {
	inventory := &processInventory{
		processes: map[processKey]*exec.FileInfo{},
		changed:   make(chan struct{}, 1),
	}

	var polling sync.WaitGroup

	polling.Go(func() {
		inventory.poll(ctx, store, interval)
	})

	defer polling.Wait()

	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-events:
			if !ok {
				events = nil
				continue
			}

			inventory.mu.Lock()
			updateProcesses(ctx, inventory.processes, event)
			inventory.mu.Unlock()
			select {
			case inventory.changed <- struct{}{}:
			default:
			}
		}
	}
}

func (i *processInventory) poll(ctx context.Context, store *localStore, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		i.mu.Lock()
		processes := maps.Clone(i.processes)
		i.mu.Unlock()

		expired := refreshInventory(ctx, processes, store)

		i.mu.Lock()
		for _, key := range expired {
			delete(i.processes, key)
		}
		i.mu.Unlock()

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-i.changed:
		}
	}
}

func updateProcesses(ctx context.Context, processes map[processKey]*exec.FileInfo, event exec.ProcessEvent) {
	if event.File == nil {
		return
	}

	key := processKey{pid: int32(event.File.Pid()), start: event.File.StartTime()}

	if event.Type == exec.ProcessEventTerminated {
		delete(processes, key)
		return
	}

	processes[key] = event.ServiceFile()
	registerChildProcesses(ctx, processes, key)
}

func registerChildProcesses(ctx context.Context, processes map[processKey]*exec.FileInfo, parent processKey) {
	start, err := procs.StartTime(app.PID(parent.pid))
	if err != nil || (parent.start != 0 && start != parent.start) {
		return
	}

	proc := &process.Process{Pid: parent.pid}
	executable, err := proc.ExeWithContext(ctx)
	if err != nil {
		return
	}

	children, err := proc.ChildrenWithContext(ctx)
	if err != nil {
		return
	}

	for _, child := range children {
		childExecutable, err := child.ExeWithContext(ctx)
		if err != nil || childExecutable != executable {
			continue
		}

		start, err := procs.StartTime(app.PID(child.Pid))
		if err != nil {
			continue
		}

		key := processKey{pid: child.Pid, start: start}
		if _, exists := processes[key]; !exists {
			processes[key] = processes[parent]
		}

		registerChildProcesses(ctx, processes, key)
	}
}

func refreshInventory(ctx context.Context, processes map[processKey]*exec.FileInfo, store *localStore) []processKey {
	var expired []processKey
	services := map[Service]struct{}{}
	listeners := map[Listener]struct{}{}

	for key, file := range processes {
		if ctx.Err() != nil {
			return expired
		}

		start, err := procs.StartTime(app.PID(key.pid))
		if err != nil || (key.start != 0 && start != key.start) {
			delete(processes, key)
			expired = append(expired, key)
			continue
		}

		attrs := file.ServiceAttrs()
		service := store.serviceFor(attrs)
		if service.Name == "" {
			continue
		}

		services[service] = struct{}{}
		registerListeners(ctx, key.pid, service, listeners)
	}

	serviceList := slices.AppendSeq(make([]Service, 0, len(services)), maps.Keys(services))
	listenerList := slices.AppendSeq(make([]Listener, 0, len(listeners)), maps.Keys(listeners))
	store.setInventory(serviceList, listenerList)

	return expired
}

func registerListeners(ctx context.Context, pid int32, service Service, listeners map[Listener]struct{}) {
	connections, err := net.ConnectionsPidWithoutUidsWithContext(ctx, "inet", pid)
	if err != nil {
		return
	}

	for _, connection := range connections {
		if connection.Status != "LISTEN" {
			continue
		}

		addr, err := netip.ParseAddr(connection.Laddr.IP)
		if err != nil {
			continue
		}

		listeners[Listener{
			Endpoint: Endpoint{
				IP:   addr.Unmap().String(),
				Port: int(connection.Laddr.Port),
			},
			Service: service,
		}] = struct{}{}
	}
}
