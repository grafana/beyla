// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package transform // import "go.opentelemetry.io/obi/pkg/transform"

import (
	"context"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/internal/ecs"
	"go.opentelemetry.io/obi/pkg/internal/helpers/container"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

func ECSProcessEventDecoratorProvider(ctxInfo *global.ContextInfo,
	input, output *msg.Queue[exec.ProcessEvent],
) swarm.InstanceFunc {
	return func(context.Context) (swarm.RunFunc, error) {
		if ctxInfo.ECSInventory == nil {
			return swarm.Bypass(input, output)
		}
		d := ecsProcessDecorator{
			inventory:     ctxInfo.ECSInventory,
			input:         input.Subscribe(msg.SubscriberName("ECSProcessEventDecorator")),
			output:        output,
			processes:     map[app.PID]*ecsProcess{},
			containerInfo: container.InfoForPID,
		}
		return d.run, nil
	}
}

type ecsProcess struct {
	event        exec.ProcessEvent
	fallbackName string
	appliedName  string
}

type ecsProcessDecorator struct {
	inventory     *ecs.Inventory
	input         <-chan exec.ProcessEvent
	output        *msg.Queue[exec.ProcessEvent]
	processes     map[app.PID]*ecsProcess
	containerInfo func(app.PID) (container.Info, error)
}

func (d *ecsProcessDecorator) run(ctx context.Context) {
	defer d.output.Close()
	changes := d.inventory.Changes()
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-d.input:
			if !ok {
				return
			}
			d.handleProcessEvent(ctx, event)
		case <-changes:
			changes = d.inventory.Changes()
			for _, process := range d.processes {
				if d.decorate(process) {
					d.output.SendCtx(ctx, process.event)
				}
			}
		}
	}
}

func (d *ecsProcessDecorator) handleProcessEvent(ctx context.Context, event exec.ProcessEvent) {
	if event.File == nil {
		return
	}
	pid := event.File.Pid()
	if event.Type == exec.ProcessEventTerminated {
		if previous := d.processes[pid]; previous != nil && previous.event.File == event.File {
			delete(d.processes, pid)
		}
	} else {
		service := event.ServiceFile().ServiceAttrs()
		if service.AutoName() {
			process := d.processes[pid]
			if process == nil || process.event.File != event.File {
				process = &ecsProcess{fallbackName: service.UID.Name}
				d.processes[pid] = process
			} else if service.UID.Name != process.appliedName {
				process.fallbackName = service.UID.Name
			}
			process.event = event
			d.decorate(process)
		} else {
			delete(d.processes, pid)
		}
	}
	d.output.SendCtx(ctx, event)
}

func (d *ecsProcessDecorator) decorate(process *ecsProcess) bool {
	file := process.event.ServiceFile()
	service := file.ServiceAttrs()
	if !service.AutoName() {
		return false
	}
	info, err := d.containerInfo(file.Pid())
	if err != nil {
		return false
	}
	file.SetRuntimeContainerID(info.ContainerID)
	name, ok := d.inventory.ServiceNameForContainerID(info.ContainerID)
	if !ok {
		name = process.fallbackName
	}
	process.appliedName = name
	if service.UID.Name == name {
		return false
	}
	service.UID.Name = name
	file.SetUID(service.UID)
	return true
}
