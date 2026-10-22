// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package transform // import "go.opentelemetry.io/obi/pkg/transform"

import (
	"context"
	"errors"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/cloud"
	"go.opentelemetry.io/obi/pkg/internal/helpers/container"
	"go.opentelemetry.io/obi/pkg/metadata"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

func CloudProcessEventDecoratorProvider(ctxInfo *global.ContextInfo, cfg *NameResolverConfig,
	input, output *msg.Queue[exec.ProcessEvent],
) swarm.InstanceFunc {
	return func(context.Context) (swarm.RunFunc, error) {
		if ctxInfo.CloudMetaInventory == nil {
			return swarm.Bypass(input, output)
		}
		d := cloudProcessDecorator{
			instanceID:    localCloudInstanceID(&ctxInfo.NodeMeta, cfg),
			inventory:     ctxInfo.CloudMetaInventory,
			changes:       ctxInfo.CloudMetaInventory.SubscribeContainerChanges(),
			input:         input.Subscribe(msg.SubscriberName("CloudProcessEventDecorator")),
			output:        output,
			containerInfo: container.InfoForPID,
		}
		return d.run, nil
	}
}

// localCloudInstanceID selects the detected VM identity for both process and span
// decoration. Each provider checks that the configured scope matches this host.
func localCloudInstanceID(node *metadata.NodeMeta, cfg *NameResolverConfig) string {
	if cfg == nil {
		return ""
	}
	if resolverSources(cfg.Sources).Has(ResolverGCE) {
		if id := gceLocalInstanceID(*node, cfg.GCE); id != "" {
			return id
		}
	}
	return localAzureInstanceID(node, cfg)
}

type cloudProcessDecorator struct {
	inventory     *cloud.Inventory
	changes       <-chan cloud.ContainerChanges
	processes     map[app.PID]cloudProcess
	input         <-chan exec.ProcessEvent
	output        *msg.Queue[exec.ProcessEvent]
	containerInfo func(app.PID) (container.Info, error)
	instanceID    string
}

type cloudProcess struct {
	event        exec.ProcessEvent
	fallbackName string
}

func (d *cloudProcessDecorator) run(ctx context.Context) {
	defer d.output.Close()
	d.processes = map[app.PID]cloudProcess{}

	for {
		select {
		case <-ctx.Done():
			return
		case changes := <-d.changes:
			for _, process := range d.processes {
				event := process.event
				id := event.ServiceFile().ServiceAttrs().RuntimeContainerID
				_, changed := changes.Changed[id]
				_, removed := changes.Removed[id]
				instanceChanged := d.instanceID != "" && changes.InstancesChanged
				if (changed || removed || instanceChanged) && d.decorate(event, process.fallbackName) {
					d.output.SendCtx(ctx, event)
				}
			}
		case event, ok := <-d.input:
			if !ok {
				return
			}
			d.handleProcessEvent(ctx, event)
		}
	}
}

func (d *cloudProcessDecorator) handleProcessEvent(ctx context.Context, event exec.ProcessEvent) {
	if event.File == nil {
		return
	}
	pid := event.File.Pid()
	if event.Type == exec.ProcessEventTerminated {
		if previous, ok := d.processes[pid]; ok && previous.event.File == event.File {
			delete(d.processes, pid)
		}
	} else {
		service := event.ServiceFile().ServiceAttrs()
		if service.AutoName() {
			fallbackName := service.UID.Name
			if previous, ok := d.processes[pid]; ok && previous.event.File == event.File {
				fallbackName = previous.fallbackName
			}
			d.decorate(event, fallbackName)
			d.processes[pid] = cloudProcess{event: event, fallbackName: fallbackName}
		} else {
			delete(d.processes, pid)
		}
	}

	d.output.SendCtx(ctx, event)
}

func (d *cloudProcessDecorator) decorate(event exec.ProcessEvent, fallbackName string) bool {
	file := event.ServiceFile()
	service := file.ServiceAttrs()
	if !service.AutoName() {
		return false
	}
	id := service.RuntimeContainerID
	if id == "" {
		info, err := d.containerInfo(file.Pid())
		switch {
		case err == nil:
			id = info.ContainerID
			file.SetRuntimeContainerID(id)
		case !errors.Is(err, container.ErrContainerNotFound):
			return false
		}
	}
	name, ok := d.inventory.ServiceNameForContainerID(id)
	// Container identity takes priority; host processes can use VM membership.
	if !ok && d.instanceID != "" {
		name, ok = d.inventory.ServiceNameForInstanceID(d.instanceID)
	}
	if !ok {
		name = fallbackName
	}
	if service.UID.Name == name {
		return false
	}
	service.UID.Name = name
	file.SetUID(service.UID)
	return true
}
