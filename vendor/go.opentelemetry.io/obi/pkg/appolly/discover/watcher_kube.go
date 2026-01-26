// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/internal/helpers/container"
	ikube "go.opentelemetry.io/obi/pkg/internal/kube"
	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/transform"
)

// injectable functions for testing
var (
	containerInfoForPID = container.InfoForPID
)

// watcherKubeEnricher keeps an update relational snapshot of the in-host process-pods-deployments,
// which is continuously updated from two sources: the input from the ProcessWatcher and the kube.Store.
type watcherKubeEnricher struct {
	store *kube.Store

	log *slog.Logger

	// cached system objects
	mt                 sync.RWMutex
	containerByPID     map[PID]container.Info
	processByContainer map[string][]ProcessAttrs

	podsInfoCh chan Event[*informer.ObjectMeta]
	output     *msg.Queue[[]Event[ProcessAttrs]]
	input      <-chan []Event[ProcessAttrs]
}

// kubeMetadataProvider abstracts kube.MetadataProvider for easier dependency
// injection in tests
type kubeMetadataProvider interface {
	IsKubeEnabled() bool
	Get(context.Context) (*kube.Store, error)
}

func WatcherKubeEnricherProvider(
	kubeMetaProvider kubeMetadataProvider,
	input, output *msg.Queue[[]Event[ProcessAttrs]],
) swarm.InstanceFunc {
	return func(ctx context.Context) (swarm.RunFunc, error) {
		if !kubeMetaProvider.IsKubeEnabled() {
			return swarm.Bypass(input, output)
		}
		store, err := kubeMetaProvider.Get(ctx)
		if err != nil {
			return nil, fmt.Errorf("instantiating WatcherKubeEnricher: %w", err)
		}
		wk := watcherKubeEnricher{
			log:                slog.With("component", "discover.watcherKubeEnricher"),
			store:              store,
			containerByPID:     map[PID]container.Info{},
			processByContainer: map[string][]ProcessAttrs{},
			podsInfoCh:         make(chan Event[*informer.ObjectMeta], 10),
			input:              input.Subscribe(msg.SubscriberName("WatcherKubeEnricher")),
			output:             output,
		}
		return wk.enrich, nil
	}
}

func (wk *watcherKubeEnricher) ID() string { return "unique-watcher-kube-enricher-id" }

// On is invoked every time an object metadata instance is stored or deleted in the
// kube.Store. It will just forward the event via the channel for proper asynchronous
// handling in the enrich main loop
func (wk *watcherKubeEnricher) On(event *informer.Event) error {
	// ignoring updates on non-pod resources
	if event.Resource == nil || event.GetResource().GetPod() == nil {
		return nil
	}
	switch event.Type {
	case informer.EventType_CREATED, informer.EventType_UPDATED:
		wk.podsInfoCh <- Event[*informer.ObjectMeta]{Type: EventCreated, Obj: event.Resource}
	case informer.EventType_DELETED:
		wk.podsInfoCh <- Event[*informer.ObjectMeta]{Type: EventDeleted, Obj: event.Resource}
	default:
		wk.log.Debug("ignoring unknown event type", "event", event)
	}
	return nil
}

// enrich listens for any potential instrumentable process from three asynchronous sources:
// ProcessWatcher, and the ReplicaSet and Pod informers from kube.Store.
// We can't assume any order in the reception of the events, so we always keep an in-memory
// snapshot of the process-pod tuple that is updated as long as each event
// is received from different sources.
func (wk *watcherKubeEnricher) enrich(_ context.Context) {
	defer wk.output.Close()

	wk.log.Debug("starting watcherKubeEnricher")
	// the initialization needs to go in a different thread,
	// as the subscription "welcome message" would otherwise be blocked
	// trying to send events to the wk.podsInfoCh channel
	// before the enrich loop has the chance to receive them
	go wk.store.Subscribe(wk)

	for {
		select {
		case podEvent := <-wk.podsInfoCh:
			wk.enrichPodEvent(podEvent)
		case processEvents, ok := <-wk.input:
			if !ok {
				wk.log.Debug("input channel closed. Stopping")
				return
			}
			wk.enrichProcessEvent(processEvents)
		}
	}
}

func (wk *watcherKubeEnricher) enrichPodEvent(podEvent Event[*informer.ObjectMeta]) {
	switch podEvent.Type {
	case EventCreated:
		wk.log.Debug("Pod added",
			"namespace", podEvent.Obj.Namespace, "name", podEvent.Obj.Name,
			"containers", podEvent.Obj.Pod.Containers)
		if events := wk.onNewPod(podEvent.Obj); len(events) > 0 {
			wk.output.Send(events)
		}
	case EventDeleted:
		wk.log.Debug("Pod deleted", "namespace", podEvent.Obj.Namespace, "name", podEvent.Obj.Name)
		wk.onDeletedPod(podEvent.Obj)
		// we don't forward Pod deletion, as it will be eventually done
		// when the process is removed
	}
}

// enrichProcessEvent creates a copy of the process information in the input slice, but decorated with
// K8s attributes, if any. It also handles deletion of processes
func (wk *watcherKubeEnricher) enrichProcessEvent(processEvents []Event[ProcessAttrs]) {
	eventsWithMeta := make([]Event[ProcessAttrs], 0, len(processEvents))
	for _, procEvent := range processEvents {
		switch procEvent.Type {
		case EventCreated:
			wk.log.Debug("new process", "pid", procEvent.Obj.pid)
			if procWithMeta, ok := wk.onNewProcess(procEvent.Obj); ok {
				eventsWithMeta = append(eventsWithMeta, Event[ProcessAttrs]{
					Type: EventCreated,
					Obj:  procWithMeta,
				})
			}
		case EventDeleted:
			wk.log.Debug("process stopped", "pid", procEvent.Obj.pid)
			wk.onProcessTerminate(procEvent.Obj)
			// no need to decorate deleted processes
			eventsWithMeta = append(eventsWithMeta, procEvent)
		}
	}

	if len(eventsWithMeta) > 0 {
		wk.output.Send(eventsWithMeta)
	}
}

func (wk *watcherKubeEnricher) onNewProcess(procInfo ProcessAttrs) (ProcessAttrs, bool) {
	wk.mt.Lock()
	defer wk.mt.Unlock()
	// 1. get container owning the process and cache it
	// 2. if there is already a pod registered for that container, decorate processAttrs with pod attributes
	containerInfo, err := wk.getContainerInfo(procInfo.pid)
	if err != nil {
		// it is expected for any process not running inside a container
		wk.log.Debug("can't get container info for PID", "pid", procInfo.pid, "error", err)
		return ProcessAttrs{}, false
	}

	wk.log.Debug("found container info for process", "pid", procInfo.pid, "container", containerInfo.ContainerID)

	wk.processByContainer[containerInfo.ContainerID] = append(wk.processByContainer[containerInfo.ContainerID], procInfo)

	if pod := wk.store.PodByContainerID(containerInfo.ContainerID); pod != nil {
		wk.log.Debug("matched process with running container", "pid", procInfo.pid, "container", containerInfo.ContainerID)
		procInfo = withMetadata(procInfo, pod.Meta, containerInfo.ContainerID)
	}
	return procInfo, true
}

func (wk *watcherKubeEnricher) onProcessTerminate(procInfo ProcessAttrs) {
	wk.mt.Lock()
	defer wk.mt.Unlock()

	if cnt, ok := wk.containerByPID[procInfo.pid]; ok {
		if pidProcInfos, ok := wk.processByContainer[cnt.ContainerID]; ok {
			filtered := []ProcessAttrs{}

			for _, pidProcInfo := range pidProcInfos {
				if pidProcInfo.pid != procInfo.pid {
					filtered = append(filtered, pidProcInfo)
					continue
				}
				wk.log.Debug("removing process mapping", "container", cnt.ContainerID, "pid", pidProcInfo.pid)
			}
			if len(filtered) == 0 {
				delete(wk.processByContainer, cnt.ContainerID)
			} else {
				wk.processByContainer[cnt.ContainerID] = filtered
			}
		}
	}
	delete(wk.containerByPID, procInfo.pid)
	wk.store.DeleteProcess(uint32(procInfo.pid))
}

func (wk *watcherKubeEnricher) onNewPod(pod *informer.ObjectMeta) []Event[ProcessAttrs] {
	wk.mt.RLock()
	defer wk.mt.RUnlock()
	var events []Event[ProcessAttrs]
	for _, cnt := range pod.Pod.Containers {
		wk.log.Debug("looking up running process for pod container", "container", cnt.Id)
		if procInfos, ok := wk.processByContainer[cnt.Id]; ok {
			for _, procInfo := range procInfos {
				wk.log.Debug("matched pod with running process", "container", cnt.Id, "pid", procInfo.pid)
				events = append(events, Event[ProcessAttrs]{
					Type: EventCreated,
					Obj:  withMetadata(procInfo, pod, cnt.Id),
				})
			}
		}
	}
	return events
}

func (wk *watcherKubeEnricher) onDeletedPod(pod *informer.ObjectMeta) {
	wk.mt.Lock()
	defer wk.mt.Unlock()
	for _, cnt := range pod.Pod.Containers {
		if pbcs, ok := wk.processByContainer[cnt.Id]; ok {
			for _, pbc := range pbcs {
				delete(wk.containerByPID, pbc.pid)
			}
		}
		delete(wk.processByContainer, cnt.Id)
	}
}

func (wk *watcherKubeEnricher) getContainerInfo(pid PID) (container.Info, error) {
	if cntInfo, ok := wk.containerByPID[pid]; ok {
		return cntInfo, nil
	}
	cntInfo, err := containerInfoForPID(uint32(pid))
	if err != nil {
		return container.Info{}, err
	}
	wk.containerByPID[pid] = cntInfo
	return cntInfo, nil
}

// withMetadata returns a copy with a new map to avoid race conditions in later stages of the pipeline
func withMetadata(pp ProcessAttrs, info *informer.ObjectMeta, containerID string) ProcessAttrs {
	ownerName := info.Name
	if topOwner := ikube.TopOwner(info.Pod); topOwner != nil {
		ownerName = topOwner.Name
	}

	ret := pp
	ret.metadata = map[string]string{
		services.AttrNamespace: info.Namespace,
		services.AttrPodName:   info.Name,
		services.AttrOwnerName: ownerName,
	}
	ret.podLabels = info.Labels
	ret.podAnnotations = info.Annotations

	// add any other owner name (they might be several, e.g. replicaset and deployment)
	for _, owner := range info.Pod.Owners {
		ret.metadata[transform.OwnerLabelName(owner.Kind).Prom()] = owner.Name
	}
	if containerID == "" {
		return ret
	}
	for _, podContainer := range info.Pod.Containers {
		if podContainer.Id == containerID {
			ret.metadata[services.AttrContainerName] = podContainer.Name
			break
		}
	}
	return ret
}
