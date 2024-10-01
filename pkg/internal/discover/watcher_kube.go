package discover

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/mariomac/pipes/pipe"
	"k8s.io/client-go/tools/cache"

	attr "github.com/grafana/beyla/pkg/export/attributes/names"
	"github.com/grafana/beyla/pkg/internal/helpers/container"
	"github.com/grafana/beyla/pkg/internal/helpers/maps"
	"github.com/grafana/beyla/pkg/internal/imetrics"
	"github.com/grafana/beyla/pkg/internal/kube"
	"github.com/grafana/beyla/pkg/services"
)

// injectable functions for testing
var (
	containerInfoForPID = container.InfoForPID
)

// kubeMetadata is implemented by kube.Metadata
type kubeMetadata interface {
	GetContainerPod(containerID string) (*kube.PodInfo, bool)
	AddPodEventHandler(handler cache.ResourceEventHandler) error
}

// watcherKubeEnricher keeps an update relational snapshot of the in-host process-pods-deployments,
// which is continuously updated from two sources: the input from the ProcessWatcher and the kube.Metadata informers.
type watcherKubeEnricher struct {
	informer kubeMetadata

	log *slog.Logger
	m   imetrics.Reporter
	// cached system objects
	containerByPID     map[PID]container.Info
	processByContainer map[string]processAttrs
	// podByOwners indexes all the PodInfos owned by a given ReplicaSet
	// we use our own indexer instead an informer indexer because we need a 1:N relation while
	// the other indices provide N:1 relation
	// level-1 key: replicaset ns/name. Level-2 key: Pod name
	podsByOwner maps.Map2[nsName, string, *kube.PodInfo]

	podsInfoCh chan Event[*kube.PodInfo]
}

type nsName struct {
	namespace string
	name      string
}

// kubeMetadataProvider abstracts kube.MetadataProvider for easier dependency
// injection in tests
type kubeMetadataProvider interface {
	IsKubeEnabled() bool
	Get(context.Context) (*kube.Metadata, error)
}

func WatcherKubeEnricherProvider(
	ctx context.Context,
	informerProvider kubeMetadataProvider,
	m imetrics.Reporter,
) pipe.MiddleProvider[[]Event[processAttrs], []Event[processAttrs]] {
	return func() (pipe.MiddleFunc[[]Event[processAttrs], []Event[processAttrs]], error) {
		if !informerProvider.IsKubeEnabled() {
			return pipe.Bypass[[]Event[processAttrs]](), nil
		}
		informer, err := informerProvider.Get(ctx)
		if err != nil {
			return nil, fmt.Errorf("instantiating WatcherKubeEnricher: %w", err)
		}
		wk := watcherKubeEnricher{informer: informer, m: m}
		if err := wk.init(); err != nil {
			return nil, err
		}

		return wk.enrich, nil
	}
}

func (wk *watcherKubeEnricher) init() error {
	wk.log = slog.With("component", "discover.watcherKubeEnricher")
	wk.containerByPID = map[PID]container.Info{}
	wk.processByContainer = map[string]processAttrs{}
	wk.podsByOwner = maps.Map2[nsName, string, *kube.PodInfo]{}

	// the podsInfoCh channel will receive any update about pods being created or deleted
	wk.podsInfoCh = make(chan Event[*kube.PodInfo], 10)
	if err := wk.informer.AddPodEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod := obj.(*kube.PodInfo)
			d := time.Since(pod.CreationTimestamp.Time)
			wk.podsInfoCh <- Event[*kube.PodInfo]{Type: EventCreated, Obj: obj.(*kube.PodInfo)}
			wk.m.InformerAddDuration("pod", d)
		},
		UpdateFunc: func(_, newObj interface{}) {
			pod := newObj.(*kube.PodInfo)
			d := time.Since(pod.CreationTimestamp.Time)
			wk.podsInfoCh <- Event[*kube.PodInfo]{Type: EventCreated, Obj: newObj.(*kube.PodInfo)}
			wk.m.InformerUpdateDuration("pod", d)
		},
		DeleteFunc: func(obj interface{}) {
			wk.podsInfoCh <- Event[*kube.PodInfo]{Type: EventDeleted, Obj: obj.(*kube.PodInfo)}
		},
	}); err != nil {
		return fmt.Errorf("can't register watcherKubeEnricher as Pod event handler in the K8s informer: %w", err)
	}

	return nil
}

// enrich listens for any potential instrumentable process from three asyncronous sources:
// ProcessWatcher, and the ReplicaSet and Pod informers from kube.Metadata.
// We can't assume any order in the reception of the events, so we always keep an in-memory
// snapshot of the process-pod-replicaset 3-tuple that is updated as long as each event
// is received from different sources.
func (wk *watcherKubeEnricher) enrich(in <-chan []Event[processAttrs], out chan<- []Event[processAttrs]) {
	wk.log.Debug("starting watcherKubeEnricher")
	for {
		select {
		case podEvent := <-wk.podsInfoCh:
			wk.enrichPodEvent(podEvent, out)
		case processEvents, ok := <-in:
			if !ok {
				wk.log.Debug("input channel closed. Stopping")
				return
			}
			wk.enrichProcessEvent(processEvents, out)
		}
	}
}

func (wk *watcherKubeEnricher) enrichPodEvent(podEvent Event[*kube.PodInfo], out chan<- []Event[processAttrs]) {
	switch podEvent.Type {
	case EventCreated:
		wk.log.Debug("Pod added",
			"namespace", podEvent.Obj.Namespace, "name", podEvent.Obj.Name, "containers", podEvent.Obj.ContainerIDs)
		if events := wk.onNewPod(podEvent.Obj); len(events) > 0 {
			out <- events
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
func (wk *watcherKubeEnricher) enrichProcessEvent(processEvents []Event[processAttrs], out chan<- []Event[processAttrs]) {
	eventsWithMeta := make([]Event[processAttrs], 0, len(processEvents))
	for _, procEvent := range processEvents {
		switch procEvent.Type {
		case EventCreated:
			wk.log.Debug("new process", "pid", procEvent.Obj.pid)
			if procWithMeta, ok := wk.onNewProcess(procEvent.Obj); ok {
				eventsWithMeta = append(eventsWithMeta, Event[processAttrs]{
					Type: EventCreated,
					Obj:  procWithMeta,
				})
			}
		case EventDeleted:
			wk.log.Debug("process stopped", "pid", procEvent.Obj.pid)
			delete(wk.containerByPID, procEvent.Obj.pid)
			// no need to decorate deleted processes
			eventsWithMeta = append(eventsWithMeta, procEvent)
		}
	}
	out <- eventsWithMeta
}

func (wk *watcherKubeEnricher) onNewProcess(procInfo processAttrs) (processAttrs, bool) {
	// 1. get container owning the process and cache it
	// 2. if there is already a pod registered for that container, decorate processAttrs with pod attributes
	containerInfo, err := wk.getContainerInfo(procInfo.pid)
	if err != nil {
		// it is expected for any process not running inside a container
		wk.log.Warn("can't get container info for PID", "pid", procInfo.pid, "error", err)
		return processAttrs{}, false
	}

	wk.processByContainer[containerInfo.ContainerID] = procInfo

	if pod, ok := wk.informer.GetContainerPod(containerInfo.ContainerID); ok {
		procInfo = withMetadata(procInfo, pod)
	}
	return procInfo, true
}

func (wk *watcherKubeEnricher) onNewPod(pod *kube.PodInfo) []Event[processAttrs] {
	wk.updateNewPodsByOwnerIndex(pod)

	var events []Event[processAttrs]
	for _, containerID := range pod.ContainerIDs {
		if procInfo, ok := wk.processByContainer[containerID]; ok {
			events = append(events, Event[processAttrs]{
				Type: EventCreated,
				Obj:  withMetadata(procInfo, pod),
			})
		}
	}
	return events
}

func (wk *watcherKubeEnricher) onDeletedPod(pod *kube.PodInfo) {
	wk.updateDeletedPodsByOwnerIndex(pod)
	for _, containerID := range pod.ContainerIDs {
		delete(wk.processByContainer, containerID)
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

func (wk *watcherKubeEnricher) updateNewPodsByOwnerIndex(pod *kube.PodInfo) {
	if pod.Owner != nil {
		wk.podsByOwner.Put(nsName{namespace: pod.Namespace, name: pod.Owner.Name}, pod.Name, pod)
	}
}

func (wk *watcherKubeEnricher) updateDeletedPodsByOwnerIndex(pod *kube.PodInfo) {
	if pod.Owner != nil {
		wk.podsByOwner.Delete(nsName{namespace: pod.Namespace, name: pod.Owner.Name}, pod.Name)
	}
}

// withMetadata returns a copy with a new map to avoid race conditions in later stages of the pipeline
func withMetadata(pp processAttrs, info *kube.PodInfo) processAttrs {
	ret := pp
	ret.metadata = map[string]string{
		services.AttrNamespace: info.Namespace,
		services.AttrPodName:   info.Name,
	}
	ret.podLabels = info.Labels

	if info.Owner != nil {
		ret.metadata[attr.Name(info.Owner.LabelName).Prom()] = info.Owner.Name
		topOwner := info.Owner.TopOwner()
		ret.metadata[attr.Name(topOwner.LabelName).Prom()] = topOwner.Name
		ret.metadata[services.AttrOwnerName] = topOwner.Name
	}
	return ret
}
