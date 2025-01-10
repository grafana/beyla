package discover

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/mariomac/pipes/pipe"

	"github.com/grafana/beyla/pkg/internal/helpers/container"
	"github.com/grafana/beyla/pkg/internal/kube"
	"github.com/grafana/beyla/pkg/kubecache/informer"
	"github.com/grafana/beyla/pkg/services"
	"github.com/grafana/beyla/pkg/transform"
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
	processByContainer map[string]processAttrs

	podsInfoCh chan Event[*informer.ObjectMeta]
}

// kubeMetadataProvider abstracts kube.MetadataProvider for easier dependency
// injection in tests
type kubeMetadataProvider interface {
	IsKubeEnabled() bool
	Get(context.Context) (*kube.Store, error)
}

func WatcherKubeEnricherProvider(
	ctx context.Context,
	kubeMetaProvider kubeMetadataProvider,
) pipe.MiddleProvider[[]Event[processAttrs], []Event[processAttrs]] {
	return func() (pipe.MiddleFunc[[]Event[processAttrs], []Event[processAttrs]], error) {
		if !kubeMetaProvider.IsKubeEnabled() {
			return pipe.Bypass[[]Event[processAttrs]](), nil
		}
		store, err := kubeMetaProvider.Get(ctx)
		if err != nil {
			return nil, fmt.Errorf("instantiating WatcherKubeEnricher: %w", err)
		}
		wk := watcherKubeEnricher{
			log:                slog.With("component", "discover.watcherKubeEnricher"),
			store:              store,
			containerByPID:     map[PID]container.Info{},
			processByContainer: map[string]processAttrs{},
			podsInfoCh:         make(chan Event[*informer.ObjectMeta], 10),
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
	if event.GetResource().GetPod() == nil {
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

// enrich listens for any potential instrumentable process from three asyncronous sources:
// ProcessWatcher, and the ReplicaSet and Pod informers from kube.Store.
// We can't assume any order in the reception of the events, so we always keep an in-memory
// snapshot of the process-pod tuple that is updated as long as each event
// is received from different sources.
func (wk *watcherKubeEnricher) enrich(in <-chan []Event[processAttrs], out chan<- []Event[processAttrs]) {
	wk.log.Debug("starting watcherKubeEnricher")
	// the initialization needs to go in a different thread,
	// as the subscription "welcome message" would otherwise be blocked
	// trying to send events to the wk.podsInfoCh channel
	// before the enrich loop has the chance to receive them
	go wk.store.Subscribe(wk)

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

func (wk *watcherKubeEnricher) enrichPodEvent(podEvent Event[*informer.ObjectMeta], out chan<- []Event[processAttrs]) {
	switch podEvent.Type {
	case EventCreated:
		wk.log.Debug("Pod added",
			"namespace", podEvent.Obj.Namespace, "name", podEvent.Obj.Name,
			"containers", podEvent.Obj.Pod.Containers)
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
			wk.mt.Lock()
			if cnt, ok := wk.containerByPID[procEvent.Obj.pid]; ok {
				delete(wk.processByContainer, cnt.ContainerID)
			}
			delete(wk.containerByPID, procEvent.Obj.pid)
			wk.store.DeleteProcess(uint32(procEvent.Obj.pid))
			wk.mt.Unlock()
			// no need to decorate deleted processes
			eventsWithMeta = append(eventsWithMeta, procEvent)
		}
	}
	out <- eventsWithMeta
}

func (wk *watcherKubeEnricher) onNewProcess(procInfo processAttrs) (processAttrs, bool) {
	wk.mt.Lock()
	defer wk.mt.Unlock()
	// 1. get container owning the process and cache it
	// 2. if there is already a pod registered for that container, decorate processAttrs with pod attributes
	containerInfo, err := wk.getContainerInfo(procInfo.pid)
	if err != nil {
		// it is expected for any process not running inside a container
		wk.log.Debug("can't get container info for PID", "pid", procInfo.pid, "error", err)
		return processAttrs{}, false
	}

	wk.processByContainer[containerInfo.ContainerID] = procInfo

	if pod := wk.store.PodByContainerID(containerInfo.ContainerID); pod != nil {
		procInfo = withMetadata(procInfo, pod)
	}
	return procInfo, true
}

func (wk *watcherKubeEnricher) onNewPod(pod *informer.ObjectMeta) []Event[processAttrs] {
	wk.mt.RLock()
	defer wk.mt.RUnlock()
	var events []Event[processAttrs]
	for _, cnt := range pod.Pod.Containers {
		if procInfo, ok := wk.processByContainer[cnt.Id]; ok {
			events = append(events, Event[processAttrs]{
				Type: EventCreated,
				Obj:  withMetadata(procInfo, pod),
			})
		}
	}
	return events
}

func (wk *watcherKubeEnricher) onDeletedPod(pod *informer.ObjectMeta) {
	wk.mt.Lock()
	defer wk.mt.Unlock()
	for _, cnt := range pod.Pod.Containers {
		if pbc, ok := wk.processByContainer[cnt.Id]; ok {
			delete(wk.containerByPID, pbc.pid)
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
func withMetadata(pp processAttrs, info *informer.ObjectMeta) processAttrs {

	ownerName := info.Name
	if topOwner := kube.TopOwner(info.Pod); topOwner != nil {
		ownerName = topOwner.Name
	}

	ret := pp
	ret.metadata = map[string]string{
		services.AttrNamespace: info.Namespace,
		services.AttrPodName:   info.Name,
		services.AttrOwnerName: ownerName,
	}
	ret.podLabels = info.Labels

	// add any other owner name (they might be several, e.g. replicaset and deployment)
	for _, owner := range info.Pod.Owners {
		ret.metadata[transform.OwnerLabelName(owner.Kind).Prom()] = owner.Name
	}
	return ret
}
