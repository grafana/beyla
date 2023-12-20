package discover

import (
	"fmt"
	"log/slog"

	"github.com/mariomac/pipes/pkg/node"
	"k8s.io/client-go/tools/cache"

	"github.com/grafana/beyla/pkg/internal/discover/services"
	"github.com/grafana/beyla/pkg/internal/helpers"
	"github.com/grafana/beyla/pkg/internal/helpers/container"
	"github.com/grafana/beyla/pkg/internal/kube"
)

// injectable functions for testing
var (
	containerInfoForPID = container.InfoForPID
)

// kubeMetadata is implemented by kube.Metadata
type kubeMetadata interface {
	FetchPodOwnerInfo(pod *kube.PodInfo)
	GetContainerPod(containerID string) (*kube.PodInfo, bool)
	AddPodEventHandler(handler cache.ResourceEventHandler) error
	AddReplicaSetEventHandler(handler cache.ResourceEventHandler) error
}

// WatcherKubeEnricher keeps an update relational snapshot of the in-host process-pods-deployments,
// which is continuously updated from two sources: the input from the ProcessWatcher and the kube.Metadata informers.
type WatcherKubeEnricher struct {
	Informer kubeMetadata

	log *slog.Logger

	// cached system objects
	containerByPID     map[PID]container.Info
	processByContainer map[string]processAttrs
	// podByOwners indexes all the PodInfos owned by a given ReplicaSet
	// we use our own indexer instead an informer indexer because we need a 1:N relation while
	// the other indices provide N:1 relation
	// level-1 key: replicaset ns/name. Level-2 key: Pod name
	podsByOwner helpers.Map2[nsName, string, *kube.PodInfo]

	podsInfoCh chan Event[*kube.PodInfo]
	rsInfoCh   chan Event[*kube.ReplicaSetInfo]
}

type nsName struct {
	namespace string
	name      string
}

func WatcherKubeEnricherProvider(wk *WatcherKubeEnricher) (node.MiddleFunc[[]Event[processAttrs], []Event[processAttrs]], error) {
	if err := wk.init(); err != nil {
		return nil, err
	}

	return wk.enrich, nil
}

func (wk *WatcherKubeEnricher) init() error {
	wk.log = slog.With("component", "discover.WatcherKubeEnricher")
	wk.containerByPID = map[PID]container.Info{}
	wk.processByContainer = map[string]processAttrs{}
	wk.podsByOwner = helpers.Map2[nsName, string, *kube.PodInfo]{}

	// the podsInfoCh channel will receive any update about pods being created or deleted
	wk.podsInfoCh = make(chan Event[*kube.PodInfo], 10)
	if err := wk.Informer.AddPodEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			wk.podsInfoCh <- Event[*kube.PodInfo]{Type: EventCreated, Obj: obj.(*kube.PodInfo)}
		},
		UpdateFunc: func(_, newObj interface{}) {
			wk.podsInfoCh <- Event[*kube.PodInfo]{Type: EventCreated, Obj: newObj.(*kube.PodInfo)}
		},
		DeleteFunc: func(obj interface{}) {
			wk.podsInfoCh <- Event[*kube.PodInfo]{Type: EventDeleted, Obj: obj.(*kube.PodInfo)}
		},
	}); err != nil {
		return fmt.Errorf("can't register WatcherKubeEnricher as Pod event handler in the K8s informer: %w", err)
	}

	// the rsInfoCh channel will receive any update about replicasets being created or deleted
	wk.rsInfoCh = make(chan Event[*kube.ReplicaSetInfo], 10)
	if err := wk.Informer.AddReplicaSetEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			wk.rsInfoCh <- Event[*kube.ReplicaSetInfo]{Type: EventCreated, Obj: obj.(*kube.ReplicaSetInfo)}
		},
		UpdateFunc: func(_, newObj interface{}) {
			wk.rsInfoCh <- Event[*kube.ReplicaSetInfo]{Type: EventCreated, Obj: newObj.(*kube.ReplicaSetInfo)}
		},
		DeleteFunc: func(obj interface{}) {
			wk.rsInfoCh <- Event[*kube.ReplicaSetInfo]{Type: EventDeleted, Obj: obj.(*kube.ReplicaSetInfo)}
		},
	}); err != nil {
		return fmt.Errorf("can't register WatcherKubeEnricher as ReplicaSet event handler in the K8s informer: %w", err)
	}
	return nil
}

// enrich listens for any potential instrumentable process from three asyncronous sources:
// ProcessWatcher, and the ReplicaSet and Pod informers from kube.Metadata.
// We can't assume any order in the reception of the events, so we always keep an in-memory
// snapshot of the process-pod-replicaset 3-tuple that is updated as long as each event
// is received from different sources.
func (wk *WatcherKubeEnricher) enrich(in <-chan []Event[processAttrs], out chan<- []Event[processAttrs]) {
	wk.log.Debug("starting WatcherKubeEnricher")
	for {
		select {
		case podEvent := <-wk.podsInfoCh:
			wk.enrichPodEvent(podEvent, out)
		case rsEvent := <-wk.rsInfoCh:
			wk.enrichReplicaSetEvent(rsEvent, out)
		case processEvents, ok := <-in:
			if !ok {
				wk.log.Debug("input channel closed. Stopping")
				return
			}
			wk.enrichProcessEvent(processEvents, out)
		}
	}
}

func (wk *WatcherKubeEnricher) enrichPodEvent(podEvent Event[*kube.PodInfo], out chan<- []Event[processAttrs]) {
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

func (wk *WatcherKubeEnricher) enrichReplicaSetEvent(rsEvent Event[*kube.ReplicaSetInfo], out chan<- []Event[processAttrs]) {
	switch rsEvent.Type {
	case EventCreated:
		wk.log.Debug("ReplicaSet added", "namespace",
			rsEvent.Obj.Namespace, "name", rsEvent.Obj.Name, "deployment", rsEvent.Obj.DeploymentName)
		out <- wk.onNewReplicaSet(rsEvent.Obj)
	case EventDeleted:
		wk.log.Debug("ReplicaSet deleted", "namespace", rsEvent.Obj.Namespace, "name", rsEvent.Obj.Name)
		wk.onDeletedReplicaSet(rsEvent.Obj)
		// we don't forward replicaset deletion, as it will be eventually done
		// when the process is removed
	}
}

// enrichProcessEvent creates a copy of the process information in the input slice, but decorated with
// K8s attributes, if any. It also handles deletion of processes
func (wk *WatcherKubeEnricher) enrichProcessEvent(processEvents []Event[processAttrs], out chan<- []Event[processAttrs]) {
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

func (wk *WatcherKubeEnricher) onNewProcess(procInfo processAttrs) (processAttrs, bool) {
	// 1. get container owning the process and cache it
	// 2. if there is already a pod registered for that container, decorate processAttrs with pod attributes
	containerInfo, err := wk.getContainerInfo(procInfo.pid)
	if err != nil {
		// it is expected for any process not running inside a container
		wk.log.Debug("can't get container info for PID", "pid", procInfo.pid, "error", err)
		return processAttrs{}, false
	}

	wk.processByContainer[containerInfo.ContainerID] = procInfo

	if pod, ok := wk.getPodInfo(containerInfo.ContainerID); ok {
		procInfo = withMetadata(procInfo, pod)
	}
	return procInfo, true
}

func (wk *WatcherKubeEnricher) onNewPod(pod *kube.PodInfo) []Event[processAttrs] {
	wk.updateNewPodsByOwnerIndex(pod)

	// update PodInfo with its owner's info, if any
	// for each container in the Pod
	//   - get matching process, if available
	//		- forward enriched processAttrs data
	wk.Informer.FetchPodOwnerInfo(pod)

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

func (wk *WatcherKubeEnricher) onDeletedPod(pod *kube.PodInfo) {
	wk.updateDeletedPodsByOwnerIndex(pod)
	for _, containerID := range pod.ContainerIDs {
		delete(wk.processByContainer, containerID)
	}
}

func (wk *WatcherKubeEnricher) onNewReplicaSet(rsInfo *kube.ReplicaSetInfo) []Event[processAttrs] {
	// for each Pod in the ReplicaSet
	//   for each container in the Pod
	//      - get matching process, if any
	//         - enrich and forward it
	podInfos := wk.getReplicaSetPods(rsInfo.Namespace, rsInfo.Name)
	var allProcesses []Event[processAttrs]
	for _, pod := range podInfos {
		for _, containerID := range pod.ContainerIDs {
			if procInfo, ok := wk.processByContainer[containerID]; ok {
				pod.ReplicaSetName = rsInfo.Name
				pod.DeploymentName = rsInfo.DeploymentName
				allProcesses = append(allProcesses, Event[processAttrs]{
					Type: EventCreated,
					Obj:  withMetadata(procInfo, pod),
				})
			}
		}
	}
	return allProcesses
}

func (wk *WatcherKubeEnricher) onDeletedReplicaSet(rsInfo *kube.ReplicaSetInfo) {
	wk.podsByOwner.DeleteAll(nsName{namespace: rsInfo.Namespace, name: rsInfo.Name})
}

func (wk *WatcherKubeEnricher) getContainerInfo(pid PID) (container.Info, error) {
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

func (wk *WatcherKubeEnricher) getPodInfo(containerID string) (*kube.PodInfo, bool) {
	if pod, ok := wk.Informer.GetContainerPod(containerID); ok {
		wk.Informer.FetchPodOwnerInfo(pod)
		return pod, true
	}
	return nil, false
}

func (wk *WatcherKubeEnricher) getReplicaSetPods(namespace, name string) []*kube.PodInfo {
	var podInfos []*kube.PodInfo
	if pods, ok := wk.podsByOwner[nsName{namespace: namespace, name: name}]; ok {
		podInfos = make([]*kube.PodInfo, 0, len(pods))
		for _, pod := range pods {
			podInfos = append(podInfos, pod)
		}
	}
	return podInfos
}

func (wk *WatcherKubeEnricher) updateNewPodsByOwnerIndex(pod *kube.PodInfo) {
	if pod.ReplicaSetName != "" {
		wk.podsByOwner.Put(nsName{namespace: pod.Namespace, name: pod.ReplicaSetName}, pod.Name, pod)
	}
}

func (wk *WatcherKubeEnricher) updateDeletedPodsByOwnerIndex(pod *kube.PodInfo) {
	if pod.ReplicaSetName != "" {
		wk.podsByOwner.Delete(nsName{namespace: pod.Namespace, name: pod.ReplicaSetName}, pod.Name)
	}
}

// withMetadata returns a copy with a new map to avoid race conditions in later stages of the pipeline
func withMetadata(pp processAttrs, info *kube.PodInfo) processAttrs {
	ret := pp
	ret.metadata = map[string]string{
		services.AttrNamespace: info.Namespace,
		services.AttrPodName:   info.Name,
	}
	if info.DeploymentName != "" {
		ret.metadata[services.AttrDeploymentName] = info.DeploymentName
	}
	if info.ReplicaSetName != "" {
		ret.metadata[services.AttrReplicaSetName] = info.ReplicaSetName
	}
	return ret
}
