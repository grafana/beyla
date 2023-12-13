package discover

import (
	"fmt"
	"log/slog"

	"github.com/mariomac/pipes/pkg/node"
	"k8s.io/client-go/tools/cache"

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
	AddPodEventHandler(handler cache.ResourceEventHandler) (cache.ResourceEventHandlerRegistration, error)
	AddReplicaSetEventHandler(handler cache.ResourceEventHandler) (cache.ResourceEventHandlerRegistration, error)
}

type WatcherKubeEnricher struct {
	log      *slog.Logger
	informer kubeMetadata

	// caches
	containerByPID     map[PID]container.Info
	processByContainer map[string]*processPorts
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

func WatcherKubeEnricherProvider(wk *WatcherKubeEnricher) (node.MiddleFunc[Event[processPorts], Event[processPorts]], error) {
	if err := wk.init(); err != nil {
		return nil, err
	}

	return wk.enrich, nil
}

func (wk *WatcherKubeEnricher) init() error {
	wk.log = slog.With("component", "discover.WatcherKubeEnricher")
	wk.containerByPID = map[PID]container.Info{}
	wk.processByContainer = map[string]*processPorts{}
	wk.podsByOwner = helpers.Map2[nsName, string, *kube.PodInfo]{}

	wk.podsInfoCh = make(chan Event[*kube.PodInfo], 10)
	_, err := wk.informer.AddPodEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			wk.podsInfoCh <- Event[*kube.PodInfo]{Type: EventCreated, Obj: obj.(*kube.PodInfo)}
		},
		DeleteFunc: func(obj interface{}) {
			wk.podsInfoCh <- Event[*kube.PodInfo]{Type: EventDeleted, Obj: obj.(*kube.PodInfo)}
		},
	})
	if err != nil {
		return fmt.Errorf("can't register WatcherKubeEnricher as Pod event handler in the K8s informer: %w", err)
	}
	wk.rsInfoCh = make(chan Event[*kube.ReplicaSetInfo], 10)
	_, err = wk.informer.AddReplicaSetEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			wk.rsInfoCh <- Event[*kube.ReplicaSetInfo]{Type: EventCreated, Obj: obj.(*kube.ReplicaSetInfo)}
		},
		DeleteFunc: func(obj interface{}) {
			wk.rsInfoCh <- Event[*kube.ReplicaSetInfo]{Type: EventDeleted, Obj: obj.(*kube.ReplicaSetInfo)}
		},
	})
	if err != nil {
		return fmt.Errorf("can't register WatcherKubeEnricher as ReplicaSet event handler in the K8s informer: %w", err)
	}
	return nil
}

func (wk *WatcherKubeEnricher) enrich(in <-chan Event[processPorts], out chan<- Event[processPorts]) {
	wk.log.Debug("starting WatcherKubeEnricher")
	for {
		select {
		case podEvent := <-wk.podsInfoCh:
			switch podEvent.Type {
			case EventCreated:
				for _, pp := range wk.onNewPod(podEvent.Obj) {
					out <- Event[processPorts]{Type: EventCreated, Obj: pp}
				}
			case EventDeleted:
				wk.onDeletedPod(podEvent.Obj)
			}
		case rsEvent := <-wk.rsInfoCh:
			switch rsEvent.Type {
			case EventCreated:
				for _, pp := range wk.onNewReplicaSet(rsEvent.Obj) {
					out <- Event[processPorts]{Type: EventCreated, Obj: pp}
				}
			case EventDeleted:
				// TODO
			}
		case pp, ok := <-in:
			if !ok {
				wk.log.Debug("input channel closed. Stopping")
				return
			}
			switch pp.Type {
			case EventCreated:
				wk.onNewProcess(&pp.Obj)
				out <- pp
			case EventDeleted:
				wk.onDeletedProcess(&pp.Obj)
			}
		}
	}
}

func (wk *WatcherKubeEnricher) onNewProcess(pp *processPorts) {
	containerInfo, err := wk.getContainerInfo(pp.pid)
	if err != nil {
		// it is expected for any process not running inside a container
		wk.log.Debug("can't get container info for PID. Will try to match against process info",
			"pid", pp.pid, "error", err)
		return
	}

	wk.processByContainer[containerInfo.ContainerID] = pp

	pod, ok := wk.getPodInfo(containerInfo.ContainerID)
	if ok {
		pp.ownerPod = pod
	}
}

func (wk *WatcherKubeEnricher) onDeletedProcess(pp *processPorts) {
	delete(wk.containerByPID, pp.pid)
}

func (wk *WatcherKubeEnricher) onNewPod(pod *kube.PodInfo) []processPorts {
	wk.updateNewPodsByOwnerIndex(pod)

	// get deployment/rs info
	// get stored process, if any
	// if all the information is available
	//		- forward enriched processPorts data
	// else
	// 		for each pod container
	// 			- get associated process
	//			- cache by pid
	wk.informer.FetchPodOwnerInfo(pod)

	var pps []processPorts
	for _, cntID := range pod.ContainerIDs {
		if pp, ok := wk.processByContainer[cntID]; ok {
			pp.ownerPod = pod
			pps = append(pps, *pp)
		}
	}

	return pps
}

func (wk *WatcherKubeEnricher) onDeletedPod(pod *kube.PodInfo) {
	wk.updateDeletedPodsByOwnerIndex(pod)
	for _, cnt := range pod.ContainerIDs {
		delete(wk.processByContainer, cnt)
	}
}

func (wk *WatcherKubeEnricher) onNewReplicaSet(p *kube.ReplicaSetInfo) []processPorts {
	// get pod info
	// get stored process, if any
	// if all the information is available
	//		- forward enriched processPorts data
	// else
	// 		cache by pod name
	podInfos := wk.getReplicaSetPods(p.Namespace, p.Name)
	var allProcessPorts []processPorts
	for _, pod := range podInfos {
		for _, cntID := range pod.ContainerIDs {
			if pp, ok := wk.processByContainer[cntID]; ok {
				pod.ReplicaSetName = p.Name
				pod.DeploymentName = p.DeploymentName
				pp.ownerPod = pod
				allProcessPorts = append(allProcessPorts, *pp)
			}
		}
	}
	return allProcessPorts
}

func (wk *WatcherKubeEnricher) onDeletedReplicaSet(p *kube.ReplicaSetInfo) {
	wk.podsByOwner.DeleteAll(nsName{namespace: p.Namespace, name: p.Name})
}

func (wk *WatcherKubeEnricher) getContainerInfo(pid PID) (container.Info, error) {
	if ci, ok := wk.containerByPID[pid]; ok {
		return ci, nil
	}
	ci, err := containerInfoForPID(uint32(pid))
	if err != nil {
		return container.Info{}, err
	}
	wk.containerByPID[pid] = ci
	return ci, nil
}

func (wk *WatcherKubeEnricher) getPodInfo(containerID string) (*kube.PodInfo, bool) {
	if pod, ok := wk.informer.GetContainerPod(containerID); ok {
		wk.informer.FetchPodOwnerInfo(pod)
		return pod, true
	}
	return nil, false
}

func (wk *WatcherKubeEnricher) getReplicaSetPods(namespace, name string) []*kube.PodInfo {
	var podInfos []*kube.PodInfo
	if pods, ok := wk.podsByOwner[nsName{namespace: namespace, name: name}]; ok {
		podInfos = make([]*kube.PodInfo, 0, len(pods))
		for _, p := range pods {
			podInfos = append(podInfos, p)
		}
	}
	return podInfos
}

func (wk *WatcherKubeEnricher) updateNewPodsByOwnerIndex(pod *kube.PodInfo) {
	for i := range pod.GetOwnerReferences() {
		or := &pod.OwnerReferences[i]
		if or.APIVersion == "apps/v1" && or.Kind == "ReplicaSet" {
			wk.podsByOwner.Put(nsName{namespace: pod.Namespace, name: or.Name}, pod.Name, pod)
			break
		}
	}
}

func (wk *WatcherKubeEnricher) updateDeletedPodsByOwnerIndex(pod *kube.PodInfo) {
	for i := range pod.GetOwnerReferences() {
		or := &pod.OwnerReferences[i]
		if or.APIVersion == "apps/v1" && or.Kind == "ReplicaSet" {
			wk.podsByOwner.Delete(nsName{namespace: pod.Namespace, name: or.Name}, pod.Name)
			break
		}
	}
}
