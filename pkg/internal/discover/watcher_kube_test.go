package discover

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/grafana/beyla/pkg/internal/helpers/container"
	"github.com/grafana/beyla/pkg/internal/kube"
)

func TestWatcherKubeEnricher(t *testing.T) {
	containerInfoForPID = fakeContainerInfo{
		123: container.Info{ContainerID: "container-123"},
	}.forPID
	informer := fakeKubeMetadata{}
	wkeNodeFunc, err := WatcherKubeEnricherProvider(&WatcherKubeEnricher{
		informer: &informer,
	})
	require.NoError(t, err)
	inputCh, outputCh := make(chan Event[processPorts], 10), make(chan Event[processPorts], 10)
	go wkeNodeFunc(inputCh, outputCh)

	inputCh <- Event[processPorts]{Type: EventCreated, Obj: processPorts{
		pid: 123, openPorts: []uint32{332}}}

	o := <-outputCh
	j, _ := json.Marshal(o.Obj.ownerPod)
	fmt.Printf("pid: %v. ports: %v. owner: %s\n", o.Obj.pid, o.Obj.openPorts, string(j))

	informer.addPod(&kube.PodInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "ns",
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps/v1",
				Kind:       "ReplicaSet",
				Name:       "rs-3321",
			}},
		},
		ContainerIDs: []string{"container-123"},
	})

	o = <-outputCh
	j, _ = json.Marshal(o.Obj.ownerPod)
	fmt.Printf("pid: %v. ports: %v. owner: %s\n", o.Obj.pid, o.Obj.openPorts, string(j))

	informer.addReplicaSet(&kube.ReplicaSetInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "rs-3321",
			Namespace: "ns",
		},
		DeploymentName: "deployment",
	})

	o = <-outputCh
	j, _ = json.Marshal(o.Obj.ownerPod)
	fmt.Printf("pid: %v. ports: %v. owner: %s\n", o.Obj.pid, o.Obj.openPorts, string(j))

	for o := range outputCh {
		j, _ := json.Marshal(o.Obj.ownerPod)
		fmt.Printf("pid: %v. ports: %v. owner: %s\n", o.Obj.pid, o.Obj.openPorts, string(j))
	}
}

// test cases
// process-pod-rs
// process-rs-pod
// pod-process-rs
// pod-rs-process
// rs-pod-process
// rs-process-pod
// process-pod (no rs)
// pod-process (no rs)
// TEST DELETION

type fakeContainerInfo map[uint32]container.Info

func (f fakeContainerInfo) forPID(pid uint32) (container.Info, error) {
	return f[pid], nil
}

type fakeKubeMetadata struct {
	podsByContainer  map[string]*kube.PodInfo
	replicaSets      map[nsName]*kube.ReplicaSetInfo
	podEventHandlers []cache.ResourceEventHandler
	rsEventhandlers  []cache.ResourceEventHandler
}

func (f *fakeKubeMetadata) addPod(pod *kube.PodInfo) {
	if f.podsByContainer == nil {
		f.podsByContainer = map[string]*kube.PodInfo{}
	}
	for _, c := range pod.ContainerIDs {
		f.podsByContainer[c] = pod
	}
	for _, eh := range f.podEventHandlers {
		eh.OnAdd(pod, false)
	}
}

func (f *fakeKubeMetadata) deletePod(pod *kube.PodInfo) {
	for _, c := range pod.ContainerIDs {
		delete(f.podsByContainer, c)
	}
	for _, eh := range f.podEventHandlers {
		eh.OnDelete(pod)
	}
}

func (f *fakeKubeMetadata) addReplicaSet(rs *kube.ReplicaSetInfo) {
	if f.replicaSets == nil {
		f.replicaSets = map[nsName]*kube.ReplicaSetInfo{}
	}
	f.replicaSets[nsName{namespace: rs.Namespace, name: rs.Name}] = rs
	for _, eh := range f.rsEventhandlers {
		eh.OnAdd(rs, false)
	}
}

func (f *fakeKubeMetadata) deleteReplicaSet(rs *kube.ReplicaSetInfo) {
	delete(f.replicaSets, nsName{namespace: rs.Namespace, name: rs.Name})
	for _, eh := range f.rsEventhandlers {
		eh.OnDelete(rs)
	}
}

func (f *fakeKubeMetadata) FetchPodOwnerInfo(pod *kube.PodInfo) {
	if f.replicaSets != nil && pod.DeploymentName == "" && pod.ReplicaSetName != "" {
		if rsi, ok := f.replicaSets[nsName{namespace: pod.Namespace, name: pod.ReplicaSetName}]; ok {
			pod.DeploymentName = rsi.DeploymentName
		}
	}
}

func (f *fakeKubeMetadata) GetContainerPod(containerID string) (*kube.PodInfo, bool) {
	if f.podsByContainer == nil {
		return nil, false
	}
	pod, ok := f.podsByContainer[containerID]
	return pod, ok
}

func (f *fakeKubeMetadata) AddPodEventHandler(handler cache.ResourceEventHandler) (cache.ResourceEventHandlerRegistration, error) {
	f.podEventHandlers = append(f.podEventHandlers, handler)
	return nil, nil
}

func (f *fakeKubeMetadata) AddReplicaSetEventHandler(handler cache.ResourceEventHandler) (cache.ResourceEventHandlerRegistration, error) {
	f.rsEventhandlers = append(f.rsEventhandlers, handler)
	return nil, nil
}

type fakeNode[T any] chan T

func (fn fakeNode[T]) asStartNode(out chan<- T) {
	for i := range fn {
		out <- i
	}
}

func (fn fakeNode[T]) asTermNode(in <-chan T) {
	for i := range in {
		fn <- i
	}
}
