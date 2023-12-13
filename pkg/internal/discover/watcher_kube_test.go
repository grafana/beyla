package discover

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	fakek8sclientset "k8s.io/client-go/kubernetes/fake"

	"github.com/grafana/beyla/pkg/internal/helpers/container"
	"github.com/grafana/beyla/pkg/internal/kube"
)

func TestWatcherKubeEnricher(t *testing.T) {
	containerInfoForPID = fakeContainerInfo{
		123: container.Info{ContainerID: "container-123"},
	}.forPID
	k8sClient := fakek8sclientset.NewSimpleClientset()

	informer := kube.Metadata{}
	require.NoError(t, informer.InitFromClient(k8sClient, 30*time.Minute))
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

	ns := "test-ns"
	_, err = k8sClient.CoreV1().Namespaces().Create(
		context.Background(),
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}},
		metav1.CreateOptions{})
	require.NoError(t, err)

	_, err = k8sClient.CoreV1().Pods(ns).Create(
		context.Background(),
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Name: "foo", Namespace: ns,
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps/v1",
				Kind:       "ReplicaSet",
				Name:       "rs-3321",
			}},
		}, Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{{
				ContainerID: "container-123",
			}},
		}},
		metav1.CreateOptions{})
	require.NoError(t, err)

	o = <-outputCh
	j, _ = json.Marshal(o.Obj.ownerPod)
	fmt.Printf("pid: %v. ports: %v. owner: %s\n", o.Obj.pid, o.Obj.openPorts, string(j))

	_, err = k8sClient.AppsV1().ReplicaSets(ns).Create(context.Background(),
		&appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: ns,
				Name:      "rs-3321",
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: "apps/v1",
					Kind:       "Deployment",
					Name:       "the-deployment",
				}},
			},
		},
		metav1.CreateOptions{})

	require.NoError(t, err)

	o = <-outputCh
	j, _ = json.Marshal(o.Obj.ownerPod)
	fmt.Printf("pid: %v. ports: %v. owner: %s\n", o.Obj.pid, o.Obj.openPorts, string(j))

	o = <-outputCh
	j, _ = json.Marshal(o.Obj.ownerPod)
	fmt.Printf("pid: %v. ports: %v. owner: %s\n", o.Obj.pid, o.Obj.openPorts, string(j))
	o = <-outputCh
	j, _ = json.Marshal(o.Obj.ownerPod)
	fmt.Printf("pid: %v. ports: %v. owner: %s\n", o.Obj.pid, o.Obj.openPorts, string(j))

	//informer.addReplicaSet(&kube.ReplicaSetInfo{
	//	ObjectMeta: metav1.ObjectMeta{
	//		Name:      "rs-3321",
	//		Namespace: "ns",
	//	},
	//	DeploymentName: "deployment",
	//})
	//
	//o = <-outputCh
	//j, _ = json.Marshal(o.Obj.ownerPod)
	//fmt.Printf("pid: %v. ports: %v. owner: %s\n", o.Obj.pid, o.Obj.openPorts, string(j))
	//
	//for o := range outputCh {
	//	j, _ := json.Marshal(o.Obj.ownerPod)
	//	fmt.Printf("pid: %v. ports: %v. owner: %s\n", o.Obj.pid, o.Obj.openPorts, string(j))
	//}
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
