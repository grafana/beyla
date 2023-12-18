package discover

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	fakek8sclientset "k8s.io/client-go/kubernetes/fake"

	"github.com/grafana/beyla/pkg/internal/helpers/container"
	"github.com/grafana/beyla/pkg/internal/kube"
)

const timeout = 5 * time.Second
const (
	namespace      = "test-ns"
	containerPID   = 123
	containerID    = "container-123"
	containerPort  = 332
	replicaSetName = "rs-3321"
	deploymentName = "the-deployment"
	podName        = "the-pod"
)

func TestWatcherKubeEnricher(t *testing.T) {

	type fn func(t *testing.T, inputCh chan Event[processAttrs], k8sClient *fakek8sclientset.Clientset)
	type testCase struct {
		name  string
		steps []fn
	}

	testCases := []testCase{{
		name:  "process-pod-rs",
		steps: []fn{newProcess, deployOwnedPod, deployReplicaSet},
	}, {
		name:  "process-rs-pod",
		steps: []fn{newProcess, deployReplicaSet, deployOwnedPod},
	}, {
		name:  "pod-process-rs",
		steps: []fn{deployOwnedPod, newProcess, deployReplicaSet},
	}, {
		name:  "pod-rs-process",
		steps: []fn{deployOwnedPod, deployReplicaSet, newProcess},
	}, {
		name:  "rs-pod-process",
		steps: []fn{deployReplicaSet, deployOwnedPod, newProcess},
	}, {
		name:  "rs-process-pod",
		steps: []fn{newProcess, deployOwnedPod, deployReplicaSet},
	}, {
		name:  "process-pod (no rs)",
		steps: []fn{newProcess, deployPod},
	}, {
		name:  "pod-process (no rs)",
		steps: []fn{deployPod, newProcess},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			containerInfoForPID = fakeContainerInfo{
				containerPID: container.Info{ContainerID: containerID},
			}.forPID
			k8sClient := fakek8sclientset.NewSimpleClientset()
			informer := kube.Metadata{}
			require.NoError(t, informer.InitFromClient(k8sClient, 30*time.Minute))
			wkeNodeFunc, err := WatcherKubeEnricherProvider(&WatcherKubeEnricher{
				informer: &informer,
			})
			require.NoError(t, err)
			inputCh, outputCh := make(chan Event[processAttrs], 10), make(chan Event[processAttrs], 10)
			defer close(inputCh)
			go wkeNodeFunc(inputCh, outputCh)
			_, err = k8sClient.CoreV1().Namespaces().Create(
				context.Background(),
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}},
				metav1.CreateOptions{})
			require.NoError(t, err)

			for _, step := range tc.steps {
				step(t, inputCh, k8sClient)
			}

			test.Eventually(t, timeout, func(t require.TestingT) {
				event := <-outputCh
				assert.Equal(t, EventCreated, event.Type)
				assert.EqualValues(t, containerPID, event.Obj.pid)
				assert.Equal(t, []uint32{containerPort}, event.Obj.openPorts)
				assert.Equal(t, namespace, event.Obj.attributes[attrNamespace])
				assert.Equal(t, podName, event.Obj.attributes[attrPodName])
				if strings.Contains(tc.name, "(no rs)") {
					assert.Empty(t, event.Obj.attributes[attrReplicaSetName])
					assert.Empty(t, event.Obj.attributes[attrDeploymentName])
				} else {
					assert.Equal(t, replicaSetName, event.Obj.attributes[attrReplicaSetName])
					assert.Equal(t, deploymentName, event.Obj.attributes[attrDeploymentName])
				}
			})
		})
	}
}

func newProcess(_ *testing.T, inputCh chan Event[processAttrs], _ *fakek8sclientset.Clientset) {
	inputCh <- Event[processAttrs]{
		Type: EventCreated,
		Obj:  processAttrs{pid: containerPID, openPorts: []uint32{containerPort}},
	}
}

func deployPod(t *testing.T, _ chan Event[processAttrs], k8sClient *fakek8sclientset.Clientset) {
	t.Helper()
	_, err := k8sClient.CoreV1().Pods(namespace).Create(
		context.Background(),
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Name: podName, Namespace: namespace,
		}, Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{{
				ContainerID: containerID,
			}},
		}},
		metav1.CreateOptions{})
	require.NoError(t, err)
}

func deployOwnedPod(t *testing.T, _ chan Event[processAttrs], k8sClient *fakek8sclientset.Clientset) {
	t.Helper()
	_, err := k8sClient.CoreV1().Pods(namespace).Create(
		context.Background(),
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Name: podName, Namespace: namespace,
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps/v1",
				Kind:       "ReplicaSet",
				Name:       replicaSetName,
			}},
		}, Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{{
				ContainerID: containerID,
			}},
		}},
		metav1.CreateOptions{})
	require.NoError(t, err)
}

func deployReplicaSet(t *testing.T, _ chan Event[processAttrs], k8sClient *fakek8sclientset.Clientset) {
	t.Helper()
	_, err := k8sClient.AppsV1().ReplicaSets(namespace).Create(context.Background(),
		&appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: namespace,
				Name:      replicaSetName,
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: "apps/v1",
					Kind:       "Deployment",
					Name:       deploymentName,
				}},
			},
		},
		metav1.CreateOptions{})
	require.NoError(t, err)
}

type fakeContainerInfo map[uint32]container.Info

func (f fakeContainerInfo) forPID(pid uint32) (container.Info, error) {
	return f[pid], nil
}
