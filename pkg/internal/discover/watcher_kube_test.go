package discover

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	fakek8sclientset "k8s.io/client-go/kubernetes/fake"

	"github.com/grafana/beyla/pkg/internal/discover/services"
	"github.com/grafana/beyla/pkg/internal/helpers/container"
	"github.com/grafana/beyla/pkg/internal/kube"
	"github.com/grafana/beyla/pkg/internal/pipe"
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
	type fn func(t *testing.T, inputCh chan []Event[processAttrs], k8sClient *fakek8sclientset.Clientset)
	type testCase struct {
		name  string
		steps []fn
	}
	// The WatcherKubeEnricher has to listen and relate information from multiple asynchronous sources.
	// Each test case verifies that whatever the order of the events is,
	testCases := []testCase{
		{name: "process-pod-rs", steps: []fn{newProcess, deployOwnedPod, deployReplicaSet}},
		{name: "process-rs-pod", steps: []fn{newProcess, deployReplicaSet, deployOwnedPod}},
		{name: "pod-process-rs", steps: []fn{deployOwnedPod, newProcess, deployReplicaSet}},
		{name: "pod-rs-process", steps: []fn{deployOwnedPod, deployReplicaSet, newProcess}},
		{name: "rs-pod-process", steps: []fn{deployReplicaSet, deployOwnedPod, newProcess}},
		{name: "rs-process-pod", steps: []fn{newProcess, deployOwnedPod, deployReplicaSet}},
		{name: "process-pod (no rs)", steps: []fn{newProcess, deployPod}},
		{name: "pod-process (no rs)", steps: []fn{deployPod, newProcess}}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			containerInfoForPID = fakeContainerInfo{
				containerPID: container.Info{ContainerID: containerID},
			}.forPID
			// Setup a fake K8s API connected to the WatcherKubeEnricher
			k8sClient := fakek8sclientset.NewSimpleClientset()
			informer := kube.Metadata{}
			require.NoError(t, informer.InitFromClient(k8sClient, 30*time.Minute))
			wkeNodeFunc, err := WatcherKubeEnricherProvider(&WatcherKubeEnricher{
				informer: &informer,
			})
			require.NoError(t, err)
			inputCh, outputCh := make(chan []Event[processAttrs], 10), make(chan []Event[processAttrs], 10)
			defer close(inputCh)
			go wkeNodeFunc(inputCh, outputCh)

			_, err = k8sClient.CoreV1().Namespaces().Create(
				context.Background(),
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}},
				metav1.CreateOptions{})
			require.NoError(t, err)

			// deploy all the involved elements where the metadata are composed of
			for _, step := range tc.steps {
				step(t, inputCh, k8sClient)
			}

			// check that the WatcherKubeEnricher eventually submits an event with the expected metadata
			test.Eventually(t, timeout, func(t require.TestingT) {
				events := <-outputCh
				require.Len(t, events, 1)
				event := events[0]
				assert.Equal(t, EventCreated, event.Type)
				assert.EqualValues(t, containerPID, event.Obj.pid)
				assert.Equal(t, []uint32{containerPort}, event.Obj.openPorts)
				assert.Equal(t, namespace, event.Obj.metadata[services.AttrNamespace])
				assert.Equal(t, podName, event.Obj.metadata[services.AttrPodName])
				if strings.Contains(tc.name, "(no rs)") {
					assert.Empty(t, event.Obj.metadata[services.AttrReplicaSetName])
					assert.Empty(t, event.Obj.metadata[services.AttrDeploymentName])
				} else {
					assert.Equal(t, replicaSetName, event.Obj.metadata[services.AttrReplicaSetName])
					assert.Equal(t, deploymentName, event.Obj.metadata[services.AttrDeploymentName])
				}
			})
		})
	}
}

func TestWatcherKubeEnricherWithMatcher(t *testing.T) {
	containerInfoForPID = fakeContainerInfo{
		containerPID: container.Info{ContainerID: containerID},
	}.forPID
	// Setup a fake K8s API connected to the WatcherKubeEnricher
	k8sClient := fakek8sclientset.NewSimpleClientset()
	informer := kube.Metadata{}
	require.NoError(t, informer.InitFromClient(k8sClient, 30*time.Minute))
	wkeNodeFunc, err := WatcherKubeEnricherProvider(&WatcherKubeEnricher{
		informer: &informer,
	})
	pipeConfig := pipe.Config{}
	require.NoError(t, yaml.Unmarshal([]byte(`discovery:
  services:
  - name: port-only
    namespace: foo
    open_ports: 80
  - name: metadata-only
    k8s_pod_name: chichi
  - name: both
    open_ports: 443
    k8s_pod_name: chacha
`), &pipeConfig))
	mtchNodeFunc, err := CriteriaMatcherProvider(CriteriaMatcher{Cfg: &pipeConfig})
	require.NoError(t, err)
	inputCh, connectCh := make(chan []Event[processAttrs], 10), make(chan []Event[processAttrs], 10)
	outputCh := make(chan []Event[ProcessMatch], 10)
	defer close(inputCh)
	go wkeNodeFunc(inputCh, connectCh)
	go mtchNodeFunc(connectCh, outputCh)

	voy poraki
}

func newProcess(_ *testing.T, inputCh chan []Event[processAttrs], _ *fakek8sclientset.Clientset) {
	inputCh <- []Event[processAttrs]{{
		Type: EventCreated,
		Obj:  processAttrs{pid: containerPID, openPorts: []uint32{containerPort}},
	}}
}

func deployPod(t *testing.T, _ chan []Event[processAttrs], k8sClient *fakek8sclientset.Clientset) {
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

func deployOwnedPod(t *testing.T, _ chan []Event[processAttrs], k8sClient *fakek8sclientset.Clientset) {
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

func deployReplicaSet(t *testing.T, _ chan []Event[processAttrs], k8sClient *fakek8sclientset.Clientset) {
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
