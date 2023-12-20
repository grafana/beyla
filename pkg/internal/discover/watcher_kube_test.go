package discover

import (
	"context"
	"fmt"
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
	"github.com/grafana/beyla/pkg/internal/testutil"
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
	// test deployment functions
	var process = func(_ *testing.T, inputCh chan []Event[processAttrs], _ *fakek8sclientset.Clientset) {
		newProcess(inputCh, containerPID, []uint32{containerPort})
	}
	var pod = func(t *testing.T, _ chan []Event[processAttrs], k8sClient *fakek8sclientset.Clientset) {
		deployPod(t, k8sClient, namespace, podName, containerID)
	}
	var ownedPod = func(t *testing.T, _ chan []Event[processAttrs], k8sClient *fakek8sclientset.Clientset) {
		deployOwnedPod(t, k8sClient, namespace, podName, replicaSetName, containerID)
	}
	var replicaSet = func(t *testing.T, _ chan []Event[processAttrs], k8sClient *fakek8sclientset.Clientset) {
		deployReplicaSet(t, k8sClient, namespace, replicaSetName, deploymentName)
	}

	// The WatcherKubeEnricher has to listen and relate information from multiple asynchronous sources.
	// Each test case verifies that whatever the order of the events is,
	testCases := []testCase{
		{name: "process-pod-rs", steps: []fn{process, ownedPod, replicaSet}},
		{name: "process-rs-pod", steps: []fn{process, replicaSet, ownedPod}},
		{name: "pod-process-rs", steps: []fn{ownedPod, process, replicaSet}},
		{name: "pod-rs-process", steps: []fn{ownedPod, replicaSet, process}},
		{name: "rs-pod-process", steps: []fn{replicaSet, ownedPod, process}},
		{name: "rs-process-pod", steps: []fn{process, ownedPod, replicaSet}},
		{name: "process-pod (no rs)", steps: []fn{process, pod}},
		{name: "pod-process (no rs)", steps: []fn{pod, process}}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			containerInfoForPID = fakeContainerInfo
			// Setup a fake K8s API connected to the WatcherKubeEnricher
			k8sClient := fakek8sclientset.NewSimpleClientset()
			informer := kube.Metadata{}
			require.NoError(t, informer.InitFromClient(k8sClient, 30*time.Minute))
			wkeNodeFunc, err := WatcherKubeEnricherProvider(&WatcherKubeEnricher{
				Informer: &informer,
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
	containerInfoForPID = fakeContainerInfo
	processInfo = fakeProcessInfo
	// Setup a fake K8s API connected to the WatcherKubeEnricher
	k8sClient := fakek8sclientset.NewSimpleClientset()
	informer := kube.Metadata{}
	require.NoError(t, informer.InitFromClient(k8sClient, 30*time.Minute))
	wkeNodeFunc, err := WatcherKubeEnricherProvider(&WatcherKubeEnricher{
		Informer: &informer,
	})
	require.NoError(t, err)
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
    k8s_deployment_name: chacha
`), &pipeConfig))
	mtchNodeFunc, err := CriteriaMatcherProvider(CriteriaMatcher{Cfg: &pipeConfig})
	require.NoError(t, err)
	inputCh, connectCh := make(chan []Event[processAttrs], 10), make(chan []Event[processAttrs], 10)
	outputCh := make(chan []Event[ProcessMatch], 10)
	defer close(inputCh)
	go wkeNodeFunc(inputCh, connectCh)
	go mtchNodeFunc(connectCh, outputCh)

	// sending some events that shouldn't match any of the above discovery criteria
	// so they won't be forwarded before any of later matched events
	t.Run("unmatched events", func(t *testing.T) {
		newProcess(inputCh, 123, []uint32{777})
		newProcess(inputCh, 456, []uint32{})
		newProcess(inputCh, 789, []uint32{443})
		deployOwnedPod(t, k8sClient, namespace, "pod-789", "rs-789", "container-789")
		deployReplicaSet(t, k8sClient, namespace, "rs-789", "ouyeah")
	})

	// sending events that will match and will be forwarded
	t.Run("port-only match", func(t *testing.T) {
		newProcess(inputCh, 12, []uint32{80})
		matches := testutil.ReadChannel(t, outputCh, timeout)
		require.Len(t, matches, 1)
		m := matches[0]
		assert.Equal(t, EventCreated, m.Type)
		assert.Equal(t, "port-only", m.Obj.Criteria.Name)
		assert.EqualValues(t, 12, m.Obj.Process.Pid)
	})

	t.Run("metadata-only match", func(t *testing.T) {
		newProcess(inputCh, 34, []uint32{8080})
		deployPod(t, k8sClient, namespace, "chichi", "container-34")
		matches := testutil.ReadChannel(t, outputCh, timeout)
		require.Len(t, matches, 1)
		m := matches[0]
		assert.Equal(t, EventCreated, m.Type)
		assert.Equal(t, "metadata-only", m.Obj.Criteria.Name)
		assert.EqualValues(t, 34, m.Obj.Process.Pid)
	})

	t.Run("both process and metadata match", func(t *testing.T) {
		newProcess(inputCh, 56, []uint32{443})
		deployOwnedPod(t, k8sClient, namespace, "pod-56", "rs-56", "container-56")
		deployReplicaSet(t, k8sClient, namespace, "rs-56", "chacha")
		matches := testutil.ReadChannel(t, outputCh, timeout)
		require.Len(t, matches, 1)
		m := matches[0]
		assert.Equal(t, EventCreated, m.Type)
		assert.Equal(t, "both", m.Obj.Criteria.Name)
		assert.EqualValues(t, 56, m.Obj.Process.Pid)
	})

	t.Run("process deletion", func(t *testing.T) {
		inputCh <- []Event[processAttrs]{
			{Type: EventDeleted, Obj: processAttrs{pid: 123}},
			{Type: EventDeleted, Obj: processAttrs{pid: 456}},
			{Type: EventDeleted, Obj: processAttrs{pid: 789}},
			{Type: EventDeleted, Obj: processAttrs{pid: 1011}},
			{Type: EventDeleted, Obj: processAttrs{pid: 12}},
			{Type: EventDeleted, Obj: processAttrs{pid: 34}},
			{Type: EventDeleted, Obj: processAttrs{pid: 56}},
		}
		// only forwards the deletion of the processes that were already matched
		matches := testutil.ReadChannel(t, outputCh, timeout)
		require.Len(t, matches, 3)
		assert.Equal(t, EventDeleted, matches[0].Type)
		assert.EqualValues(t, 12, matches[0].Obj.Process.Pid)
		assert.Equal(t, EventDeleted, matches[1].Type)
		assert.EqualValues(t, 34, matches[1].Obj.Process.Pid)
		assert.Equal(t, EventDeleted, matches[2].Type)
		assert.EqualValues(t, 56, matches[2].Obj.Process.Pid)
	})
}

func newProcess(inputCh chan []Event[processAttrs], pid PID, ports []uint32) {
	inputCh <- []Event[processAttrs]{{
		Type: EventCreated,
		Obj:  processAttrs{pid: pid, openPorts: ports},
	}}
}

func deployPod(t *testing.T, k8sClient *fakek8sclientset.Clientset, ns, name, containerID string) {
	t.Helper()
	_, err := k8sClient.CoreV1().Pods(ns).Create(
		context.Background(),
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: ns,
		}, Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{{
				ContainerID: containerID,
			}},
		}},
		metav1.CreateOptions{})
	require.NoError(t, err)
}

func deployOwnedPod(t *testing.T, k8sClient *fakek8sclientset.Clientset, ns, name, rsName, containerID string) {
	t.Helper()
	_, err := k8sClient.CoreV1().Pods(ns).Create(
		context.Background(),
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: ns,
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps/v1",
				Kind:       "ReplicaSet",
				Name:       rsName,
			}},
		}, Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{{
				ContainerID: containerID,
			}},
		}},
		metav1.CreateOptions{})
	require.NoError(t, err)
}

func deployReplicaSet(t *testing.T, k8sClient *fakek8sclientset.Clientset, ns, name, deploymentName string) {
	t.Helper()
	_, err := k8sClient.AppsV1().ReplicaSets(ns).Create(context.Background(),
		&appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: ns,
				Name:      name,
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

func fakeContainerInfo(pid uint32) (container.Info, error) {
	return container.Info{ContainerID: fmt.Sprintf("container-%d", pid)}, nil
}

func fakeProcessInfo(pp processAttrs) (*services.ProcessInfo, error) {
	return &services.ProcessInfo{
		Pid:       int32(pp.pid),
		OpenPorts: pp.openPorts,
		ExePath:   fmt.Sprintf("/bin/process%d", pp.pid),
	}, nil
}
