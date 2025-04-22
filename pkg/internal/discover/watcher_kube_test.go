package discover

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/grafana/beyla/v2/pkg/beyla"
	"github.com/grafana/beyla/v2/pkg/internal/helpers/container"
	"github.com/grafana/beyla/v2/pkg/internal/kube"
	"github.com/grafana/beyla/v2/pkg/internal/testutil"
	"github.com/grafana/beyla/v2/pkg/kubecache/informer"
	"github.com/grafana/beyla/v2/pkg/kubecache/meta"
	"github.com/grafana/beyla/v2/pkg/pipe/msg"
	"github.com/grafana/beyla/v2/pkg/pipe/swarm"
	"github.com/grafana/beyla/v2/pkg/services"
)

const timeout = 5 * time.Second

const (
	namespace      = "test-ns"
	containerPID   = 123
	containerID    = "container-123"
	containerPort  = 332
	replicaSetName = "the-deployment-123456789"
	deploymentName = "the-deployment"
	podName        = "the-deployment-123456789-abcde"
)

func TestWatcherKubeEnricher(t *testing.T) {
	type event struct {
		fn           func(input *msg.Queue[[]Event[processAttrs]], fInformer meta.Notifier)
		shouldNotify bool
	}
	type testCase struct {
		name  string
		steps []event
	}
	// test deployment functions
	var process = func(input *msg.Queue[[]Event[processAttrs]], _ meta.Notifier) {
		newProcess(input, containerPID, []uint32{containerPort})
	}
	var pod = func(_ *msg.Queue[[]Event[processAttrs]], fInformer meta.Notifier) {
		deployPod(fInformer, namespace, podName, containerID, nil)
	}
	var ownedPod = func(_ *msg.Queue[[]Event[processAttrs]], fInformer meta.Notifier) {
		deployOwnedPod(fInformer, namespace, podName, replicaSetName, deploymentName, containerID)
	}

	// The watcherKubeEnricher has to listen and relate information from multiple asynchronous sources.
	// Each test case verifies that whatever the order of the events is,
	testCases := []testCase{
		{name: "process-pod", steps: []event{{fn: process, shouldNotify: true}, {fn: ownedPod, shouldNotify: true}}},
		{name: "pod-process", steps: []event{{fn: ownedPod, shouldNotify: false}, {fn: process, shouldNotify: true}}},
		{name: "process-pod (no owner)", steps: []event{{fn: process, shouldNotify: true}, {fn: pod, shouldNotify: true}}},
		{name: "pod-process (no owner)", steps: []event{{fn: pod, shouldNotify: false}, {fn: process, shouldNotify: true}}}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			containerInfoForPID = fakeContainerInfo

			// Setup a fake K8s API connected to the watcherKubeEnricher
			fInformer := &fakeInformer{}
			store := kube.NewStore(fInformer, kube.ResourceLabels{})
			input := msg.NewQueue[[]Event[processAttrs]](msg.ChannelBufferLen(10))
			defer input.Close()
			output := msg.NewQueue[[]Event[processAttrs]](msg.ChannelBufferLen(10))
			outputCh := output.Subscribe()
			wkeNodeFunc, err := WatcherKubeEnricherProvider(&fakeMetadataProvider{store: store}, input, output)(t.Context())
			require.NoError(t, err)
			go wkeNodeFunc(t.Context())

			// deploy all the involved elements where the metadata are composed of
			// in different orders to test that watcherKubeEnricher will eventually handle everything
			var events []Event[processAttrs]
			for _, step := range tc.steps {
				step.fn(input, fInformer)
				if step.shouldNotify {
					events = testutil.ReadChannel(t, outputCh, timeout)
				}
			}

			require.Len(t, events, 1)
			event := events[0]
			assert.Equal(t, EventCreated, event.Type)
			assert.EqualValues(t, containerPID, event.Obj.pid)
			assert.Equal(t, []uint32{containerPort}, event.Obj.openPorts)
			assert.Equal(t, namespace, event.Obj.metadata[services.AttrNamespace])
			assert.Equal(t, podName, event.Obj.metadata[services.AttrPodName])
			if strings.Contains(tc.name, "(no owner)") {
				assert.Empty(t, event.Obj.metadata[services.AttrReplicaSetName])
				assert.Empty(t, event.Obj.metadata[services.AttrDeploymentName])
			} else {
				assert.Equal(t, replicaSetName, event.Obj.metadata[services.AttrReplicaSetName])
				assert.Equal(t, deploymentName, event.Obj.metadata[services.AttrDeploymentName])
			}
		})
	}
}

func TestWatcherKubeEnricherWithMatcher(t *testing.T) {
	containerInfoForPID = fakeContainerInfo
	processInfo = fakeProcessInfo

	// Setup a fake K8s API connected to the watcherKubeEnricher
	fInformer := &fakeInformer{}
	store := kube.NewStore(fInformer, kube.ResourceLabels{})
	inputQueue := msg.NewQueue[[]Event[processAttrs]](msg.ChannelBufferLen(10))
	defer inputQueue.Close()
	connectQueue := msg.NewQueue[[]Event[processAttrs]](msg.ChannelBufferLen(10))
	outputQueue := msg.NewQueue[[]Event[ProcessMatch]](msg.ChannelBufferLen(10))
	outputCh := outputQueue.Subscribe()
	swi := swarm.Instancer{}
	swi.Add(WatcherKubeEnricherProvider(&fakeMetadataProvider{store: store}, inputQueue, connectQueue))

	pipeConfig := beyla.Config{}
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
  - name: pod-label-only
    k8s_pod_labels:
      instrument: "beyla"
  - name: pod-multi-label-only
    k8s_pod_labels:
      instrument: "ebpf"
      lang: "go.*"
  - name: pod-annotation-only
    k8s_pod_annotations:
      deploy.type: "canary"
  - name: pod-multi-annotation-only
    k8s_pod_annotations:
      deploy.type: "prod"
      version: "v\\d+"
`), &pipeConfig))

	swi.Add(CriteriaMatcherProvider(&pipeConfig, connectQueue, outputQueue))

	nodesRunner, err := swi.Instance(t.Context())
	require.NoError(t, err)

	nodesRunner.Start(t.Context())

	// sending some events that shouldn't match any of the above discovery criteria
	// so they won't be forwarded before any of later matched events
	newProcess(inputQueue, 123, []uint32{777})
	newProcess(inputQueue, 456, []uint32{})
	newProcess(inputQueue, 789, []uint32{443})
	deployOwnedPod(fInformer, namespace, "depl-rsid-podid", "depl-rsid", "depl", "container-789")

	// sending events that will match and will be forwarded
	t.Run("port-only match", func(t *testing.T) {
		newProcess(inputQueue, 12, []uint32{80})
		matches := testutil.ReadChannel(t, outputCh, timeout)
		require.Len(t, matches, 1)
		m := matches[0]
		assert.Equal(t, EventCreated, m.Type)
		assert.Equal(t, "port-only", m.Obj.Criteria.Name)
		assert.EqualValues(t, 12, m.Obj.Process.Pid)
	})

	t.Run("metadata-only match", func(t *testing.T) {
		newProcess(inputQueue, 34, []uint32{8080})
		deployPod(fInformer, namespace, "chichi", "container-34", nil)
		matches := testutil.ReadChannel(t, outputCh, timeout)
		require.Len(t, matches, 1)
		m := matches[0]
		assert.Equal(t, EventCreated, m.Type)
		assert.Equal(t, "metadata-only", m.Obj.Criteria.Name)
		assert.EqualValues(t, 34, m.Obj.Process.Pid)
	})

	t.Run("pod-label-only match", func(t *testing.T) {
		newProcess(inputQueue, 42, []uint32{8080})
		deployPod(fInformer, namespace, "labeltest", "container-42", map[string]string{"instrument": "beyla"})
		matches := testutil.ReadChannel(t, outputCh, timeout)
		require.Len(t, matches, 1)
		m := matches[0]
		assert.Equal(t, EventCreated, m.Type)
		assert.Equal(t, "pod-label-only", m.Obj.Criteria.Name)
		assert.EqualValues(t, 42, m.Obj.Process.Pid)
	})

	t.Run("pod-multi-label-only match", func(t *testing.T) {
		newProcess(inputQueue, 43, []uint32{8080})
		deployPod(fInformer, namespace, "multi-labeltest", "container-43", map[string]string{"instrument": "ebpf", "lang": "golang"})
		matches := testutil.ReadChannel(t, outputCh, timeout)
		require.Len(t, matches, 1)
		m := matches[0]
		assert.Equal(t, EventCreated, m.Type)
		assert.Equal(t, "pod-multi-label-only", m.Obj.Criteria.Name)
		assert.EqualValues(t, 43, m.Obj.Process.Pid)
	})

	t.Run("pod-annotation-only match", func(t *testing.T) {
		newProcess(inputQueue, 44, []uint32{8080})
		deployPod(fInformer, namespace, "annotationtest", "container-44", nil, map[string]string{"deploy.type": "canary"})
		matches := testutil.ReadChannel(t, outputCh, timeout)
		require.Len(t, matches, 1)
		m := matches[0]
		assert.Equal(t, EventCreated, m.Type)
		assert.Equal(t, "pod-annotation-only", m.Obj.Criteria.Name)
		assert.EqualValues(t, 44, m.Obj.Process.Pid)
	})

	t.Run("pod-multi-annotation-only match", func(t *testing.T) {
		newProcess(inputQueue, 45, []uint32{8080})
		deployPod(fInformer, namespace, "multi-annotationtest", "container-45", nil, map[string]string{"deploy.type": "prod", "version": "v1"})
		matches := testutil.ReadChannel(t, outputCh, timeout)
		require.Len(t, matches, 1)
		m := matches[0]
		assert.Equal(t, EventCreated, m.Type)
		assert.Equal(t, "pod-multi-annotation-only", m.Obj.Criteria.Name)
		assert.EqualValues(t, 45, m.Obj.Process.Pid)
	})

	t.Run("both process and metadata match", func(t *testing.T) {
		newProcess(inputQueue, 56, []uint32{443})
		deployOwnedPod(fInformer, namespace, "chacha-rsid-podid", "chacha-rsid", "chacha", "container-56")
		matches := testutil.ReadChannel(t, outputCh, timeout)
		require.Len(t, matches, 1)
		m := matches[0]
		assert.Equal(t, EventCreated, m.Type)
		assert.Equal(t, "both", m.Obj.Criteria.Name)
		assert.EqualValues(t, 56, m.Obj.Process.Pid)
	})

	t.Run("process deletion", func(t *testing.T) {
		inputQueue.Send([]Event[processAttrs]{
			{Type: EventDeleted, Obj: processAttrs{pid: 123}},
			{Type: EventDeleted, Obj: processAttrs{pid: 456}},
			{Type: EventDeleted, Obj: processAttrs{pid: 789}},
			{Type: EventDeleted, Obj: processAttrs{pid: 1011}},
			{Type: EventDeleted, Obj: processAttrs{pid: 12}},
			{Type: EventDeleted, Obj: processAttrs{pid: 34}},
			{Type: EventDeleted, Obj: processAttrs{pid: 42}},
			{Type: EventDeleted, Obj: processAttrs{pid: 43}},
			{Type: EventDeleted, Obj: processAttrs{pid: 44}},
			{Type: EventDeleted, Obj: processAttrs{pid: 45}},
			{Type: EventDeleted, Obj: processAttrs{pid: 56}},
		})
		// only forwards the deletion of the processes that were already matched
		matches := testutil.ReadChannel(t, outputCh, timeout)
		require.Len(t, matches, 7)
		assert.Equal(t, EventDeleted, matches[0].Type)
		assert.EqualValues(t, 12, matches[0].Obj.Process.Pid)
		assert.Equal(t, EventDeleted, matches[1].Type)
		assert.EqualValues(t, 34, matches[1].Obj.Process.Pid)
		assert.Equal(t, EventDeleted, matches[2].Type)
		assert.EqualValues(t, 42, matches[2].Obj.Process.Pid)
		assert.Equal(t, EventDeleted, matches[3].Type)
		assert.EqualValues(t, 43, matches[3].Obj.Process.Pid)
		assert.Equal(t, EventDeleted, matches[4].Type)
		assert.EqualValues(t, 44, matches[4].Obj.Process.Pid)
		assert.Equal(t, EventDeleted, matches[5].Type)
		assert.EqualValues(t, 45, matches[5].Obj.Process.Pid)
		assert.Equal(t, EventDeleted, matches[6].Type)
		assert.EqualValues(t, 56, matches[6].Obj.Process.Pid)
	})
}

func newProcess(input *msg.Queue[[]Event[processAttrs]], pid PID, ports []uint32) {
	input.Send([]Event[processAttrs]{{
		Type: EventCreated,
		Obj:  processAttrs{pid: pid, openPorts: ports},
	}})
}

func deployPod(fInformer meta.Notifier, ns, name, containerID string, labels map[string]string, annotations ...map[string]string) {
	var podAnnotations map[string]string
	if len(annotations) > 0 {
		podAnnotations = annotations[0]
	}
	fInformer.Notify(&informer.Event{
		Type: informer.EventType_CREATED,
		Resource: &informer.ObjectMeta{
			Name: name, Namespace: ns, Labels: labels, Annotations: podAnnotations,
			Kind: "Pod",
			Pod: &informer.PodInfo{
				Containers: []*informer.ContainerInfo{{Id: containerID}},
			},
		},
	})
}

func deployOwnedPod(fInformer meta.Notifier, ns, name, replicaSetName, deploymentName, containerID string) {
	fInformer.Notify(&informer.Event{
		Type: informer.EventType_CREATED,
		Resource: &informer.ObjectMeta{
			Name: name, Namespace: ns,
			Kind: "Pod",
			Pod: &informer.PodInfo{
				Containers: []*informer.ContainerInfo{{Id: containerID}},
				Owners: []*informer.Owner{{Name: replicaSetName, Kind: "ReplicaSet"},
					{Name: deploymentName, Kind: "Deployment"}},
			},
		},
	})
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

type fakeMetadataProvider struct {
	store *kube.Store
}

func (i *fakeMetadataProvider) IsKubeEnabled() bool { return true }

func (i *fakeMetadataProvider) Get(_ context.Context) (*kube.Store, error) {
	return i.store, nil
}

type fakeInformer struct {
	mt        sync.Mutex
	observers map[string]meta.Observer
}

func (f *fakeInformer) Subscribe(observer meta.Observer) {
	f.mt.Lock()
	defer f.mt.Unlock()
	if f.observers == nil {
		f.observers = map[string]meta.Observer{}
	}
	f.observers[observer.ID()] = observer
}

func (f *fakeInformer) Unsubscribe(observer meta.Observer) {
	f.mt.Lock()
	defer f.mt.Unlock()
	delete(f.observers, observer.ID())
}

func (f *fakeInformer) Notify(event *informer.Event) {
	f.mt.Lock()
	defer f.mt.Unlock()
	for _, observer := range f.observers {
		_ = observer.On(event)
	}
}
