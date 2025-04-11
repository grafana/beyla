package transform

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	attr "github.com/grafana/beyla/v2/pkg/export/attributes/names"
	"github.com/grafana/beyla/v2/pkg/internal/helpers/container"
	"github.com/grafana/beyla/v2/pkg/internal/kube"
	"github.com/grafana/beyla/v2/pkg/internal/request"
	"github.com/grafana/beyla/v2/pkg/internal/svc"
	"github.com/grafana/beyla/v2/pkg/internal/testutil"
	"github.com/grafana/beyla/v2/pkg/kubecache/informer"
	"github.com/grafana/beyla/v2/pkg/kubecache/meta"
	"github.com/grafana/beyla/v2/pkg/pipe/msg"
)

const timeout = 5 * time.Second

func TestDecoration(t *testing.T) {
	inf := &fakeInformer{}
	store := kube.NewStore(inf, kube.ResourceLabels{
		"service.name":      []string{"app.kubernetes.io/name"},
		"service.namespace": []string{"app.kubernetes.io/part-of"},
	})
	// pre-populated kubernetes metadata database
	inf.Notify(&informer.Event{Type: informer.EventType_CREATED, Resource: &informer.ObjectMeta{
		Name: "pod-12", Namespace: "the-ns", Kind: "Pod",
		Pod: &informer.PodInfo{
			NodeName:     "the-node",
			StartTimeStr: "2020-01-02 12:12:56",
			Uid:          "uid-12",
			Owners:       []*informer.Owner{{Kind: "Deployment", Name: "deployment-12"}},
			Containers:   []*informer.ContainerInfo{{Name: "a-container", Id: "container-12"}},
		},
	}})
	inf.Notify(&informer.Event{Type: informer.EventType_CREATED, Resource: &informer.ObjectMeta{
		Name: "pod-34", Namespace: "the-ns", Kind: "Pod",
		Pod: &informer.PodInfo{
			NodeName:     "the-node",
			StartTimeStr: "2020-01-02 12:34:56",
			Uid:          "uid-34",
			Owners:       []*informer.Owner{{Kind: "ReplicaSet", Name: "rs"}},
			Containers:   []*informer.ContainerInfo{{Name: "a-container", Id: "container-34"}},
		},
	}})
	inf.Notify(&informer.Event{Type: informer.EventType_CREATED, Resource: &informer.ObjectMeta{
		Name: "the-pod", Namespace: "the-ns", Kind: "Pod",
		Pod: &informer.PodInfo{
			NodeName:     "the-node",
			Uid:          "uid-56",
			StartTimeStr: "2020-01-02 12:56:56",
			Containers:   []*informer.ContainerInfo{{Name: "a-container", Id: "container-56"}},
		},
	}})
	inf.Notify(&informer.Event{Type: informer.EventType_CREATED, Resource: &informer.ObjectMeta{
		Name: "overridden-meta", Namespace: "the-ns", Kind: "Pod",
		Labels: map[string]string{
			"app.kubernetes.io/name":    "a-cool-name",
			"app.kubernetes.io/part-of": "a-cool-namespace",
		},
		Pod: &informer.PodInfo{
			NodeName:     "the-node",
			Uid:          "uid-78",
			StartTimeStr: "2020-01-02 12:56:56",
			Containers:   []*informer.ContainerInfo{{Name: "a-container", Id: "container-78"}},
		},
	}})
	inf.Notify(&informer.Event{Type: informer.EventType_CREATED, Resource: &informer.ObjectMeta{
		Name: "overridden-meta-annots", Namespace: "the-ns", Kind: "Pod",
		Annotations: map[string]string{
			"resource.opentelemetry.io/service.name":      "otel-override-name",
			"resource.opentelemetry.io/service.namespace": "otel-override-ns",
		},
		Labels: map[string]string{
			"app.kubernetes.io/name":    "a-cool-name",
			"app.kubernetes.io/part-of": "a-cool-namespace",
		},
		Pod: &informer.PodInfo{
			NodeName:     "the-node",
			Uid:          "uid-33",
			StartTimeStr: "2020-01-02 12:56:56",
			Containers:   []*informer.ContainerInfo{{Name: "a-container", Id: "container-33"}},
		},
	}})
	inf.Notify(&informer.Event{Type: informer.EventType_CREATED, Resource: &informer.ObjectMeta{
		Name: "env-var-takes-precedence", Namespace: "the-ns", Kind: "Pod",
		Annotations: map[string]string{
			"resource.opentelemetry.io/service.name":      "otel-override-name",
			"resource.opentelemetry.io/service.namespace": "otel-override-ns",
		},
		Labels: map[string]string{
			"app.kubernetes.io/name":    "a-cool-name",
			"app.kubernetes.io/part-of": "a-cool-namespace",
		},
		Pod: &informer.PodInfo{
			NodeName:     "the-node",
			Uid:          "uid-66",
			StartTimeStr: "2020-01-02 12:56:56",
			Containers: []*informer.ContainerInfo{{
				Name: "a-container", Id: "container-66",
				Env: map[string]string{
					"OTEL_RESOURCE_ATTRIBUTES": "service.name=env-svc-name,service.namespace=env-svc-ns",
				},
			}},
		},
	}})
	// we need to add PID metadata for all the pod/containers above
	// by convention, the mocked pid namespace will be PID+1000
	kube.InfoForPID = func(pid uint32) (container.Info, error) {
		return container.Info{
			ContainerID:  fmt.Sprintf("container-%d", pid),
			PIDNamespace: 1000 + pid,
		}, nil
	}
	for _, pid := range []uint32{12, 34, 56, 78, 33, 66} {
		store.AddProcess(pid)
	}
	inputQueue := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
	dec := metadataDecorator{
		db: store, clusterName: "the-cluster",
		input:  inputQueue.Subscribe(),
		output: msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10)),
	}
	outputCh := dec.output.Subscribe()
	defer inputQueue.Close()
	go dec.nodeLoop(context.Background())

	autoNameSvc := svc.Attrs{}
	autoNameSvc.SetAutoName()

	t.Run("complete pod info should set deployment as name", func(t *testing.T) {
		inputQueue.Send([]request.Span{{
			Pid: request.PidInfo{Namespace: 1012}, Service: autoNameSvc,
		}})
		deco := testutil.ReadChannel(t, outputCh, timeout)
		require.Len(t, deco, 1)
		assert.Equal(t, "the-ns", deco[0].Service.UID.Namespace)
		assert.Equal(t, "deployment-12", deco[0].Service.UID.Name)
		assert.EqualValues(t, "the-ns.pod-12.a-container", deco[0].Service.UID.Instance)
		assert.Equal(t, map[attr.Name]string{
			"k8s.node.name":       "the-node",
			"k8s.namespace.name":  "the-ns",
			"k8s.pod.name":        "pod-12",
			"k8s.container.name":  "a-container",
			"k8s.pod.uid":         "uid-12",
			"k8s.deployment.name": "deployment-12",
			"k8s.owner.name":      "deployment-12",
			"k8s.pod.start_time":  "2020-01-02 12:12:56",
			"k8s.cluster.name":    "the-cluster",
		}, deco[0].Service.Metadata)
	})
	t.Run("pod info whose replicaset did not have an Owner should set the replicaSet name", func(t *testing.T) {
		inputQueue.Send([]request.Span{{
			Pid: request.PidInfo{Namespace: 1034}, Service: autoNameSvc,
		}})
		deco := testutil.ReadChannel(t, outputCh, timeout)
		require.Len(t, deco, 1)
		assert.Equal(t, "the-ns", deco[0].Service.UID.Namespace)
		assert.Equal(t, "rs", deco[0].Service.UID.Name)
		assert.EqualValues(t, "the-ns.pod-34.a-container", deco[0].Service.UID.Instance)
		assert.Equal(t, map[attr.Name]string{
			"k8s.node.name":       "the-node",
			"k8s.namespace.name":  "the-ns",
			"k8s.replicaset.name": "rs",
			"k8s.owner.name":      "rs",
			"k8s.pod.name":        "pod-34",
			"k8s.container.name":  "a-container",
			"k8s.pod.uid":         "uid-34",
			"k8s.pod.start_time":  "2020-01-02 12:34:56",
			"k8s.cluster.name":    "the-cluster",
		}, deco[0].Service.Metadata)
	})
	t.Run("pod info with only pod name should set pod name as name", func(t *testing.T) {
		inputQueue.Send([]request.Span{{
			Pid: request.PidInfo{Namespace: 1056}, Service: autoNameSvc,
		}})
		deco := testutil.ReadChannel(t, outputCh, timeout)
		require.Len(t, deco, 1)
		assert.Equal(t, "the-ns", deco[0].Service.UID.Namespace)
		assert.Equal(t, "the-pod", deco[0].Service.UID.Name)
		assert.EqualValues(t, "the-ns.the-pod.a-container", deco[0].Service.UID.Instance)
		assert.Equal(t, map[attr.Name]string{
			"k8s.node.name":      "the-node",
			"k8s.namespace.name": "the-ns",
			"k8s.pod.name":       "the-pod",
			"k8s.container.name": "a-container",
			"k8s.pod.uid":        "uid-56",
			"k8s.pod.start_time": "2020-01-02 12:56:56",
			"k8s.cluster.name":   "the-cluster",
		}, deco[0].Service.Metadata)
	})
	t.Run("user can override service name and ns via labels", func(t *testing.T) {
		inputQueue.Send([]request.Span{{
			Pid: request.PidInfo{Namespace: 1078}, Service: autoNameSvc,
		}})
		deco := testutil.ReadChannel(t, outputCh, timeout)
		require.Len(t, deco, 1)
		assert.Equal(t, "a-cool-namespace", deco[0].Service.UID.Namespace)
		assert.Equal(t, "a-cool-name", deco[0].Service.UID.Name)
		assert.EqualValues(t, "the-ns.overridden-meta.a-container", deco[0].Service.UID.Instance)
		assert.Equal(t, map[attr.Name]string{
			"k8s.node.name":      "the-node",
			"k8s.namespace.name": "the-ns",
			"k8s.pod.name":       "overridden-meta",
			"k8s.container.name": "a-container",
			"k8s.pod.uid":        "uid-78",
			"k8s.pod.start_time": "2020-01-02 12:56:56",
			"k8s.cluster.name":   "the-cluster",
			"service.name":       "a-cool-name",
			"service.namespace":  "a-cool-namespace",
		}, deco[0].Service.Metadata)
	})
	t.Run("user can override service name and ns via annotations", func(t *testing.T) {
		inputQueue.Send([]request.Span{{
			Pid: request.PidInfo{Namespace: 1033}, Service: autoNameSvc,
		}})
		deco := testutil.ReadChannel(t, outputCh, timeout)
		require.Len(t, deco, 1)
		assert.Equal(t, "otel-override-ns", deco[0].Service.UID.Namespace)
		assert.Equal(t, "otel-override-name", deco[0].Service.UID.Name)
		assert.EqualValues(t, "the-ns.overridden-meta-annots.a-container", deco[0].Service.UID.Instance)
		assert.Equal(t, map[attr.Name]string{
			"k8s.node.name":      "the-node",
			"k8s.namespace.name": "the-ns",
			"k8s.pod.name":       "overridden-meta-annots",
			"k8s.container.name": "a-container",
			"k8s.pod.uid":        "uid-33",
			"k8s.pod.start_time": "2020-01-02 12:56:56",
			"k8s.cluster.name":   "the-cluster",
			"service.name":       "otel-override-name",
			"service.namespace":  "otel-override-ns",
		}, deco[0].Service.Metadata)
	})
	t.Run("user can override service name and ns via env vars, taking precedence over any other criteria", func(t *testing.T) {
		inputQueue.Send([]request.Span{{
			Pid: request.PidInfo{Namespace: 1066}, Service: autoNameSvc,
		}})
		deco := testutil.ReadChannel(t, outputCh, timeout)
		require.Len(t, deco, 1)
		assert.Equal(t, "env-svc-ns", deco[0].Service.UID.Namespace)
		assert.Equal(t, "env-svc-name", deco[0].Service.UID.Name)
		assert.EqualValues(t, "the-ns.env-var-takes-precedence.a-container", deco[0].Service.UID.Instance)
		assert.Equal(t, map[attr.Name]string{
			"k8s.node.name":      "the-node",
			"k8s.namespace.name": "the-ns",
			"k8s.pod.name":       "env-var-takes-precedence",
			"k8s.container.name": "a-container",
			"k8s.pod.uid":        "uid-66",
			"k8s.pod.start_time": "2020-01-02 12:56:56",
			"k8s.cluster.name":   "the-cluster",
			"service.name":       "env-svc-name",
			"service.namespace":  "env-svc-ns",
		}, deco[0].Service.Metadata)
	})
	t.Run("process without pod Info won't be decorated", func(t *testing.T) {
		svc := svc.Attrs{UID: svc.UID{Name: "exec"}}
		svc.SetAutoName()
		inputQueue.Send([]request.Span{{
			Pid: request.PidInfo{Namespace: 1099}, Service: svc,
		}})
		deco := testutil.ReadChannel(t, outputCh, timeout)
		require.Len(t, deco, 1)
		assert.Empty(t, deco[0].Service.UID.Namespace)
		assert.Equal(t, "exec", deco[0].Service.UID.Name)
		assert.Empty(t, deco[0].Service.Metadata)
	})
	t.Run("if service name or namespace are manually specified, don't override them", func(t *testing.T) {
		inputQueue.Send([]request.Span{{
			Pid: request.PidInfo{Namespace: 1012}, Service: svc.Attrs{UID: svc.UID{Name: "tralari", Namespace: "tralara"}},
		}})
		deco := testutil.ReadChannel(t, outputCh, timeout)
		require.Len(t, deco, 1)
		assert.Equal(t, "tralara", deco[0].Service.UID.Namespace)
		assert.Equal(t, "tralari", deco[0].Service.UID.Name)
		assert.EqualValues(t, "the-ns.pod-12.a-container", deco[0].Service.UID.Instance)
		assert.Equal(t, map[attr.Name]string{
			"k8s.node.name":       "the-node",
			"k8s.namespace.name":  "the-ns",
			"k8s.pod.name":        "pod-12",
			"k8s.container.name":  "a-container",
			"k8s.pod.uid":         "uid-12",
			"k8s.deployment.name": "deployment-12",
			"k8s.owner.name":      "deployment-12",
			"k8s.pod.start_time":  "2020-01-02 12:12:56",
			"k8s.cluster.name":    "the-cluster",
		}, deco[0].Service.Metadata)
	})
}

type fakeInformer struct {
	observers map[string]meta.Observer
}

func (f *fakeInformer) Subscribe(observer meta.Observer) {
	if f.observers == nil {
		f.observers = map[string]meta.Observer{}
	}
	f.observers[observer.ID()] = observer
}

func (f *fakeInformer) Unsubscribe(observer meta.Observer) {
	delete(f.observers, observer.ID())
}

func (f *fakeInformer) Notify(event *informer.Event) {
	for _, observer := range f.observers {
		_ = observer.On(event)
	}
}
