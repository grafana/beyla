package transform

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla-k8s-cache/pkg/informer"
	"github.com/grafana/beyla-k8s-cache/pkg/meta"
	attr "github.com/grafana/beyla/pkg/export/attributes/names"
	"github.com/grafana/beyla/pkg/internal/kube"
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/svc"
	"github.com/grafana/beyla/pkg/internal/testutil"
)

const timeout = 5 * time.Second

func TestDecoration(t *testing.T) {
	inf := &fakeInformer{}
	store := kube.NewStore(inf)
	// pre-populated kubernetes metadata database
	inf.Notify(&informer.Event{Type: informer.EventType_CREATED, Resource: &informer.ObjectMeta{
		Name: "pod-12", Namespace: "the-ns",
		Pod: &informer.PodInfo{
			NodeName:     "the-node",
			StartTimeStr: "2020-01-02 12:12:56",
			Uid:          "uid-12",
			OwnerKind:    "Deployment",
			OwnerName:    "deployment-12",
		},
	}})
	inf.Notify(&informer.Event{Type: informer.EventType_CREATED, Resource: &informer.ObjectMeta{
		Name: "pod-34", Namespace: "the-ns",
		Pod: &informer.PodInfo{
			NodeName:     "the-node",
			StartTimeStr: "2020-01-02 12:34:56",
			Uid:          "uid-34",
			OwnerName:    "rs-34",
			OwnerKind:    "ReplicaSet",
		},
	}})
	inf.Notify(&informer.Event{Type: informer.EventType_CREATED, Resource: &informer.ObjectMeta{
		Name: "the-pod", Namespace: "the-ns",
		Pod: &informer.PodInfo{
			NodeName:     "the-node",
			Uid:          "uid-56",
			StartTimeStr: "2020-01-02 12:56:56",
		},
	}})

	dec := metadataDecorator{db: store, clusterName: "the-cluster"}
	inputCh, outputhCh := make(chan []request.Span, 10), make(chan []request.Span, 10)
	defer close(inputCh)
	go dec.nodeLoop(inputCh, outputhCh)

	autoNameSvc := svc.ID{}
	autoNameSvc.SetAutoName()

	t.Run("complete pod info should set deployment as name", func(t *testing.T) {
		inputCh <- []request.Span{{
			Pid: request.PidInfo{Namespace: 12}, ServiceID: autoNameSvc,
		}}
		deco := testutil.ReadChannel(t, outputhCh, timeout)
		require.Len(t, deco, 1)
		assert.Equal(t, "the-ns", deco[0].ServiceID.Namespace)
		assert.Equal(t, "deployment-12", deco[0].ServiceID.Name)
		assert.Equal(t, map[attr.Name]string{
			"k8s.node.name":       "the-node",
			"k8s.namespace.name":  "the-ns",
			"k8s.pod.name":        "pod-12",
			"k8s.pod.uid":         "uid-12",
			"k8s.deployment.name": "deployment-12",
			"k8s.owner.name":      "deployment-12",
			"k8s.pod.start_time":  "2020-01-02 12:12:56",
			"k8s.cluster.name":    "the-cluster",
		}, deco[0].ServiceID.Metadata)
	})
	t.Run("pod info without deployment should set replicaset as name", func(t *testing.T) {
		inputCh <- []request.Span{{
			Pid: request.PidInfo{Namespace: 34}, ServiceID: autoNameSvc,
		}}
		deco := testutil.ReadChannel(t, outputhCh, timeout)
		require.Len(t, deco, 1)
		assert.Equal(t, "the-ns", deco[0].ServiceID.Namespace)
		assert.Equal(t, "rs", deco[0].ServiceID.Name)
		assert.Equal(t, map[attr.Name]string{
			"k8s.node.name":       "the-node",
			"k8s.namespace.name":  "the-ns",
			"k8s.replicaset.name": "rs-34",
			"k8s.deployment.name": "rs",
			"k8s.owner.name":      "rs",
			"k8s.pod.name":        "pod-34",
			"k8s.pod.uid":         "uid-34",
			"k8s.pod.start_time":  "2020-01-02 12:34:56",
			"k8s.cluster.name":    "the-cluster",
		}, deco[0].ServiceID.Metadata)
	})
	t.Run("pod info with only pod name should set pod name as name", func(t *testing.T) {
		inputCh <- []request.Span{{
			Pid: request.PidInfo{Namespace: 56}, ServiceID: autoNameSvc,
		}}
		deco := testutil.ReadChannel(t, outputhCh, timeout)
		require.Len(t, deco, 1)
		assert.Equal(t, "the-ns", deco[0].ServiceID.Namespace)
		assert.Equal(t, "the-pod", deco[0].ServiceID.Name)
		assert.Equal(t, map[attr.Name]string{
			"k8s.node.name":      "the-node",
			"k8s.namespace.name": "the-ns",
			"k8s.pod.name":       "the-pod",
			"k8s.pod.uid":        "uid-56",
			"k8s.pod.start_time": "2020-01-02 12:56:56",
			"k8s.cluster.name":   "the-cluster",
		}, deco[0].ServiceID.Metadata)
	})
	t.Run("process without pod Info won't be decorated", func(t *testing.T) {
		svc := svc.ID{Name: "exec"}
		svc.SetAutoName()
		inputCh <- []request.Span{{
			Pid: request.PidInfo{Namespace: 78}, ServiceID: svc,
		}}
		deco := testutil.ReadChannel(t, outputhCh, timeout)
		require.Len(t, deco, 1)
		assert.Empty(t, deco[0].ServiceID.Namespace)
		assert.Equal(t, "exec", deco[0].ServiceID.Name)
		assert.Empty(t, deco[0].ServiceID.Metadata)
	})
	t.Run("if service name or namespace are manually specified, don't override them", func(t *testing.T) {
		inputCh <- []request.Span{{
			Pid: request.PidInfo{Namespace: 12}, ServiceID: svc.ID{Name: "tralari", Namespace: "tralara"},
		}}
		deco := testutil.ReadChannel(t, outputhCh, timeout)
		require.Len(t, deco, 1)
		assert.Equal(t, "tralara", deco[0].ServiceID.Namespace)
		assert.Equal(t, "tralari", deco[0].ServiceID.Name)
		assert.Equal(t, map[attr.Name]string{
			"k8s.node.name":       "the-node",
			"k8s.namespace.name":  "the-ns",
			"k8s.pod.name":        "pod-12",
			"k8s.pod.uid":         "uid-12",
			"k8s.deployment.name": "deployment-12",
			"k8s.owner.name":      "deployment-12",
			"k8s.pod.start_time":  "2020-01-02 12:12:56",
			"k8s.cluster.name":    "the-cluster",
		}, deco[0].ServiceID.Metadata)
	})
}

type fakeInformer struct {
	observer meta.Observer
}

func (f *fakeInformer) Subscribe(observer meta.Observer) {
	f.observer = observer
}

func (f *fakeInformer) Unsubscribe(_ meta.Observer) {
	f.observer = nil
}

func (f *fakeInformer) Notify(event *informer.Event) {
	f.observer.On(event)
}
