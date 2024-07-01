package transform

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	attr "github.com/grafana/beyla/pkg/internal/export/attributes/names"
	"github.com/grafana/beyla/pkg/internal/kube"
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/svc"
	"github.com/grafana/beyla/pkg/internal/testutil"
)

const timeout = 5 * time.Second

func TestDecoration(t *testing.T) {
	// pre-populated kubernetes metadata database
	dec := metadataDecorator{db: &fakeDatabase{pidNSPods: map[uint32]*kube.PodInfo{
		12: &kube.PodInfo{
			ObjectMeta: v1.ObjectMeta{
				Name: "pod-12", Namespace: "the-ns", UID: "uid-12",
			},
			NodeName:     "the-node",
			StartTimeStr: "2020-01-02 12:12:56",
			Owner:        &kube.Owner{LabelName: kube.OwnerDeployment, Name: "deployment-12"},
		},
		34: &kube.PodInfo{
			ObjectMeta: v1.ObjectMeta{
				Name: "pod-34", Namespace: "the-ns", UID: "uid-34",
			},
			NodeName:     "the-node",
			StartTimeStr: "2020-01-02 12:34:56",
			Owner:        &kube.Owner{LabelName: kube.OwnerReplicaSet, Name: "rs-34"},
		},
		56: &kube.PodInfo{
			ObjectMeta: v1.ObjectMeta{
				Name: "the-pod", Namespace: "the-ns", UID: "uid-56",
			},
			NodeName:     "the-node",
			StartTimeStr: "2020-01-02 12:56:56",
		},
	}}, clusterName: "the-cluster"}
	inputCh, outputhCh := make(chan []request.Span, 10), make(chan []request.Span, 10)
	defer close(inputCh)
	go dec.nodeLoop(inputCh, outputhCh)

	t.Run("complete pod info should set deployment as name", func(t *testing.T) {
		inputCh <- []request.Span{{
			Pid: request.PidInfo{Namespace: 12}, ServiceID: svc.ID{AutoName: true},
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
			"k8s.pod.start_time":  "2020-01-02 12:12:56",
			"k8s.cluster.name":    "the-cluster",
		}, deco[0].ServiceID.Metadata)
	})
	t.Run("pod info without deployment should set replicaset as name", func(t *testing.T) {
		inputCh <- []request.Span{{
			Pid: request.PidInfo{Namespace: 34}, ServiceID: svc.ID{AutoName: true},
		}}
		deco := testutil.ReadChannel(t, outputhCh, timeout)
		require.Len(t, deco, 1)
		assert.Equal(t, "the-ns", deco[0].ServiceID.Namespace)
		assert.Equal(t, "rs-34", deco[0].ServiceID.Name)
		assert.Equal(t, map[attr.Name]string{
			"k8s.node.name":       "the-node",
			"k8s.namespace.name":  "the-ns",
			"k8s.replicaset.name": "rs-34",
			"k8s.pod.name":        "pod-34",
			"k8s.pod.uid":         "uid-34",
			"k8s.pod.start_time":  "2020-01-02 12:34:56",
			"k8s.cluster.name":    "the-cluster",
		}, deco[0].ServiceID.Metadata)
	})
	t.Run("pod info with only pod name should set pod name as name", func(t *testing.T) {
		inputCh <- []request.Span{{
			Pid: request.PidInfo{Namespace: 56}, ServiceID: svc.ID{AutoName: true},
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
		inputCh <- []request.Span{{
			Pid: request.PidInfo{Namespace: 78}, ServiceID: svc.ID{Name: "exec", AutoName: true},
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
			"k8s.pod.start_time":  "2020-01-02 12:12:56",
			"k8s.cluster.name":    "the-cluster",
		}, deco[0].ServiceID.Metadata)
	})
}

type fakeDatabase struct {
	pidNSPods map[uint32]*kube.PodInfo
	ipNames   map[string]string
}

func (f *fakeDatabase) HostNameForIP(ip string) string {
	return f.ipNames[ip]
}

func (f *fakeDatabase) OwnerPodInfo(pidNamespace uint32) (*kube.PodInfo, bool) {
	pi, ok := f.pidNSPods[pidNamespace]
	return pi, ok
}
