package transform

import (
	"testing"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	attr "github.com/grafana/beyla/pkg/export/attributes/names"
	kube2 "github.com/grafana/beyla/pkg/internal/kube"
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/svc"
	"github.com/grafana/beyla/pkg/internal/transform/kube"
)

func TestSuffixPrefix(t *testing.T) {
	assert.Equal(t, "super", trimSuffixIgnoreCase("superDuper", "DUPER"))
	assert.Equal(t, "superDup", trimSuffixIgnoreCase("superDuper", "ER"))
	assert.Equal(t, "superDuper", trimSuffixIgnoreCase("superDuper", "Not matching"))
	assert.Equal(t, "superDuper", trimSuffixIgnoreCase("superDuper", "SuperDuperDuper"))
	assert.Equal(t, "", trimSuffixIgnoreCase("superDuper", "SuperDuper"))
	assert.Equal(t, "superDuper", trimSuffixIgnoreCase("superDuper", ""))

	assert.Equal(t, "super", trimPrefixIgnoreCase("Dupersuper", "DUPER"))
	assert.Equal(t, "super", trimPrefixIgnoreCase("Ersuper", "ER"))
	assert.Equal(t, "superDuper", trimPrefixIgnoreCase("superDuper", "Not matching"))
	assert.Equal(t, "superDuper", trimPrefixIgnoreCase("superDuper", "SuperDuperDuper"))
	assert.Equal(t, "", trimPrefixIgnoreCase("superDuper", "SuperDuper"))
	assert.Equal(t, "superDuper", trimPrefixIgnoreCase("superDuper", ""))
}

func TestResolvePodsFromK8s(t *testing.T) {
	db := kube.CreateDatabase(nil)

	pod1 := kube2.PodInfo{
		ObjectMeta: metav1.ObjectMeta{Name: "pod1"},
		IPInfo:     kube2.IPInfo{IPs: []string{"10.0.0.1", "10.1.0.1"}},
	}

	pod2 := kube2.PodInfo{
		ObjectMeta: metav1.ObjectMeta{Name: "pod2", Namespace: "something"},
		IPInfo:     kube2.IPInfo{IPs: []string{"10.0.0.2", "10.1.0.2"}},
	}

	pod3 := kube2.PodInfo{
		ObjectMeta: metav1.ObjectMeta{Name: "pod3"},
		IPInfo:     kube2.IPInfo{IPs: []string{"10.0.0.3", "10.1.0.3"}},
	}

	db.UpdateNewPodsByIPIndex(&pod1)
	db.UpdateNewPodsByIPIndex(&pod2)
	db.UpdateNewPodsByIPIndex(&pod3)

	assert.Equal(t, &pod1, db.PodInfoForIP("10.0.0.1"))
	assert.Equal(t, &pod1, db.PodInfoForIP("10.1.0.1"))
	assert.Equal(t, &pod2, db.PodInfoForIP("10.0.0.2"))
	assert.Equal(t, &pod2, db.PodInfoForIP("10.1.0.2"))
	assert.Equal(t, &pod3, db.PodInfoForIP("10.1.0.3"))
	db.UpdateDeletedPodsByIPIndex(&pod3)
	assert.Nil(t, db.PodInfoForIP("10.1.0.3"))

	nr := NameResolver{
		db:      &db,
		cache:   expirable.NewLRU[string, string](10, nil, 5*time.Hour),
		sources: resolverSources([]string{"dns", "k8s"}),
	}

	name, namespace := nr.resolveFromK8s("10.0.0.1")
	assert.Equal(t, "pod1", name)
	assert.Equal(t, "", namespace)

	name, namespace = nr.resolveFromK8s("10.0.0.2")
	assert.Equal(t, "pod2", name)
	assert.Equal(t, "something", namespace)

	name, namespace = nr.resolveFromK8s("10.0.0.3")
	assert.Equal(t, "", name)
	assert.Equal(t, "", namespace)

	clientSpan := request.Span{
		Type: request.EventTypeHTTPClient,
		Peer: "10.0.0.1",
		Host: "10.0.0.2",
		ServiceID: svc.ID{
			Name:      "pod1",
			Namespace: "",
		},
	}

	serverSpan := request.Span{
		Type: request.EventTypeHTTP,
		Peer: "10.0.0.1",
		Host: "10.0.0.2",
		ServiceID: svc.ID{
			Name:      "pod2",
			Namespace: "something",
		},
	}

	nr.resolveNames(&clientSpan)

	assert.Equal(t, "pod1", clientSpan.PeerName)
	assert.Equal(t, "", clientSpan.ServiceID.Namespace)
	assert.Equal(t, "pod2", clientSpan.HostName)
	assert.Equal(t, "something", clientSpan.OtherNamespace)

	nr.resolveNames(&serverSpan)

	assert.Equal(t, "pod1", serverSpan.PeerName)
	assert.Equal(t, "", serverSpan.OtherNamespace)
	assert.Equal(t, "pod2", serverSpan.HostName)
	assert.Equal(t, "something", serverSpan.ServiceID.Namespace)
}

func TestResolveServiceFromK8s(t *testing.T) {
	db := kube.CreateDatabase(nil)

	svc1 := kube2.ServiceInfo{
		ObjectMeta: metav1.ObjectMeta{Name: "pod1"},
		IPInfo:     kube2.IPInfo{IPs: []string{"10.0.0.1", "10.1.0.1"}},
	}

	svc2 := kube2.ServiceInfo{
		ObjectMeta: metav1.ObjectMeta{Name: "pod2", Namespace: "something"},
		IPInfo:     kube2.IPInfo{IPs: []string{"10.0.0.2", "10.1.0.2"}},
	}

	svc3 := kube2.ServiceInfo{
		ObjectMeta: metav1.ObjectMeta{Name: "pod3"},
		IPInfo:     kube2.IPInfo{IPs: []string{"10.0.0.3", "10.1.0.3"}},
	}

	db.UpdateNewServicesByIPIndex(&svc1)
	db.UpdateNewServicesByIPIndex(&svc2)
	db.UpdateNewServicesByIPIndex(&svc3)

	assert.Equal(t, &svc1, db.ServiceInfoForIP("10.0.0.1"))
	assert.Equal(t, &svc1, db.ServiceInfoForIP("10.1.0.1"))
	assert.Equal(t, &svc2, db.ServiceInfoForIP("10.0.0.2"))
	assert.Equal(t, &svc2, db.ServiceInfoForIP("10.1.0.2"))
	assert.Equal(t, &svc3, db.ServiceInfoForIP("10.1.0.3"))
	db.UpdateDeletedServicesByIPIndex(&svc3)
	assert.Nil(t, db.PodInfoForIP("10.1.0.3"))

	nr := NameResolver{
		db:      &db,
		cache:   expirable.NewLRU[string, string](10, nil, 5*time.Hour),
		sources: resolverSources([]string{"dns", "k8s"}),
	}

	name, namespace := nr.resolveFromK8s("10.0.0.1")
	assert.Equal(t, "pod1", name)
	assert.Equal(t, "", namespace)

	name, namespace = nr.resolveFromK8s("10.0.0.2")
	assert.Equal(t, "pod2", name)
	assert.Equal(t, "something", namespace)

	name, namespace = nr.resolveFromK8s("10.0.0.3")
	assert.Equal(t, "", name)
	assert.Equal(t, "", namespace)

	clientSpan := request.Span{
		Type: request.EventTypeHTTPClient,
		Peer: "10.0.0.1",
		Host: "10.0.0.2",
		ServiceID: svc.ID{
			Name:      "pod1",
			Namespace: "",
		},
	}

	serverSpan := request.Span{
		Type: request.EventTypeHTTP,
		Peer: "10.0.0.1",
		Host: "10.0.0.2",
		ServiceID: svc.ID{
			Name:      "pod2",
			Namespace: "something",
		},
	}

	nr.resolveNames(&clientSpan)

	assert.Equal(t, "pod1", clientSpan.PeerName)
	assert.Equal(t, "", clientSpan.ServiceID.Namespace)
	assert.Equal(t, "pod2", clientSpan.HostName)
	assert.Equal(t, "something", clientSpan.OtherNamespace)

	nr.resolveNames(&serverSpan)

	assert.Equal(t, "pod1", serverSpan.PeerName)
	assert.Equal(t, "", serverSpan.OtherNamespace)
	assert.Equal(t, "pod2", serverSpan.HostName)
	assert.Equal(t, "something", serverSpan.ServiceID.Namespace)
}

func TestCleanName(t *testing.T) {
	s := svc.ID{
		Name:      "service",
		Namespace: "special.namespace",
		Metadata: map[attr.Name]string{
			attr.K8sNamespaceName: "k8snamespace",
		},
	}

	nr := NameResolver{}

	assert.Equal(t, "service", nr.cleanName(&s, "127.0.0.1", "127-0-0-1.service"))
	assert.Equal(t, "1.service", nr.cleanName(&s, "127.0.0.1", "1.service"))
	assert.Equal(t, "service", nr.cleanName(&s, "127.0.0.1", "service."))
	assert.Equal(t, "service", nr.cleanName(&s, "127.0.0.1", "service.svc.cluster.local."))
	assert.Equal(t, "service", nr.cleanName(&s, "127.0.0.1", "service.special.namespace.svc.cluster.local."))
	assert.Equal(t, "service", nr.cleanName(&s, "127.0.0.1", "service.k8snamespace.svc.cluster.local."))
}

func TestResolveNodesFromK8s(t *testing.T) {
	db := kube.CreateDatabase(nil)

	node1 := kube2.NodeInfo{
		ObjectMeta: metav1.ObjectMeta{Name: "node1"},
		IPInfo:     kube2.IPInfo{IPs: []string{"10.0.0.1", "10.1.0.1"}},
	}

	node2 := kube2.NodeInfo{
		ObjectMeta: metav1.ObjectMeta{Name: "node2", Namespace: "something"},
		IPInfo:     kube2.IPInfo{IPs: []string{"10.0.0.2", "10.1.0.2"}},
	}

	node3 := kube2.NodeInfo{
		ObjectMeta: metav1.ObjectMeta{Name: "node3"},
		IPInfo:     kube2.IPInfo{IPs: []string{"10.0.0.3", "10.1.0.3"}},
	}

	db.UpdateNewNodesByIPIndex(&node1)
	db.UpdateNewNodesByIPIndex(&node2)
	db.UpdateNewNodesByIPIndex(&node3)

	assert.Equal(t, &node1, db.NodeInfoForIP("10.0.0.1"))
	assert.Equal(t, &node1, db.NodeInfoForIP("10.1.0.1"))
	assert.Equal(t, &node2, db.NodeInfoForIP("10.0.0.2"))
	assert.Equal(t, &node2, db.NodeInfoForIP("10.1.0.2"))
	assert.Equal(t, &node3, db.NodeInfoForIP("10.1.0.3"))
	db.UpdateDeletedNodesByIPIndex(&node3)
	assert.Nil(t, db.NodeInfoForIP("10.1.0.3"))

	nr := NameResolver{
		db:      &db,
		cache:   expirable.NewLRU[string, string](10, nil, 5*time.Hour),
		sources: resolverSources([]string{"dns", "k8s"}),
	}

	name, namespace := nr.resolveFromK8s("10.0.0.1")
	assert.Equal(t, "node1", name)
	assert.Equal(t, "", namespace)

	name, namespace = nr.resolveFromK8s("10.0.0.2")
	assert.Equal(t, "node2", name)
	assert.Equal(t, "something", namespace)

	name, namespace = nr.resolveFromK8s("10.0.0.3")
	assert.Equal(t, "", name)
	assert.Equal(t, "", namespace)

	clientSpan := request.Span{
		Type: request.EventTypeHTTPClient,
		Peer: "10.0.0.1",
		Host: "10.0.0.2",
		ServiceID: svc.ID{
			Name:      "node1",
			Namespace: "",
		},
	}

	serverSpan := request.Span{
		Type: request.EventTypeHTTP,
		Peer: "10.0.0.1",
		Host: "10.0.0.2",
		ServiceID: svc.ID{
			Name:      "node2",
			Namespace: "something",
		},
	}

	nr.resolveNames(&clientSpan)

	assert.Equal(t, "node1", clientSpan.PeerName)
	assert.Equal(t, "", clientSpan.ServiceID.Namespace)
	assert.Equal(t, "node2", clientSpan.HostName)
	assert.Equal(t, "something", clientSpan.OtherNamespace)

	nr.resolveNames(&serverSpan)

	assert.Equal(t, "node1", serverSpan.PeerName)
	assert.Equal(t, "", serverSpan.OtherNamespace)
	assert.Equal(t, "node2", serverSpan.HostName)
	assert.Equal(t, "something", serverSpan.ServiceID.Namespace)
}
