package transform

import (
	"testing"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/svc"
	attr "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/attributes/names"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/kubecache/informer"
	"github.com/stretchr/testify/assert"

	kube2 "github.com/grafana/beyla/v2/pkg/internal/kube"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/app/request"
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
	inf := &fakeInformer{}
	db := kube2.NewStore(inf, kube2.ResourceLabels{}, nil)
	pod1 := &informer.ObjectMeta{Name: "pod1", Kind: "Pod", Ips: []string{"10.0.0.1", "10.1.0.1"}}
	pod2 := &informer.ObjectMeta{Name: "pod2", Namespace: "something", Kind: "Pod", Ips: []string{"10.0.0.2", "10.1.0.2"}}
	pod3 := &informer.ObjectMeta{Name: "pod3", Kind: "Pod", Ips: []string{"10.0.0.3", "10.1.0.3"}}
	inf.Notify(&informer.Event{Type: informer.EventType_CREATED, Resource: pod1})
	inf.Notify(&informer.Event{Type: informer.EventType_CREATED, Resource: pod2})
	inf.Notify(&informer.Event{Type: informer.EventType_CREATED, Resource: pod3})

	assert.Equal(t, pod1, db.ObjectMetaByIP("10.0.0.1").Meta)
	assert.Equal(t, pod1, db.ObjectMetaByIP("10.1.0.1").Meta)
	assert.Equal(t, pod2, db.ObjectMetaByIP("10.0.0.2").Meta)
	assert.Equal(t, pod2, db.ObjectMetaByIP("10.1.0.2").Meta)
	assert.Equal(t, pod3, db.ObjectMetaByIP("10.1.0.3").Meta)

	inf.Notify(&informer.Event{Type: informer.EventType_DELETED, Resource: pod3})
	assert.Nil(t, db.ObjectMetaByIP("10.1.0.3"))

	nr := NameResolver{
		db:      db,
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
		Service: svc.Attrs{UID: svc.UID{
			Name:      "pod1",
			Namespace: "",
		}},
	}

	serverSpan := request.Span{
		Type: request.EventTypeHTTP,
		Peer: "10.0.0.1",
		Host: "10.0.0.2",
		Service: svc.Attrs{UID: svc.UID{
			Name:      "pod2",
			Namespace: "something",
		}},
	}

	nr.resolveNames(&clientSpan)

	assert.Equal(t, "pod1", clientSpan.PeerName)
	assert.Equal(t, "", clientSpan.Service.UID.Namespace)
	assert.Equal(t, "pod2", clientSpan.HostName)
	assert.Equal(t, "something", clientSpan.OtherNamespace)

	nr.resolveNames(&serverSpan)

	assert.Equal(t, "pod1", serverSpan.PeerName)
	assert.Equal(t, "", serverSpan.OtherNamespace)
	assert.Equal(t, "pod2", serverSpan.HostName)
	assert.Equal(t, "something", serverSpan.Service.UID.Namespace)
}

func TestResolveServiceFromK8s(t *testing.T) {
	inf := &fakeInformer{}
	db := kube2.NewStore(inf, kube2.ResourceLabels{}, nil)
	pod1 := &informer.ObjectMeta{Name: "pod1", Kind: "Service", Ips: []string{"10.0.0.1", "10.1.0.1"}}
	pod2 := &informer.ObjectMeta{Name: "pod2", Namespace: "something", Kind: "Service", Ips: []string{"10.0.0.2", "10.1.0.2"}}
	pod3 := &informer.ObjectMeta{Name: "pod3", Kind: "Service", Ips: []string{"10.0.0.3", "10.1.0.3"}}
	inf.Notify(&informer.Event{Type: informer.EventType_CREATED, Resource: pod1})
	inf.Notify(&informer.Event{Type: informer.EventType_CREATED, Resource: pod2})
	inf.Notify(&informer.Event{Type: informer.EventType_CREATED, Resource: pod3})

	assert.Equal(t, pod1, db.ObjectMetaByIP("10.0.0.1").Meta)
	assert.Equal(t, pod1, db.ObjectMetaByIP("10.1.0.1").Meta)
	assert.Equal(t, pod2, db.ObjectMetaByIP("10.0.0.2").Meta)
	assert.Equal(t, pod2, db.ObjectMetaByIP("10.1.0.2").Meta)
	assert.Equal(t, pod3, db.ObjectMetaByIP("10.1.0.3").Meta)
	inf.Notify(&informer.Event{Type: informer.EventType_DELETED, Resource: pod3})
	assert.Nil(t, db.ObjectMetaByIP("10.1.0.3"))

	nr := NameResolver{
		db:      db,
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
		Service: svc.Attrs{UID: svc.UID{
			Name:      "pod1",
			Namespace: "",
		}},
	}

	serverSpan := request.Span{
		Type: request.EventTypeHTTP,
		Peer: "10.0.0.1",
		Host: "10.0.0.2",
		Service: svc.Attrs{UID: svc.UID{
			Name:      "pod2",
			Namespace: "something",
		}},
	}

	nr.resolveNames(&clientSpan)

	assert.Equal(t, "pod1", clientSpan.PeerName)
	assert.Equal(t, "", clientSpan.Service.UID.Namespace)
	assert.Equal(t, "pod2", clientSpan.HostName)
	assert.Equal(t, "something", clientSpan.OtherNamespace)

	nr.resolveNames(&serverSpan)

	assert.Equal(t, "pod1", serverSpan.PeerName)
	assert.Equal(t, "", serverSpan.OtherNamespace)
	assert.Equal(t, "pod2", serverSpan.HostName)
	assert.Equal(t, "something", serverSpan.Service.UID.Namespace)
}

func TestCleanName(t *testing.T) {
	s := svc.Attrs{
		UID: svc.UID{
			Name:      "service",
			Namespace: "special.namespace",
		},
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
	inf := &fakeInformer{}
	db := kube2.NewStore(inf, kube2.ResourceLabels{}, nil)
	node1 := &informer.ObjectMeta{Name: "node1", Kind: "Node", Ips: []string{"10.0.0.1", "10.1.0.1"}}
	node2 := &informer.ObjectMeta{Name: "node2", Namespace: "something", Kind: "Node", Ips: []string{"10.0.0.2", "10.1.0.2"}}
	node3 := &informer.ObjectMeta{Name: "node3", Kind: "Node", Ips: []string{"10.0.0.3", "10.1.0.3"}}
	inf.Notify(&informer.Event{Type: informer.EventType_CREATED, Resource: node1})
	inf.Notify(&informer.Event{Type: informer.EventType_CREATED, Resource: node2})
	inf.Notify(&informer.Event{Type: informer.EventType_CREATED, Resource: node3})

	assert.Equal(t, node1, db.ObjectMetaByIP("10.0.0.1").Meta)
	assert.Equal(t, node1, db.ObjectMetaByIP("10.1.0.1").Meta)
	assert.Equal(t, node2, db.ObjectMetaByIP("10.0.0.2").Meta)
	assert.Equal(t, node2, db.ObjectMetaByIP("10.1.0.2").Meta)
	assert.Equal(t, node3, db.ObjectMetaByIP("10.1.0.3").Meta)
	inf.Notify(&informer.Event{Type: informer.EventType_DELETED, Resource: node3})
	assert.Nil(t, db.ObjectMetaByIP("10.1.0.3"))

	nr := NameResolver{
		db:      db,
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
		Service: svc.Attrs{UID: svc.UID{
			Name:      "node1",
			Namespace: "",
		}},
	}

	serverSpan := request.Span{
		Type: request.EventTypeHTTP,
		Peer: "10.0.0.1",
		Host: "10.0.0.2",
		Service: svc.Attrs{UID: svc.UID{
			Name:      "node2",
			Namespace: "something",
		}},
	}

	nr.resolveNames(&clientSpan)

	assert.Equal(t, "node1", clientSpan.PeerName)
	assert.Equal(t, "", clientSpan.Service.UID.Namespace)
	assert.Equal(t, "node2", clientSpan.HostName)
	assert.Equal(t, "something", clientSpan.OtherNamespace)

	nr.resolveNames(&serverSpan)

	assert.Equal(t, "node1", serverSpan.PeerName)
	assert.Equal(t, "", serverSpan.OtherNamespace)
	assert.Equal(t, "node2", serverSpan.HostName)
	assert.Equal(t, "something", serverSpan.Service.UID.Namespace)
}
