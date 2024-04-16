package transform

import (
	"testing"
	"time"

	kube2 "github.com/grafana/beyla/pkg/internal/kube"
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/svc"
	"github.com/grafana/beyla/pkg/internal/transform/kube"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

func TestResolveFromK8s(t *testing.T) {
	db := kube.CreateDatabase(nil)

	pod1 := kube2.PodInfo{
		ObjectMeta: metav1.ObjectMeta{Name: "pod1"},
		IPs:        []string{"10.0.0.1", "10.1.0.1"},
	}

	pod2 := kube2.PodInfo{
		ObjectMeta: metav1.ObjectMeta{Name: "pod2", Namespace: "something"},
		IPs:        []string{"10.0.0.2", "10.1.0.2"},
	}

	pod3 := kube2.PodInfo{
		ObjectMeta: metav1.ObjectMeta{Name: "pod3"},
		IPs:        []string{"10.0.0.3", "10.1.0.3"},
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
		db:     &db,
		cache:  expirable.NewLRU[string, string](10, nil, 5*time.Hour),
		sCache: expirable.NewLRU[string, svc.ID](10, nil, 5*time.Hour),
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
		Metadata: map[string]string{
			kube2.NamespaceName: "k8snamespace",
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
