package kube

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/grafana/beyla/pkg/kubecache/informer"
	"github.com/grafana/beyla/pkg/kubecache/meta"
)

func TestContainerInfo(t *testing.T) {
	deployment := informer.Owner{
		Name: "service",
		Kind: "Deployment",
	}

	replicaSet := informer.Owner{
		Name: "serviceB",
		Kind: "ReplicaSet",
	}

	service := informer.ObjectMeta{
		Name:      "service",
		Namespace: "namespaceA",
		Ips:       []string{"169.0.0.1", "169.0.0.2"},
		Kind:      "Service",
	}

	podMetaA := informer.ObjectMeta{
		Name:      "podA",
		Namespace: "namespaceA",
		Ips:       []string{"1.1.1.1", "2.2.2.2"},
		Kind:      "Pod",
		Pod: &informer.PodInfo{
			Owners: []*informer.Owner{&deployment},
			Containers: []*informer.ContainerInfo{
				{
					Id:  "container1",
					Env: map[string]string{"OTEL_SERVICE_NAME": "customName"},
				},
				{
					Id:  "container2",
					Env: map[string]string{"OTEL_RESOURCE_ATTRIBUTES": "service.namespace=boo,other.attr=goo"},
				},
			},
		},
	}

	podMetaA1 := informer.ObjectMeta{
		Name:      "podA_1",
		Namespace: "namespaceA",
		Ips:       []string{"3.1.1.1", "3.2.2.2"},
		Kind:      "Pod",
		Pod: &informer.PodInfo{
			Owners: []*informer.Owner{&deployment},
			Containers: []*informer.ContainerInfo{
				{
					Id:  "container5",
					Env: map[string]string{"OTEL_SERVICE_NAME_NOT_EXIST": "customName"},
				},
				{
					Id:  "container6",
					Env: map[string]string{"OTEL_RESOURCE_ATTRIBUTES": "service.namespace1=boo,other.attr=goo"},
				},
			},
		},
	}

	podMetaB := informer.ObjectMeta{
		Name:      "podB",
		Namespace: "namespaceB",
		Ips:       []string{"1.2.1.2", "2.1.2.1"},
		Kind:      "Pod",
		Pod: &informer.PodInfo{
			Owners: []*informer.Owner{&replicaSet},
			Containers: []*informer.ContainerInfo{
				{
					Id: "container3",
				},
				{
					Id:  "container4",
					Env: map[string]string{"OTEL_RESOURCE_ATTRIBUTES": "service.namespace=boo,other.attr=goo"},
				},
			},
		},
	}

	fInformer := &fakeInformer{}

	store := NewStore(fInformer)

	store.updateNewObjectMetaByIPIndex(&service)
	store.updateNewObjectMetaByIPIndex(&podMetaA)
	store.updateNewObjectMetaByIPIndex(&podMetaA1)
	store.updateNewObjectMetaByIPIndex(&podMetaB)

	assert.Equal(t, 2, len(store.containersByOwner))

	serviceKey := ownerID(podMetaA.Namespace, service.Name)
	serviceContainers, ok := store.containersByOwner[serviceKey]
	assert.True(t, ok)
	assert.Equal(t, 4, len(serviceContainers))

	replicaSetKey := ownerID(podMetaB.Namespace, replicaSet.Name)
	replicaSetContainers, ok := store.containersByOwner[replicaSetKey]
	assert.True(t, ok)
	assert.Equal(t, 2, len(replicaSetContainers))

	assert.Equal(t, 0, len(store.otelServiceInfoByIP))

	t.Run("test with service attributes set", func(tt *testing.T) {
		for _, ip := range []string{"169.0.0.1", "1.1.1.1", "3.1.1.1"} {
			name, namespace := store.ServiceNameNamespaceForIP(ip)
			assert.Equal(tt, "customName", name, ip)
			assert.Equal(tt, "boo", namespace, ip)
		}
	})

	assert.Equal(t, 3, len(store.otelServiceInfoByIP))
	// Delete the pod which had good definition for the OTel variables.
	// We expect much different service names now
	store.updateDeletedObjectMetaByIPIndex(&podMetaA)
	// We cleaned up the cache for service IPs. We must clean all of it
	// otherwise there will be stale data left
	assert.Equal(t, 0, len(store.otelServiceInfoByIP))

	serviceKey = ownerID(podMetaA.Namespace, service.Name)
	serviceContainers, ok = store.containersByOwner[serviceKey]
	assert.True(t, ok)
	assert.Equal(t, 2, len(serviceContainers))

	t.Run("test without service attributes set", func(tt *testing.T) {
		// We removed the pod that defined the env variables
		for _, ip := range []string{"169.0.0.1", "3.1.1.1"} {
			name, namespace := store.ServiceNameNamespaceForIP(ip)
			assert.Equal(tt, "service", name)
			assert.Equal(tt, "namespaceA", namespace)
		}

		name, namespace := store.ServiceNameNamespaceForIP("1.1.1.1")
		assert.Equal(tt, "", name)
		assert.Equal(tt, "", namespace)
	})

	// 3 again, because we cache that we can't see the IP in our info
	assert.Equal(t, 3, len(store.otelServiceInfoByIP))

	t.Run("test with only namespace attributes set", func(tt *testing.T) {
		// We removed the pod that defined the env variables
		for _, ip := range []string{"1.2.1.2", "2.1.2.1"} {
			name, namespace := store.ServiceNameNamespaceForIP(ip)
			assert.Equal(tt, "serviceB", name)
			assert.Equal(tt, "boo", namespace)
		}
	})

	assert.Equal(t, 5, len(store.otelServiceInfoByIP))

	store.updateDeletedObjectMetaByIPIndex(&podMetaA1)
	store.updateDeletedObjectMetaByIPIndex(&podMetaB)

	assert.Equal(t, 0, len(store.otelServiceInfoByIP))

	// No containers left
	replicaSetKey = ownerID(podMetaB.Namespace, replicaSet.Name)
	_, ok = store.containersByOwner[replicaSetKey]
	assert.False(t, ok)

	serviceKey = ownerID(podMetaA.Namespace, service.Name)
	_, ok = store.containersByOwner[serviceKey]
	assert.False(t, ok)

	name, namespace := store.ServiceNameNamespaceForIP("169.0.0.2")
	assert.Equal(t, "service", name)
	assert.Equal(t, "namespaceA", namespace)
}

func TestMemoryCleanedUp(t *testing.T) {
	deployment := informer.Owner{
		Name: "service",
		Kind: "Deployment",
	}

	replicaSet := informer.Owner{
		Name: "serviceB",
		Kind: "ReplicaSet",
	}

	service := informer.ObjectMeta{
		Name:      "service",
		Namespace: "namespaceA",
		Ips:       []string{"169.0.0.1", "169.0.0.2"},
		Kind:      "Service",
	}

	podMetaA := informer.ObjectMeta{
		Name:      "podA",
		Namespace: "namespaceA",
		Ips:       []string{"1.1.1.1", "2.2.2.2"},
		Kind:      "Pod",
		Pod: &informer.PodInfo{
			Owners: []*informer.Owner{&deployment},
			Containers: []*informer.ContainerInfo{
				{
					Id:  "container1",
					Env: map[string]string{"OTEL_SERVICE_NAME": "customName"},
				},
				{
					Id:  "container2",
					Env: map[string]string{"OTEL_RESOURCE_ATTRIBUTES": "service.namespace=boo,other.attr=goo"},
				},
			},
		},
	}

	podMetaA1 := informer.ObjectMeta{
		Name:      "podA_1",
		Namespace: "namespaceA",
		Ips:       []string{"3.1.1.1", "3.2.2.2"},
		Kind:      "Pod",
		Pod: &informer.PodInfo{
			Owners: []*informer.Owner{&deployment},
			Containers: []*informer.ContainerInfo{
				{
					Id:  "container5",
					Env: map[string]string{"OTEL_SERVICE_NAME_NOT_EXIST": "customName"},
				},
				{
					Id:  "container6",
					Env: map[string]string{"OTEL_RESOURCE_ATTRIBUTES": "service.namespace1=boo,other.attr=goo"},
				},
			},
		},
	}

	podMetaB := informer.ObjectMeta{
		Name:      "podB",
		Namespace: "namespaceB",
		Ips:       []string{"1.2.1.2", "2.1.2.1"},
		Kind:      "Pod",
		Pod: &informer.PodInfo{
			Owners: []*informer.Owner{&replicaSet},
			Containers: []*informer.ContainerInfo{
				{
					Id: "container3",
				},
				{
					Id:  "container4",
					Env: map[string]string{"OTEL_RESOURCE_ATTRIBUTES": "service.namespace=boo,other.attr=goo"},
				},
			},
		},
	}

	fInformer := &fakeInformer{}

	store := NewStore(fInformer)

	store.updateNewObjectMetaByIPIndex(&service)
	store.updateNewObjectMetaByIPIndex(&podMetaA)
	store.updateNewObjectMetaByIPIndex(&podMetaA1)
	store.updateNewObjectMetaByIPIndex(&podMetaB)

	store.updateDeletedObjectMetaByIPIndex(&podMetaA1)
	store.updateDeletedObjectMetaByIPIndex(&podMetaA)
	store.updateDeletedObjectMetaByIPIndex(&podMetaB)
	store.updateDeletedObjectMetaByIPIndex(&service)

	assert.Equal(t, 0, len(store.containerIDs))
	assert.Equal(t, 0, len(store.containerByPID))
	assert.Equal(t, 0, len(store.namespaces))
	assert.Equal(t, 0, len(store.podsByContainer))
	assert.Equal(t, 0, len(store.containersByOwner))
	assert.Equal(t, 0, len(store.ipInfos))
	assert.Equal(t, 0, len(store.otelServiceInfoByIP))
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
		observer.On(event)
	}
}
