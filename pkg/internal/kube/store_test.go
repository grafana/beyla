package kube

import (
	"sync"
	"testing"
	"text/template"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/kubecache/informer"

	"github.com/grafana/beyla/v2/pkg/kubecache/meta"
)

func TestContainerInfoWithTemplate(t *testing.T) {
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
		Labels: map[string]string{
			"app.kubernetes.io/name":      "applicationA",
			"app.kubernetes.io/component": "componentA",
		},
		Ips:  []string{"1.1.1.1", "2.2.2.2"},
		Kind: "Pod",
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
		Labels: map[string]string{
			"app.kubernetes.io/name":      "applicationA",
			"app.kubernetes.io/component": "componentB",
		},
		Ips:  []string{"3.1.1.1", "3.2.2.2"},
		Kind: "Pod",
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
		Labels: map[string]string{
			"app.kubernetes.io/name":      "applicationB",
			"app.kubernetes.io/component": "componentA",
		},
		Ips:  []string{"1.2.1.2", "2.1.2.1"},
		Kind: "Pod",
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

	templ, _ := template.New("serviceNameTemplate").Parse(`{{- if eq .Meta.Pod nil }}{{.Meta.Name}}{{ else }}{{- .Meta.Namespace }}/{{ index .Meta.Labels "app.kubernetes.io/name" }}/{{ index .Meta.Labels "app.kubernetes.io/component" -}}{{ if .ContainerName }}/{{ .ContainerName -}}{{ end -}}{{ end -}}`)

	store := NewStore(fInformer, ResourceLabels{}, templ)

	_ = store.On(&informer.Event{Type: informer.EventType_CREATED, Resource: &service})
	_ = store.On(&informer.Event{Type: informer.EventType_CREATED, Resource: &podMetaA})
	_ = store.On(&informer.Event{Type: informer.EventType_CREATED, Resource: &podMetaA1})
	_ = store.On(&informer.Event{Type: informer.EventType_CREATED, Resource: &podMetaB})

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
	_ = store.On(&informer.Event{Type: informer.EventType_DELETED, Resource: &podMetaA})
	// We cleaned up the cache for service IPs. We must clean all of it
	// otherwise there will be stale data left
	assert.Equal(t, 0, len(store.otelServiceInfoByIP))

	serviceKey = ownerID(podMetaA.Namespace, service.Name)
	serviceContainers, ok = store.containersByOwner[serviceKey]
	assert.True(t, ok)
	assert.Equal(t, 2, len(serviceContainers))

	t.Run("test without service attributes set", func(tt *testing.T) {
		// We removed the pod that defined the env variables
		name, namespace := store.ServiceNameNamespaceForIP("169.0.0.1")
		assert.Equal(tt, "service", name)
		assert.Equal(tt, "namespaceA", namespace)

		name, namespace = store.ServiceNameNamespaceForIP("3.1.1.1")
		assert.Equal(tt, "namespaceA/applicationA/componentB", name)
		assert.Equal(tt, "namespaceA", namespace)

		name, namespace = store.ServiceNameNamespaceForIP("1.1.1.1")
		assert.Equal(tt, "", name)
		assert.Equal(tt, "", namespace)
	})

	// 3 again, because we cache that we can't see the IP in our info
	assert.Equal(t, 3, len(store.otelServiceInfoByIP))

	t.Run("test with only namespace attributes set", func(tt *testing.T) {
		// We removed the pod that defined the env variables
		name, namespace := store.ServiceNameNamespaceForIP("1.2.1.2")
		assert.Equal(tt, "namespaceB/applicationB/componentA", name)
		assert.Equal(tt, "boo", namespace)

		name, namespace = store.ServiceNameNamespaceForIP("2.1.2.1")
		assert.Equal(tt, "namespaceB/applicationB/componentA", name)
		assert.Equal(tt, "boo", namespace)
	})

	assert.Equal(t, 5, len(store.otelServiceInfoByIP))

	_ = store.On(&informer.Event{Type: informer.EventType_DELETED, Resource: &podMetaA1})
	_ = store.On(&informer.Event{Type: informer.EventType_DELETED, Resource: &podMetaB})

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

	t.Run("test with container name", func(tt *testing.T) {
		name, namespace := store.ServiceNameNamespaceForMetadata(&podMetaA, "container1")
		assert.Equal(tt, "namespaceA/applicationA/componentA/container1", name)
		assert.Equal(tt, "namespaceA", namespace)

		name, namespace = store.ServiceNameNamespaceForMetadata(&podMetaA, "container2")
		assert.Equal(tt, "namespaceA/applicationA/componentA/container2", name)
		assert.Equal(tt, "namespaceA", namespace)

		name, namespace = store.ServiceNameNamespaceForMetadata(&podMetaA1, "container5")
		assert.Equal(tt, "namespaceA/applicationA/componentB/container5", name)
		assert.Equal(tt, "namespaceA", namespace)

		name, namespace = store.ServiceNameNamespaceForMetadata(&podMetaA1, "container6")
		assert.Equal(tt, "namespaceA/applicationA/componentB/container6", name)
		assert.Equal(tt, "namespaceA", namespace)

		name, namespace = store.ServiceNameNamespaceForMetadata(&podMetaB, "container3")
		assert.Equal(tt, "namespaceB/applicationB/componentA/container3", name)
		assert.Equal(tt, "namespaceB", namespace)

		name, namespace = store.ServiceNameNamespaceForMetadata(&podMetaB, "container4")
		assert.Equal(tt, "namespaceB/applicationB/componentA/container4", name)
		assert.Equal(tt, "namespaceB", namespace)
	})
}

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

	store := NewStore(fInformer, ResourceLabels{}, nil)

	_ = store.On(&informer.Event{Type: informer.EventType_CREATED, Resource: &service})
	_ = store.On(&informer.Event{Type: informer.EventType_CREATED, Resource: &podMetaA})
	_ = store.On(&informer.Event{Type: informer.EventType_CREATED, Resource: &podMetaA1})
	_ = store.On(&informer.Event{Type: informer.EventType_CREATED, Resource: &podMetaB})

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
	_ = store.On(&informer.Event{Type: informer.EventType_DELETED, Resource: &podMetaA})
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

	_ = store.On(&informer.Event{Type: informer.EventType_DELETED, Resource: &podMetaA1})
	_ = store.On(&informer.Event{Type: informer.EventType_DELETED, Resource: &podMetaB})

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

	store := NewStore(fInformer, ResourceLabels{}, nil)

	_ = store.On(&informer.Event{Type: informer.EventType_CREATED, Resource: &service})
	_ = store.On(&informer.Event{Type: informer.EventType_CREATED, Resource: &podMetaA})
	_ = store.On(&informer.Event{Type: informer.EventType_CREATED, Resource: &podMetaA1})
	_ = store.On(&informer.Event{Type: informer.EventType_CREATED, Resource: &podMetaB})

	_ = store.On(&informer.Event{Type: informer.EventType_DELETED, Resource: &podMetaA1})
	_ = store.On(&informer.Event{Type: informer.EventType_DELETED, Resource: &podMetaA})
	_ = store.On(&informer.Event{Type: informer.EventType_DELETED, Resource: &podMetaB})
	_ = store.On(&informer.Event{Type: informer.EventType_DELETED, Resource: &service})

	assert.Equal(t, 0, len(store.containerIDs))
	assert.Equal(t, 0, len(store.containerByPID))
	assert.Equal(t, 0, len(store.namespaces))
	assert.Equal(t, 0, len(store.podsByContainer))
	assert.Equal(t, 0, len(store.containersByOwner))
	assert.Equal(t, 0, len(store.objectMetaByIP))
	assert.Equal(t, 0, len(store.otelServiceInfoByIP))
}

// Fixes a memory leak in the store where the objectMetaByIP map was not cleaned up
func TestMetaByIPEntryRemovedIfIPGroupChanges(t *testing.T) {
	// GIVEN a store with
	store := NewStore(&fakeInformer{}, ResourceLabels{}, nil)
	// WHEN an object is created with several IPs
	_ = store.On(&informer.Event{
		Type: informer.EventType_CREATED,
		Resource: &informer.ObjectMeta{
			Name:      "object_1",
			Namespace: "namespaceA",
			Ips:       []string{"3.1.1.1", "3.2.2.2"},
			Kind:      "Service",
		},
	})
	// THEN the object is only accessible through all its IPs
	assert.Nil(t, store.ObjectMetaByIP("1.2.3.4"))
	om := store.ObjectMetaByIP("3.1.1.1")
	require.NotNil(t, om)
	assert.Equal(t, "object_1", om.Meta.Name)
	assert.Equal(t, []string{"3.1.1.1", "3.2.2.2"}, om.Meta.Ips)
	om = store.ObjectMetaByIP("3.2.2.2")
	require.NotNil(t, om)
	assert.Equal(t, "object_1", om.Meta.Name)
	assert.Equal(t, []string{"3.1.1.1", "3.2.2.2"}, om.Meta.Ips)

	// AND WHEN an object is updated with a different set of IPs
	_ = store.On(&informer.Event{
		Type: informer.EventType_UPDATED,
		Resource: &informer.ObjectMeta{
			Name:      "object_1",
			Namespace: "namespaceA",
			Ips:       []string{"3.2.2.2", "3.3.3.3"},
			Kind:      "Service",
		},
	})
	// THEN the object is only accessible through all its new IPs, but not the old ones
	assert.Nil(t, store.ObjectMetaByIP("3.1.1.1"))
	om = store.ObjectMetaByIP("3.3.3.3")
	require.NotNil(t, om)
	assert.Equal(t, "object_1", om.Meta.Name)
	assert.Equal(t, []string{"3.2.2.2", "3.3.3.3"}, om.Meta.Ips)
	om = store.ObjectMetaByIP("3.2.2.2")
	require.NotNil(t, om)
	assert.Equal(t, "object_1", om.Meta.Name)
	assert.Equal(t, []string{"3.2.2.2", "3.3.3.3"}, om.Meta.Ips)
}

func TestNoLeakOnUpdateOrDeletion(t *testing.T) {
	store := NewStore(&fakeInformer{}, ResourceLabels{}, nil)
	topOwner := &informer.Owner{Name: "foo", Kind: "Deployment"}
	require.NoError(t, store.On(&informer.Event{
		Type: informer.EventType_CREATED,
		Resource: &informer.ObjectMeta{
			Name:      "pod-foo-1",
			Namespace: "namespaceA",
			Ips:       []string{"1.1.1.1", "2.2.2.2"},
			Kind:      "Pod",
			Pod: &informer.PodInfo{
				Owners: []*informer.Owner{topOwner},
				Containers: []*informer.ContainerInfo{
					{Id: "container1-1"},
					{Id: "container1-2"},
				},
			},
		},
	}))
	require.NoError(t, store.On(&informer.Event{
		Type: informer.EventType_CREATED,
		Resource: &informer.ObjectMeta{
			Name:      "pod-foo-2",
			Namespace: "namespaceA",
			Ips:       []string{"4.4.4.4", "5.5.5.5"},
			Kind:      "Pod",
			Pod: &informer.PodInfo{
				Owners: []*informer.Owner{topOwner},
				Containers: []*informer.ContainerInfo{
					{Id: "container2-1"},
					{Id: "container2-2"},
				},
			},
		},
	}))
	require.NoError(t, store.On(&informer.Event{
		Type: informer.EventType_UPDATED,
		Resource: &informer.ObjectMeta{
			Name:      "pod-foo-1",
			Namespace: "namespaceA",
			Ips:       []string{"1.1.1.1", "3.3.3.3"},
			Kind:      "Pod",
			Pod: &informer.PodInfo{
				Owners: []*informer.Owner{topOwner},
				Containers: []*informer.ContainerInfo{
					{Id: "container1-1"},
					{Id: "container1-3"},
				},
			},
		},
	}))
	require.NoError(t, store.On(&informer.Event{
		Type: informer.EventType_DELETED,
		Resource: &informer.ObjectMeta{
			Name:      "pod-foo-1",
			Namespace: "namespaceA",
			Ips:       []string{"1.1.1.1", "3.3.3.3"},
			Kind:      "Pod",
			Pod: &informer.PodInfo{
				Owners: []*informer.Owner{topOwner},
				Containers: []*informer.ContainerInfo{
					{Id: "container1"},
					{Id: "container3"},
				},
			},
		},
	}))
	require.NoError(t, store.On(&informer.Event{
		Type: informer.EventType_DELETED,
		Resource: &informer.ObjectMeta{
			Name:      "foo",
			Namespace: "namespaceA",
		},
	}))
	require.NoError(t, store.On(&informer.Event{
		Type: informer.EventType_DELETED,
		Resource: &informer.ObjectMeta{
			Name:      "pod-foo-2",
			Namespace: "namespaceA",
			Ips:       []string{"4.4.4.4", "5.5.5.5"},
			Kind:      "Pod",
			Pod: &informer.PodInfo{
				Containers: []*informer.ContainerInfo{
					{Id: "container2-1"},
					{Id: "container2-3"},
				},
			},
		},
	}))

	assert.Empty(t, store.objectMetaByQName)
	assert.Empty(t, store.objectMetaByIP)
	assert.Empty(t, store.containerIDs)
	assert.Empty(t, store.namespaces)
	assert.Empty(t, store.namespaces)
	assert.Empty(t, store.podsByContainer)
	assert.Empty(t, store.containersByOwner)
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
