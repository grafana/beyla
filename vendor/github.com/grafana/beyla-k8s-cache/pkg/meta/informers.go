package meta

import (
	"log/slog"
	"sync"

	"k8s.io/client-go/tools/cache"

	"github.com/grafana/beyla-k8s-cache/pkg/informer"
)

type Informers struct {
	log *slog.Logger
	// pods and replicaSets cache the different K8s types to custom, smaller object types
	pods     cache.SharedIndexInformer
	nodes    cache.SharedIndexInformer
	services cache.SharedIndexInformer

	// notifier implementation
	mutex     sync.RWMutex
	observers map[string]Observer
}

func (i *Informers) Subscribe(observer Observer) {
	i.mutex.Lock()
	i.observers[observer.ID()] = observer
	i.mutex.Unlock()

	// as a "welcome" message, we send the whole kube metadata to the new observer
	for _, pod := range i.pods.GetStore().List() {
		observer.On(&informer.Event{
			Type:     informer.EventType_CREATED,
			Resource: &informer.Event_Pod{Pod: pod.(*indexableEntity).Pod},
		})
	}
	for _, node := range i.nodes.GetStore().List() {
		observer.On(&informer.Event{
			Type:     informer.EventType_CREATED,
			Resource: &informer.Event_IpInfo{IpInfo: node.(*indexableEntity).IPInfo},
		})
	}
	for _, service := range i.services.GetStore().List() {
		observer.On(&informer.Event{
			Type:     informer.EventType_CREATED,
			Resource: &informer.Event_IpInfo{IpInfo: service.(*indexableEntity).IPInfo},
		})
	}
}

func (i *Informers) Unsubscribe(observer Observer) {
	i.mutex.Lock()
	delete(i.observers, observer.ID())
	i.mutex.Unlock()
}

func (i *Informers) Notify(event *informer.Event) {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	for _, observer := range i.observers {
		observer.On(event)
	}
}
