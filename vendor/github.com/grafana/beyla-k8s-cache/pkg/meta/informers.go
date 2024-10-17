package meta

import (
	"log/slog"

	"k8s.io/client-go/tools/cache"

	"github.com/grafana/beyla-k8s-cache/pkg/informer"
)

type Informers struct {
	log *slog.Logger
	// pods and replicaSets cache the different K8s types to custom, smaller object types
	pods     cache.SharedIndexInformer
	nodes    cache.SharedIndexInformer
	services cache.SharedIndexInformer

	BaseNotifier
}

func (i *Informers) Subscribe(observer Observer) {
	i.BaseNotifier.Subscribe(observer)

	// as a "welcome" message, we send the whole kube metadata to the new observer
	for _, pod := range i.pods.GetStore().List() {
		observer.On(&informer.Event{
			Type:     informer.EventType_CREATED,
			Resource: pod.(*indexableEntity).EncodedMeta,
		})
	}
	for _, node := range i.nodes.GetStore().List() {
		observer.On(&informer.Event{
			Type:     informer.EventType_CREATED,
			Resource: node.(*indexableEntity).EncodedMeta,
		})
	}
	for _, service := range i.services.GetStore().List() {
		observer.On(&informer.Event{
			Type:     informer.EventType_CREATED,
			Resource: service.(*indexableEntity).EncodedMeta,
		})
	}
}
