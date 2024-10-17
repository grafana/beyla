package meta

import (
	"log/slog"

	"k8s.io/client-go/tools/cache"

	"github.com/grafana/beyla-k8s-cache/pkg/informer"
)

type Informers struct {
	BaseNotifier

	log    *slog.Logger
	config *informersConfig

	// pods and replicaSets cache the different K8s types to custom, smaller object types
	pods     cache.SharedIndexInformer
	nodes    cache.SharedIndexInformer
	services cache.SharedIndexInformer
}

func (inf *Informers) Subscribe(observer Observer) {
	inf.BaseNotifier.Subscribe(observer)

	// as a "welcome" message, we send the whole kube metadata to the new observer
	for _, pod := range inf.pods.GetStore().List() {
		observer.On(&informer.Event{
			Type:     informer.EventType_CREATED,
			Resource: pod.(*indexableEntity).EncodedMeta,
		})
	}
	if !inf.config.disableNodes {
		for _, node := range inf.nodes.GetStore().List() {
			observer.On(&informer.Event{
				Type:     informer.EventType_CREATED,
				Resource: node.(*indexableEntity).EncodedMeta,
			})
		}
	}
	if !inf.config.disableServices {
		for _, service := range inf.services.GetStore().List() {
			observer.On(&informer.Event{
				Type:     informer.EventType_CREATED,
				Resource: service.(*indexableEntity).EncodedMeta,
			})
		}
	}
}
