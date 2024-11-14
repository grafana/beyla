package meta

import (
	"log/slog"

	"k8s.io/client-go/tools/cache"

	"github.com/grafana/beyla/pkg/kubecache/informer"
)

type Informers struct {
	BaseNotifier

	log    *slog.Logger
	config *informersConfig

	// pods and replicaSets cache the different K8s types to custom, smaller object types
	pods     cache.SharedIndexInformer
	nodes    cache.SharedIndexInformer
	services cache.SharedIndexInformer

	waitForSync chan struct{}
}

func (inf *Informers) Subscribe(observer Observer) {
	inf.BaseNotifier.Subscribe(observer)

	// as a "welcome" message, we send the whole kube metadata to the new observer
	for _, pod := range inf.pods.GetStore().List() {
		if err := observer.On(&informer.Event{
			Type:     informer.EventType_CREATED,
			Resource: pod.(*indexableEntity).EncodedMeta,
		}); err != nil {
			inf.log.Debug("error notifying observer. Unsubscribing", "observerID", observer.ID(), "error", err)
			inf.BaseNotifier.Unsubscribe(observer)
			return
		}
	}
	if !inf.config.disableNodes {
		for _, node := range inf.nodes.GetStore().List() {
			if err := observer.On(&informer.Event{
				Type:     informer.EventType_CREATED,
				Resource: node.(*indexableEntity).EncodedMeta,
			}); err != nil {
				inf.log.Debug("error notifying observer. Unsubscribing", "observerID", observer.ID(), "error", err)
				inf.BaseNotifier.Unsubscribe(observer)
				return
			}
		}
	}
	if !inf.config.disableServices {
		for _, service := range inf.services.GetStore().List() {
			if err := observer.On(&informer.Event{
				Type:     informer.EventType_CREATED,
				Resource: service.(*indexableEntity).EncodedMeta,
			}); err != nil {
				inf.log.Debug("error notifying observer. Unsubscribing", "observerID", observer.ID(), "error", err)
				return
			}
		}
	}

	// until the informer waitForSync, we won't send the sync_finished event to remote beyla clients
	<-inf.waitForSync

	// notify the end of synchronization, so the client knows that already has a snapshot
	// of all the existing resources
	if err := observer.On(&informer.Event{
		Type: informer.EventType_SYNC_FINISHED,
	}); err != nil {
		inf.log.Debug("error notifying observer. Unsubscribing", "observerID", observer.ID(), "error", err)
		inf.BaseNotifier.Unsubscribe(observer)
		return
	}
}
