// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package meta

import (
	"log/slog"
	"sync"

	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
)

// Observer can be subscribed to a Notifier to receive events
type Observer interface {
	ID() string
	// On new event. If the observer returns an error, it will be assumed as invalid and will be automatically
	// unsubscribed from the notifier. The Observer implementation should free its occupied resources and finish
	// its execution
	On(event *informer.Event) error
}

// Notifier can get subscriptions from Observers
type Notifier interface {
	Subscribe(observer Observer)
	Unsubscribe(observer Observer)
	Notify(event *informer.Event)
}

type BaseNotifier struct {
	log       *slog.Logger
	mutex     sync.RWMutex
	observers map[string]Observer
}

func NewBaseNotifier(log *slog.Logger) BaseNotifier {
	return BaseNotifier{
		log:       log,
		observers: make(map[string]Observer),
	}
}

func (i *BaseNotifier) Unsubscribe(observer Observer) {
	i.mutex.Lock()
	delete(i.observers, observer.ID())
	i.mutex.Unlock()
}

func (i *BaseNotifier) Notify(event *informer.Event) {
	if remove := i.notifyAll(event); len(remove) > 0 {
		i.mutex.Lock()
		defer i.mutex.Unlock()
		for _, id := range remove {
			delete(i.observers, id)
		}
	}
}

func (i *BaseNotifier) notifyAll(event *informer.Event) []string {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	var remove []string
	for id, observer := range i.observers {
		if err := observer.On(event); err != nil {
			i.log.Debug("observer failed. Unsubscribing it", "observer", id, "error", err)
			remove = append(remove, id)
		}
	}
	return remove
}

func (i *BaseNotifier) Subscribe(observer Observer) {
	i.mutex.Lock()
	i.observers[observer.ID()] = observer
	i.mutex.Unlock()
}
