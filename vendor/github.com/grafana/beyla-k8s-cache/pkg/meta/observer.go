package meta

import (
	"sync"

	"github.com/grafana/beyla-k8s-cache/pkg/informer"
)

type Observer interface {
	ID() string
	On(event *informer.Event)
}

type Notifier interface {
	Subscribe(observer Observer)
	Unsubscribe(observer Observer)
	Notify(event *informer.Event)
}

type BaseNotifier struct {
	mutex     sync.RWMutex
	observers map[string]Observer
}

func NewBaseNotifier() BaseNotifier {
	return BaseNotifier{
		observers: make(map[string]Observer),
	}
}

func (i *BaseNotifier) Unsubscribe(observer Observer) {
	i.mutex.Lock()
	delete(i.observers, observer.ID())
	i.mutex.Unlock()
}

func (i *BaseNotifier) Notify(event *informer.Event) {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	for _, observer := range i.observers {
		observer.On(event)
	}
}

func (i *BaseNotifier) Subscribe(observer Observer) {
	i.mutex.Lock()
	i.observers[observer.ID()] = observer
	i.mutex.Unlock()
}
