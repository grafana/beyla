package meta

import (
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
