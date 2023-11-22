package discover

import (
	"github.com/mariomac/pipes/pkg/node"

	"github.com/grafana/beyla/pkg/internal/kube"
)

type ContainerDBUpdater struct {
	DB *kube.Database
}

func ContainerDBUpdaterProvider(cn *ContainerDBUpdater) (node.MiddleFunc[[]Event[Instrumentable], []Event[Instrumentable]], error) {
	return func(in <-chan []Event[Instrumentable], out chan<- []Event[Instrumentable]) {
		for instrumentables := range in {
			for i := range instrumentables {
				ev := &instrumentables[i]
				switch ev.Type {
				case EventCreated:
					cn.DB.AddProcess(uint32(ev.Obj.FileInfo.Pid))
				case EventDeleted:
					// we don't need to handle this from here, as the Kubernetes informer will clean up the
					// database
				}
			}
			out <- instrumentables
		}
	}, nil
}
