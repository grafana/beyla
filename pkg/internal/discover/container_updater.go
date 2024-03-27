package discover

import (
	"github.com/mariomac/pipes/pkg/node"

	"github.com/grafana/beyla/pkg/transform/kube"
)

// ContainerDBUpdater is a stage in the Process Finder pipeline that will be
// enabled only if Kubernetes decoration is enabled.
// It just updates part of the kubernetes database when a new process is discovered.
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
					// we don't need to handle process deletion from here, as the Kubernetes informer will
					// remove the process from the database when the Pod that contains it is deleted
				}
			}
			out <- instrumentables
		}
	}, nil
}
