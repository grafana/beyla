package discover

import (
	"github.com/mariomac/pipes/pipe"

	"github.com/grafana/beyla/pkg/internal/transform/kube"
)

// ContainerDBUpdaterProvider is a stage in the Process Finder pipeline that will be
// enabled only if Kubernetes decoration is enabled.
// It just updates part of the kubernetes database when a new process is discovered.
func ContainerDBUpdaterProvider(enabled bool, db *kube.Database) pipe.MiddleProvider[[]Event[Instrumentable], []Event[Instrumentable]] {
	return func() (pipe.MiddleFunc[[]Event[Instrumentable], []Event[Instrumentable]], error) {
		if !enabled {
			return pipe.Bypass[[]Event[Instrumentable]](), nil
		}
		return updateLoop(db), nil
	}
}

func updateLoop(db *kube.Database) pipe.MiddleFunc[[]Event[Instrumentable], []Event[Instrumentable]] {
	return func(in <-chan []Event[Instrumentable], out chan<- []Event[Instrumentable]) {
		for instrumentables := range in {
			for i := range instrumentables {
				ev := &instrumentables[i]
				switch ev.Type {
				case EventCreated:
					db.AddProcess(uint32(ev.Obj.FileInfo.Pid))
				case EventDeleted:
					// we don't need to handle process deletion from here, as the Kubernetes informer will
					// remove the process from the database when the Pod that contains it is deleted.
					// However we clean-up the performance related caches, in case we miss pod removal event
					db.CleanProcessCaches(ev.Obj.FileInfo.Ns)
				}
			}
			out <- instrumentables
		}
	}
}
