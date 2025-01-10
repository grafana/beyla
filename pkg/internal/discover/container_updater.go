package discover

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/mariomac/pipes/pipe"

	"github.com/grafana/beyla/pkg/internal/ebpf"
	"github.com/grafana/beyla/pkg/internal/kube"
)

// ContainerDBUpdaterProvider is a stage in the Process Finder pipeline that will be
// enabled only if Kubernetes decoration is enabled.
// It just updates part of the kubernetes database when a new process is discovered.
func ContainerDBUpdaterProvider(ctx context.Context, meta kubeMetadataProvider) pipe.MiddleProvider[[]Event[ebpf.Instrumentable], []Event[ebpf.Instrumentable]] {
	return func() (pipe.MiddleFunc[[]Event[ebpf.Instrumentable], []Event[ebpf.Instrumentable]], error) {
		if !meta.IsKubeEnabled() {
			return pipe.Bypass[[]Event[ebpf.Instrumentable]](), nil
		}
		store, err := meta.Get(ctx)
		if err != nil {
			return nil, fmt.Errorf("instantiating ContainerDBUpdater: %w", err)
		}
		return updateLoop(store), nil
	}
}

func updateLoop(db *kube.Store) pipe.MiddleFunc[[]Event[ebpf.Instrumentable], []Event[ebpf.Instrumentable]] {
	log := slog.With("component", "ContainerDBUpdater")
	return func(in <-chan []Event[ebpf.Instrumentable], out chan<- []Event[ebpf.Instrumentable]) {
		for instrumentables := range in {
			for i := range instrumentables {
				ev := &instrumentables[i]
				switch ev.Type {
				case EventCreated:
					log.Debug("adding process", "pid", ev.Obj.FileInfo.Pid)
					db.AddProcess(uint32(ev.Obj.FileInfo.Pid))
				case EventDeleted:
					// we don't need to handle process deletion from here, as the Kubernetes informer will
					// remove the process from the database when the Pod that contains it is deleted.
				}
			}
			out <- instrumentables
		}
	}
}
