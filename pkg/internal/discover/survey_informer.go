package discover

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/grafana/beyla/v2/pkg/internal/ebpf"
	"github.com/grafana/beyla/v2/pkg/internal/exec"
	"github.com/grafana/beyla/v2/pkg/internal/kube"
	"github.com/grafana/beyla/v2/pkg/pipe/msg"
	"github.com/grafana/beyla/v2/pkg/pipe/swarm"
	"github.com/grafana/beyla/v2/pkg/transform"
)

// SurveyEventGenerator converts the survey discovered process events
// into actionable events to be consumed by the metrics generation
// logic
func SurveyEventGenerator(
	k8sInformer *kube.MetadataProvider,
	input *msg.Queue[[]Event[ebpf.Instrumentable]],
	output *msg.Queue[exec.ProcessEvent],
) swarm.InstanceFunc {
	m := &surveyor{
		log:    slog.With("component", "discover.SurveyEventGenerator"),
		input:  input.Subscribe(),
		output: output,
	}
	return func(ctx context.Context) (swarm.RunFunc, error) {
		if k8sInformer != nil && k8sInformer.IsKubeEnabled() {
			if store, err := k8sInformer.Get(ctx); err != nil {
				return nil, fmt.Errorf("instantiating k8s informer in survey: %w", err)
			} else {
				m.store = store
			}
		}
		return m.run, nil
	}
}

type surveyor struct {
	log    *slog.Logger
	input  <-chan []Event[ebpf.Instrumentable]
	output *msg.Queue[exec.ProcessEvent]
	store  *kube.Store
}

func (m *surveyor) run(_ context.Context) {
	defer m.output.Close()
	m.log.Debug("starting survey event generation node")
	for i := range m.input {
		m.log.Debug("surveying processes", "len", len(i))
		for _, pe := range i {
			m.fetchMetadata(&pe.Obj)
			if pe.Type == EventDeleted {
				m.output.Send(exec.ProcessEvent{Type: exec.ProcessEventTerminated, File: pe.Obj.FileInfo})
			} else {
				m.output.Send(exec.ProcessEvent{Type: exec.ProcessEventCreated, File: pe.Obj.FileInfo})
			}
			m.log.Debug("survey info generation", "pid", pe.Obj.FileInfo.Pid, "ns", pe.Obj.FileInfo.Ns, "cmd", pe.Obj.FileInfo.CmdExePath, "service", pe.Obj.FileInfo.Service.UID)
		}
	}
}

func (m *surveyor) fetchMetadata(i *ebpf.Instrumentable) {
	// default name uses the search criteria name, if any (as set in ExecTyper).
	// Now it will complete some information from the executable information
	i.CopyToServiceAttributes()
	// will try to set some information from kube metadata, if any
	if m.store != nil {
		// we can do this because there is a previous ContainerDBUpdater pipeline stage
		// that has provided this information
		if objectMeta, containerName := m.store.PodContainerByPIDNs(i.FileInfo.Ns); objectMeta != nil {
			transform.AppendKubeMetadata(m.store, &i.FileInfo.Service, objectMeta, "cluster-deleteme", containerName)
		}
	}
}
