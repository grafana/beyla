package discover

import (
	"context"
	"fmt"
	"log/slog"

	obiDiscover "go.opentelemetry.io/obi/pkg/appolly/discover"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/ebpf"
	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/transform"
)

// SurveyEventGenerator converts the survey discovered process events
// into actionable events to be consumed by the metrics generation
// logic
func SurveyEventGenerator(
	cfg *transform.KubernetesDecorator,
	k8sInformer *kube.MetadataProvider,
	input *msg.Queue[[]obiDiscover.Event[ebpf.Instrumentable]],
	output *msg.Queue[exec.ProcessEvent],
) swarm.InstanceFunc {
	m := &surveyor{
		log:    slog.With("component", "discover.SurveyEventGenerator"),
		input:  input.Subscribe(msg.SubscriberName("surveyEventInput")),
		output: output,
	}
	return func(ctx context.Context) (swarm.RunFunc, error) {
		if k8sInformer != nil && k8sInformer.IsKubeEnabled() {
			if store, err := k8sInformer.Get(ctx); err != nil {
				return nil, fmt.Errorf("instantiating k8s informer in survey: %w", err)
			} else {
				m.store = store
			}
			m.clusterName = transform.KubeClusterName(ctx, cfg, k8sInformer)

		}
		return m.run, nil
	}
}

type surveyor struct {
	log         *slog.Logger
	input       <-chan []obiDiscover.Event[ebpf.Instrumentable]
	output      *msg.Queue[exec.ProcessEvent]
	store       *kube.Store
	clusterName string
}

func (m *surveyor) run(_ context.Context) {
	defer m.output.Close()
	m.log.Debug("starting survey event generation node")
	for i := range m.input {
		m.log.Debug("surveying processes", "len", len(i))
		for _, pe := range i {
			m.fetchMetadata(&pe.Obj)
			if pe.Type == obiDiscover.EventDeleted {
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
			transform.AppendKubeMetadata(m.store, &i.FileInfo.Service, objectMeta, m.clusterName, containerName)
		}
	}
}
