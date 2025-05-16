package discover

import (
	"context"
	"log/slog"

	"github.com/grafana/beyla/v2/pkg/internal/ebpf"
	"github.com/grafana/beyla/v2/pkg/internal/exec"
	"github.com/grafana/beyla/v2/pkg/pipe/msg"
	"github.com/grafana/beyla/v2/pkg/pipe/swarm"
)

// SurveyEventGenerator converts the survey discovered process events
// into actionable events to be consumed by the metrics generation
// logic
func SurveyEventGenerator(
	input *msg.Queue[[]Event[ebpf.Instrumentable]],
	output *msg.Queue[exec.ProcessEvent],
) swarm.InstanceFunc {
	m := &surveyor{
		log:    slog.With("component", "discover.SurveyEventGenerator"),
		input:  input.Subscribe(),
		output: output,
	}
	return swarm.DirectInstance(m.run)
}

type surveyor struct {
	log    *slog.Logger
	input  <-chan []Event[ebpf.Instrumentable]
	output *msg.Queue[exec.ProcessEvent]
}

func (m *surveyor) run(_ context.Context) {
	defer m.output.Close()
	m.log.Debug("starting survey event generation node")
	for i := range m.input {
		m.log.Debug("surveying processes", "len", len(i))
		for _, pe := range i {
			pe.Obj.CopyToServiceAttributes()
			if pe.Type == EventDeleted {
				m.output.Send(exec.ProcessEvent{Type: exec.ProcessEventTerminated, File: pe.Obj.FileInfo})
			} else {
				m.output.Send(exec.ProcessEvent{Type: exec.ProcessEventSurveyCreated, File: pe.Obj.FileInfo})
			}
			m.log.Debug("survey info generation", "pid", pe.Obj.FileInfo.Pid, "ns", pe.Obj.FileInfo.Ns, "cmd", pe.Obj.FileInfo.CmdExePath, "service", pe.Obj.FileInfo.Service)
		}
	}
}
