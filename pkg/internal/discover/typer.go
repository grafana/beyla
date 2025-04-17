package discover

import (
	"context"
	"log/slog"

	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/grafana/beyla/v2/pkg/beyla"
	"github.com/grafana/beyla/v2/pkg/internal/ebpf"
	"github.com/grafana/beyla/v2/pkg/internal/exec"
	"github.com/grafana/beyla/v2/pkg/internal/imetrics"
	"github.com/grafana/beyla/v2/pkg/internal/kube"
	"github.com/grafana/beyla/v2/pkg/internal/svc"
	"github.com/grafana/beyla/v2/pkg/pipe/msg"
	"github.com/grafana/beyla/v2/pkg/pipe/swarm"
)

var instrumentableCache, _ = lru.New[uint64, InstrumentedExecutable](100)

type InstrumentedExecutable struct {
	Type svc.InstrumentableType
}

// ExecTyperProvider classifies the discovered executables according to the
// executable type (Go, generic...), and filters these executables
// that are not instrumentable.
func ExecTyperProvider(
	cfg *beyla.Config,
	metrics imetrics.Reporter,
	k8sInformer *kube.MetadataProvider,
	input *msg.Queue[[]Event[ProcessMatch]],
	output *msg.Queue[[]Event[ebpf.Instrumentable]],
) swarm.InstanceFunc {
	t := typer{
		cfg:         cfg,
		metrics:     metrics,
		k8sInformer: k8sInformer,
		log:         slog.With("component", "discover.ExecTyper"),
		currentPids: map[int32]*exec.FileInfo{},
	}
	return func(_ context.Context) (swarm.RunFunc, error) {
		in := input.Subscribe()
		return func(_ context.Context) {
			defer output.Close()
			for i := range in {
				output.Send(t.FilterClassify(i))
			}
		}, nil
	}
}

type typer struct {
	cfg         *beyla.Config
	metrics     imetrics.Reporter
	k8sInformer *kube.MetadataProvider
	log         *slog.Logger
	currentPids map[int32]*exec.FileInfo
}

// FilterClassify returns the Instrumentable types for each received ProcessMatch,
// and filters out the processes that can't be instrumented (e.g. because of the lack
// of instrumentation points)
func (t *typer) FilterClassify(evs []Event[ProcessMatch]) []Event[ebpf.Instrumentable] {
	var out []Event[ebpf.Instrumentable]

	elfs := make([]*exec.FileInfo, 0, len(evs))
	// Update first the PID map so we use only the parent processes
	// in case of multiple matches
	for i := range evs {
		ev := &evs[i]
		switch evs[i].Type {
		case EventCreated:
			svcID := svc.Attrs{
				UID: svc.UID{
					Name:      ev.Obj.Criteria.Name,
					Namespace: ev.Obj.Criteria.Namespace,
				},
				ProcPID: ev.Obj.Process.Pid,
			}
			if elfFile, err := exec.FindExecELF(ev.Obj.Process, svcID, t.k8sInformer.IsKubeEnabled()); err != nil {
				t.log.Warn("error finding process ELF. Ignoring", "error", err)
			} else {
				t.currentPids[ev.Obj.Process.Pid] = elfFile
				elfs = append(elfs, elfFile)
			}
		case EventDeleted, EventInstanceDeleted:
			if fInfo, ok := t.currentPids[ev.Obj.Process.Pid]; ok {
				delete(t.currentPids, ev.Obj.Process.Pid)
				out = append(out, Event[ebpf.Instrumentable]{
					Type: EventDeleted,
					Obj:  ebpf.Instrumentable{FileInfo: fInfo},
				})
			}
		}
	}

	for i := range elfs {
		inst := t.asInstrumentable(elfs[i])
		t.log.Debug(
			"found an instrumentable process",
			"type", inst.Type.String(),
			"exec", inst.FileInfo.CmdExePath, "pid", inst.FileInfo.Pid)
		out = append(out, Event[ebpf.Instrumentable]{Type: EventCreated, Obj: inst})
	}
	return out
}

// asInstrumentable classifies the type of executable (Go, generic...) and,
// in case of belonging to a forked process, returns its parent.
func (t *typer) asInstrumentable(execElf *exec.FileInfo) ebpf.Instrumentable {
	log := t.log.With("pid", execElf.Pid, "comm", execElf.CmdExePath)
	if ic, ok := instrumentableCache.Get(execElf.Ino); ok {
		log.Debug("new instance of existing executable", "type", ic.Type)
		return ebpf.Instrumentable{Type: ic.Type, FileInfo: execElf}
	}

	log.Debug("getting instrumentable information")

	// select the parent (or grandparent) of the executable, if any
	var child []uint32
	parent, ok := t.currentPids[execElf.Ppid]
	for ok && execElf.Ppid != execElf.Pid &&
		// we will ignore parent processes that are not the same executable. For example,
		// to avoid wrongly instrumenting process launcher such as systemd or containerd-shimd
		// when they launch an instrumentable service
		execElf.CmdExePath == parent.CmdExePath {

		log.Debug("replacing executable by its parent", "ppid", execElf.Ppid)
		child = append(child, uint32(execElf.Pid))
		execElf = parent
		parent, ok = t.currentPids[parent.Ppid]
	}

	detectedType := exec.FindProcLanguage(execElf.Pid)

	log.Debug("instrumented", "comm", execElf.CmdExePath, "pid", execElf.Pid,
		"child", child, "language", detectedType.String())

	instrumentableCache.Add(execElf.Ino, InstrumentedExecutable{Type: detectedType})
	return ebpf.Instrumentable{Type: detectedType, FileInfo: execElf, ChildPids: child}
}
