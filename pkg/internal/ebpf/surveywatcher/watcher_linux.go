package surveywatcher

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/obi"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type survey_process -target amd64,arm64 Bpf ../../../../bpf/survey_watcher/survey_watcher.c -- -I$OBI_BPF_INCLUDE

const (
	debounceInterval = 250 * time.Millisecond
	recoveryInterval = 5 * time.Second
)

type watcher struct {
	objects BpfObjects
	closers []io.Closer
	state   *State
	ready   chan error
	log     *slog.Logger
	errors  uint64
}

var _ ebpf.UtilityTracer = (*watcher)(nil)

// Start attaches observation before seeding existing sockets, then waits for the
// initial snapshot. Discovery must not start with an uninitialized socket filter.
// All programs and maps are private to Beyla and closed on context cancellation.
func Start(ctx context.Context, cfg *obi.Config, events *ebpfcommon.EBPFEventContext) (*State, error) {
	w := &watcher{state: NewState(), ready: make(chan error, 1), log: slog.With("component", "survey_watcher")}

	if err := ebpf.RunUtilityTracer(ctx, events, w, cfg); err != nil {
		w.close()
		return nil, fmt.Errorf("loading survey socket watcher: %w", err)
	}

	select {
	case err := <-w.ready:
		return w.state, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (w *watcher) LoadSpecs() ([]*ebpfcommon.SpecBundle, error) {
	spec, err := LoadBpf()
	if err != nil {
		return nil, err
	}

	return []*ebpfcommon.SpecBundle{{Spec: spec, Objects: &w.objects}}, nil
}

func (w *watcher) AddCloser(closers ...io.Closer) { w.closers = append(w.closers, closers...) }

func (w *watcher) KProbes() map[string]ebpfcommon.ProbeDesc {
	return map[string]ebpfcommon.ProbeDesc{
		"security_socket_connect": {Start: w.objects.SurveyWatchConnect, Required: true},
		"security_socket_listen":  {Start: w.objects.SurveyWatchListen, Required: true},
	}
}

func (w *watcher) Tracepoints() map[string]ebpfcommon.ProbeDesc {
	return map[string]ebpfcommon.ProbeDesc{
		"sched/sched_process_exit": {Start: w.objects.SurveyWatchExit, Required: true},
	}
}

func (w *watcher) close() {
	for i := len(w.closers) - 1; i >= 0; i-- {
		_ = w.closers[i].Close()
	}

	_ = w.objects.Close()
}

func (w *watcher) seed() error {
	iterator, err := link.AttachIter(link.IterOptions{Program: w.objects.SurveySeedSockets})
	if err != nil {
		return fmt.Errorf("attaching survey task/file iterator: %w", err)
	}

	defer iterator.Close()

	reader, err := iterator.Open()
	if err != nil {
		return fmt.Errorf("opening survey task/file iterator: %w", err)
	}

	defer reader.Close()

	if _, err := io.Copy(io.Discard, reader); err != nil {
		return fmt.Errorf("seeding existing survey sockets: %w", err)
	}

	return nil
}

func (w *watcher) refresh() error {
	snapshot := Snapshot{}
	entries := w.objects.SurveySocketPids.Iterate()

	var key BpfSurveyProcess
	var present uint8

	for entries.Next(&key, &present) {
		snapshot[Process{PID: key.Id.Pid, Namespace: key.Id.Ns, StartTime: key.StartTime}] = struct{}{}
	}

	if err := entries.Err(); err != nil {
		return fmt.Errorf("reading survey socket PIDs: %w", err)
	}

	w.state.publish(snapshot)

	return nil
}

func (w *watcher) Run(ctx context.Context) {
	defer w.close()

	reader, err := ringbuf.NewReader(w.objects.SurveySocketEvents)
	if err != nil {
		w.ready <- fmt.Errorf("opening survey socket notifications: %w", err)
		return
	}

	defer reader.Close()

	if err := w.seed(); err != nil {
		w.ready <- err
		return
	}

	if err := w.refresh(); err != nil {
		w.ready <- err
		return
	}

	notifications := make(chan struct{}, 1)
	readDone := make(chan struct{})

	stop := context.AfterFunc(ctx, func() { _ = reader.Close() })
	defer stop()

	go func() {
		defer close(readDone)
		defer close(notifications)
		for {
			if _, err := reader.Read(); err != nil {
				if !errors.Is(err, ringbuf.ErrClosed) {
					w.log.Warn("survey socket notification reader stopped; using periodic map reads", "error", err)
				}
				return
			}

			select {
			case notifications <- struct{}{}:
			default:
			}
		}
	}()

	w.ready <- nil

	reconcile(ctx, notifications, debounceInterval, recoveryInterval, func() {
		if err := w.refresh(); err != nil {
			w.log.Warn("could not refresh survey socket PIDs", "error", err)
		}
	})

	_ = reader.Close()

	<-readDone
}
