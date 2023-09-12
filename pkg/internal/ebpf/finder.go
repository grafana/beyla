//go:build linux

package ebpf

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"strconv"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/exp/slog"
	"golang.org/x/sys/unix"

	ebpfcommon "github.com/grafana/beyla/pkg/internal/ebpf/common"
	"github.com/grafana/beyla/pkg/internal/ebpf/goruntime"
	"github.com/grafana/beyla/pkg/internal/ebpf/grpc"
	"github.com/grafana/beyla/pkg/internal/ebpf/httpfltr"
	"github.com/grafana/beyla/pkg/internal/ebpf/nethttp"
	"github.com/grafana/beyla/pkg/internal/imetrics"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
)

func pflog() *slog.Logger {
	return slog.With("component", "ebpf.ProcessFinder")
}

// ProcessFinder continuously listens in background for a process matching the
// search criteria as specified to the user.
type ProcessFinder struct {
	Cfg     *ebpfcommon.TracerConfig
	Metrics imetrics.Reporter
	CtxInfo *global.ContextInfo

	discoveredTracers chan *ProcessTracer
	pinPath           string
}

func (pf *ProcessFinder) Start(ctx context.Context) (<-chan *ProcessTracer, error) {
	log := pflog()
	log.Debug("Starting Process Finder")

	pf.discoveredTracers = make(chan *ProcessTracer, pf.CtxInfo.ChannelBufferLen)

	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memory lock: %w", err)
	}
	var err error
	pf.pinPath, err = mountBpfPinPath(pf.Cfg)
	if err != nil {
		return nil, fmt.Errorf("mounting BPF FS in %q: %w", pf.Cfg.BpfBaseDir, err)
	}
	go func() {
		// TODO, for multi-process inspection
		// 1. Keep searching processes matching a given search criteria
		// 2. Instrument these that haven't been instrumented already
		// 3. Do not report service name as part of a shared configuration but as part of the trace

		log.Debug("Finding process in background...")
		pt, err := pf.findAndInstrument(ctx, pf.Metrics)
		if err != nil {
			log.Error("finding instrumentable process", err)
			return
		}
		pf.discoveredTracers <- pt
	}()
	return pf.discoveredTracers, nil
}

func (pf *ProcessFinder) Close() error {
	unmountBpfPinPath(pf.pinPath)
	return nil
}

func mountBpfPinPath(cfg *ebpfcommon.TracerConfig) (string, error) {
	pinPath := path.Join(cfg.BpfBaseDir, strconv.Itoa(os.Getpid()))
	log := pflog().With("path", pinPath)
	log.Debug("mounting BPF map pinning path")
	if _, err := os.Stat(pinPath); err != nil {
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("accessing %s stat: %w", pinPath, err)
		}
		log.Debug("BPF map pinning path does not exist. Creating before mounting")
		if err := os.MkdirAll(pinPath, 0700); err != nil {
			return "", fmt.Errorf("creating directory %s: %w", pinPath, err)
		}
	}

	return pinPath, bpfMount(pinPath)
}

func unmountBpfPinPath(pinPath string) {
	log := slog.With("component", "ebpf.TracerProvider", "path", pinPath)
	log.Debug("context has been canceled. Unmounting BPF map pinning path")
	if err := unix.Unmount(pinPath, unix.MNT_FORCE); err != nil {
		log.Warn("can't unmount pinned root. Try unmounting and removing it manually", err)
		return
	}
	log.Debug("unmounted bpf file system")
	if err := os.RemoveAll(pinPath); err != nil {
		log.Warn("can't remove pinned root. Try removing it manually", err)
	} else {
		log.Debug("removed pin path")
	}
}

func (pf *ProcessFinder) findAndInstrument(ctx context.Context, metrics imetrics.Reporter) (*ProcessTracer, error) {
	var log = logger()

	// Each program is an eBPF source: net/http, grpc...
	programs := []Tracer{
		&nethttp.Tracer{Cfg: pf.Cfg, Metrics: metrics},
		&nethttp.GinTracer{Tracer: nethttp.Tracer{Cfg: pf.Cfg, Metrics: metrics}},
		&grpc.Tracer{Cfg: pf.Cfg, Metrics: metrics},
		&goruntime.Tracer{Cfg: pf.Cfg, Metrics: metrics},
	}

	// merging all the functions from all the programs, in order to do
	// a complete inspection of the target executable
	var allFuncs []string
	if !pf.Cfg.SkipGoSpecificTracers {
		allFuncs = allGoFunctionNames(programs)
	}
	elfInfo, goffsets, err := inspect(ctx, pf.Cfg, allFuncs)
	if err != nil {
		return nil, fmt.Errorf("inspecting offsets: %w", err)
	}

	if goffsets != nil {
		programs = filterNotFoundPrograms(programs, goffsets)
		if len(programs) == 0 {
			return nil, errors.New("no instrumentable function found")
		}
	} else {
		// We are not instrumenting a Go application, we override the programs
		// list with the generic kernel/socket space filters
		programs = []Tracer{&httpfltr.Tracer{Cfg: pf.Cfg, Metrics: metrics}}
	}

	// Instead of the executable file in the disk, we pass the /proc/<pid>/exec
	// to allow loading it from different container/pods in containerized environments
	exe, err := link.OpenExecutable(elfInfo.ProExeLinkPath)
	if err != nil {
		return nil, fmt.Errorf("opening %q executable file: %w", elfInfo.ProExeLinkPath, err)
	}

	if pf.Cfg.SystemWide {
		log.Info("system wide instrumentation")
	}
	return &ProcessTracer{
		programs:            programs,
		ELFInfo:             elfInfo,
		goffsets:            goffsets,
		exe:                 exe,
		pinPath:             pf.pinPath,
		systemWide:          pf.Cfg.SystemWide,
		overrideServiceName: pf.CtxInfo.ServiceName,
	}, nil
}
