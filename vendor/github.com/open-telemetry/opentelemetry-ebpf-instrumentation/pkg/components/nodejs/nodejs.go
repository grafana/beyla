package nodejs

import (
	_ "embed"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/ebpf"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/svc"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/obi"
)

type NodeInjector struct {
	log *slog.Logger
	cfg *obi.Config
}

// make sure not to use a variable name (such as that returned by
// os.CreateTemp() to ensure that node does not load the file twice
const fdExtractorPath = "/beyla_fdextractor.js"

func NewNodeInjector(cfg *obi.Config) *NodeInjector {
	return &NodeInjector{
		cfg: cfg,
		log: slog.With("component", "nodejs.Injector"),
	}
}

func writeFile(data []byte, path string) (cleanup func(), err error) {
	file, err := os.Create(path)
	if err != nil {
		return nil, err
	}

	cleanup = func() {
		file.Close()
		os.Remove(file.Name())
	}

	if _, err := file.Write(data); err != nil {
		cleanup()
		return nil, err
	}

	if err := os.Chmod(file.Name(), 0o444); err != nil {
		cleanup()
		return nil, errors.New("failed to chmod file")
	}

	return cleanup, nil
}

func (i *NodeInjector) Enabled() bool {
	return i.cfg.Traces.Enabled() || i.cfg.TracePrinter.Enabled()
}

func (i *NodeInjector) NewExecutable(ie *ebpf.Instrumentable) {
	if !i.Enabled() {
		i.log.Debug("Node Injector is disabled")
		return
	}

	if ie.Type != svc.InstrumentableNodejs {
		i.log.Debug("not a NodeJS executable")
		return
	}

	i.log.Info("loading NodeJS instrumentation", "pid", ie.FileInfo.Pid)

	root := fmt.Sprintf("/proc/%d/root", ie.FileInfo.Pid)

	cleanup, err := writeFile(_extractorBytes, filepath.Join(root, fdExtractorPath))

	const errorMsg = "trace-context propagation will not work for NodeJS services!"

	if err != nil {
		i.log.Error("could not write agent file", "error", err)
		i.log.Error(errorMsg)
		return
	}

	defer cleanup()

	if err := i.attachAgent(int(ie.FileInfo.Pid), fdExtractorPath); err != nil {
		i.log.Error("couldn't attach NodeJS injector", "pid", ie.FileInfo.Pid, "error", err)
		i.log.Error(errorMsg)
	}
}

func (i *NodeInjector) attachAgent(pid int, agentFile string) error {
	err := syscall.Kill(pid, syscall.SIGUSR1)
	if err != nil {
		i.log.Error("error enabling node inspector", "err", err)
		return errors.New("error enabling node inspector")
	}

	return i.inject(pid, agentFile)
}

//go:embed fdextractor.js
var _extractorBytes []byte
