//go:build linux

package nodejs

import (
	_ "embed"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"

	"github.com/grafana/beyla/v2/pkg/beyla"
	"github.com/grafana/beyla/v2/pkg/internal/ebpf"
	"github.com/grafana/beyla/v2/pkg/internal/svc"
)

type NodeInjector struct {
	log *slog.Logger
	cfg *beyla.Config
}

// make sure not to use a variable name (such as that returned by
// os.CreateTemp() to ensure that node does not load the file twice
const fdExtractorPath = "/beyla_fdextractor.js"

func NewNodeInjector(cfg *beyla.Config) *NodeInjector {
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

	if err := os.Chmod(file.Name(), 0444); err != nil {
		cleanup()
		return nil, fmt.Errorf("failed to chmod file")
	}

	return cleanup, nil
}

func (i *NodeInjector) Enabled() bool {
	return i.cfg.Traces.Enabled() || i.cfg.Metrics.Enabled()
}

func (i *NodeInjector) NewExecutable(ie *ebpf.Instrumentable) {
	if ie.Type != svc.InstrumentableNodejs {
		i.log.Debug("not a NodeJS executable")
		return
	}

	i.log.Info("loading NodeJS instrumentation", "pid", ie.FileInfo.Pid)

	root := fmt.Sprintf("/proc/%d/root", ie.FileInfo.Pid)

	cleanup, err := writeFile(_extractorBytes, filepath.Join(root, fdExtractorPath))

	if err != nil {
		i.log.Error("could not write agent file", "error", err)
		return
	}

	defer cleanup()

	if err := i.attachAgent(int(ie.FileInfo.Pid), fdExtractorPath); err != nil {
		i.log.Error("couldn't attach NodeJS injector", "pid", ie.FileInfo.Pid, "error", err)
	}
}

func (i *NodeInjector) attachAgent(pid int, agentFile string) error {
	err := syscall.Kill(pid, syscall.SIGUSR1)

	if err != nil {
		i.log.Error("error enabling node inspector", "err", err)
		return fmt.Errorf("error enabling node inspector")
	}

	return i.inject(pid, agentFile)
}

//go:embed fdextractor.js
var _extractorBytes []byte
