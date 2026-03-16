// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejs // import "go.opentelemetry.io/obi/pkg/internal/nodejs"

import (
	"debug/elf"
	_ "embed"
	"fmt"
	"log/slog"
	"net"
	"syscall"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/ebpf"
	"go.opentelemetry.io/obi/pkg/obi"
)

type NodeInjector struct {
	log *slog.Logger
	cfg *obi.Config
}

func NewNodeInjector(cfg *obi.Config) *NodeInjector {
	return &NodeInjector{
		cfg: cfg,
		log: slog.With("component", "nodejs.Injector"),
	}
}

func (i *NodeInjector) Enabled() bool {
	return i.cfg.NodeJS.Enabled && (i.cfg.Traces.Enabled() || i.cfg.TracePrinter.Enabled())
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

	if err := i.attachAgent(int(ie.FileInfo.Pid), ie.FileInfo.ELF); err != nil {
		i.log.Error("couldn't attach NodeJS injector", "pid", ie.FileInfo.Pid, "error", err)
		i.log.Error("trace-context propagation will not work for NodeJS services!")
	}
}

func (i *NodeInjector) attachAgent(pid int, elfFile *elf.File) error {
	return withNetNS(pid, func() error {
		return i.injectFile(pid, elfFile)
	})
}

// injectFile attempts to connect to the Node.js inspector and inject the
// agent. It first tries to connect directly (in case the inspector is already
// open, e.g. via --inspect flag), validating with /json/version. If that fails,
// it checks for a custom SIGUSR1 handler and either sends SIGUSR1 to open the
// inspector or bails out.
func (i *NodeInjector) injectFile(pid int, elfFile *elf.File) error {
	conn, err := connect("127.0.0.1", 9229)
	if err == nil {
		// Validate this is actually a Node.js inspector, not some other
		// service that happens to listen on port 9229.
		if i.isNodeInspector(conn) {
			i.log.Debug("Node.js inspector already open, injecting directly", "pid", pid)
			return i.injectViaConn(conn)
		}
		conn.Close()
	}

	if elfFile != nil && hasUserSIGUSR1Handler(pid, elfFile) {
		i.log.Warn("Node.js process has a custom SIGUSR1 handler, skipping agent injection. "+
			"Node.js trace correlation will not work", "pid", pid)
		return nil
	}

	if err := syscall.Kill(pid, syscall.SIGUSR1); err != nil {
		return fmt.Errorf("error enabling node inspector: %w", err)
	}

	conn, err = connectWait("127.0.0.1", 9229, 5*time.Second, 200*time.Millisecond)
	if err != nil {
		return fmt.Errorf("failed to connect to inspector after SIGUSR1: %w", err)
	}

	return i.injectViaConn(conn)
}

// isNodeInspector validates that a connection to port 9229 is actually a
// Node.js inspector by requesting /json/version and checking for a valid
// JSON response.
func (i *NodeInjector) isNodeInspector(conn net.Conn) bool {
	resp, err := httpGet(conn, "/json/version")
	if err != nil {
		return false
	}

	// The Node.js inspector responds with a JSON object containing
	// "Browser" and "Protocol-Version" fields.
	return len(resp) > 0 && resp[0] == '{'
}

//go:embed fdextractor.js
var _extractorBytes []byte
