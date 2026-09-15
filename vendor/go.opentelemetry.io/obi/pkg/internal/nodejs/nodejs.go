// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejs // import "go.opentelemetry.io/obi/pkg/internal/nodejs"

import (
	"context"
	"debug/elf"
	_ "embed"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/netns"
	"go.opentelemetry.io/obi/pkg/obi"
)

type NodeInjector struct {
	log *slog.Logger
	cfg *obi.Config
}

func NewNodeInjector(cfg *obi.Config) *NodeInjector {
	log := slog.With("component", "nodejs.Injector")

	if !cfg.NodeJS.Enabled && cfg.AppRuntimeMetricsEnabled() {
		log.Warn("application_runtime is enabled but the Node.js injector is disabled " +
			"(nodejs.enabled=false): Node.js runtime metrics will not be collected")
	}

	return &NodeInjector{
		cfg: cfg,
		log: log,
	}
}

// Enabled reports whether the agent should be injected: the injected script
// is both the trace-context propagation vehicle and the only source of the
// nodejs.eventloop.* runtime metrics, so either consumer turns it on —
// unless nodejs.enabled, the global opt-out, is set to false.
func (i *NodeInjector) Enabled() bool {
	return i.cfg.NodeJS.Enabled &&
		(i.cfg.Traces.Enabled() || i.cfg.TracePrinter.Enabled() || i.cfg.AppRuntimeMetricsEnabled())
}

// injectionTrigger names what turned the injection on, so the logs explain a
// metrics-only injection.
func (i *NodeInjector) injectionTrigger() string {
	if i.cfg.Traces.Enabled() || i.cfg.TracePrinter.Enabled() {
		return "traces"
	}
	return "runtime metrics"
}

// Accepts reports whether this instrumentable is a Node.js process the
// injector is configured to handle. Callers that defer the injection check it
// before taking a queue slot.
func (i *NodeInjector) Accepts(ie *ebpf.Instrumentable) bool {
	if !i.Enabled() {
		i.log.Debug("Node Injector is disabled")
		return false
	}

	if ie.Type != svc.InstrumentableNodejs {
		i.log.Debug("not a NodeJS executable")
		return false
	}

	return true
}

// Inject injects into an accepted target.
//
// The executable and the signal go through the target's pinned process handle,
// so a PID the kernel recycled between discovery and here cannot be signaled
// in the original's place. The rest still works from the numeric PID: the gates
// read /proc, and the inspector conversation enters a network namespace, so a
// replacement can be the process examined and — where an inspector is already
// listening, which needs no signal — the one injected.
func (i *NodeInjector) Inject(ctx context.Context, target InjectionTarget) {
	pid := target.Pid
	i.log.Debug("loading NodeJS instrumentation", "pid", pid, "trigger", i.injectionTrigger())

	if err := target.Process.Alive(); err != nil {
		i.log.Debug("NodeJS process is gone, skipping injection", "pid", pid, "error", err)
		return
	}

	exe, err := target.Process.Open("exe", os.O_RDONLY)
	if err != nil {
		i.log.Debug("couldn't open the NodeJS executable, skipping injection", "pid", pid, "error", err)
		return
	}
	defer exe.Close()

	elfFile, err := elf.NewFile(exe)
	if err != nil {
		i.log.Debug("couldn't read the NodeJS executable, skipping injection", "pid", pid, "error", err)
		return
	}
	defer elfFile.Close()

	if err := i.attachAgent(ctx, target, elfFile); err != nil {
		i.log.Error("couldn't attach NodeJS injector", "pid", pid, "error", err)
		i.log.Error("trace-context propagation and nodejs runtime metrics will not work for NodeJS services!")
	}
}

// attachAgent injects the agent through the Node.js inspector, opening it with
// SIGUSR1 when it is not already listening.
//
// Only the inspector conversation runs inside the target's network namespace.
// Deciding whether the signal is safe to send reads /proc and the application's
// files, needs no namespace of its own, and can wait on the runtime for as long
// as dispositionWait.
func (i *NodeInjector) attachAgent(ctx context.Context, target InjectionTarget, elfFile *elf.File) error {
	pid := int(target.Pid)

	injected, err := i.injectViaOpenInspector(pid)
	if injected || err != nil {
		return err
	}

	reason := sigusr1Refusal(ctx, pid, elfFile)

	// Shutdown is not a refusal: the gates were abandoned rather than answered,
	// so nothing was concluded about this process and nothing is reported.
	if err := ctx.Err(); err != nil {
		return nil
	}

	if reason != "" {
		i.log.Warn("not sending SIGUSR1 to open the Node.js inspector, skipping agent injection. "+
			"Node.js trace correlation will not work", "pid", pid, "reason", reason)
		return nil
	}

	if err := sendSIGUSR1(target.Process); err != nil {
		return fmt.Errorf("error enabling node inspector: %w", err)
	}

	return netns.WithNetNS(pid, func() error {
		conn, err := connectWait("127.0.0.1", 9229, 5*time.Second, 200*time.Millisecond)
		if err != nil {
			return fmt.Errorf("failed to connect to inspector after SIGUSR1: %w", err)
		}

		return i.injectViaConn(conn)
	})
}

// injectViaOpenInspector handles the case of an inspector already listening,
// as it is under --inspect, where no signal is needed at all. The first return
// value reports whether the injection was carried out.
func (i *NodeInjector) injectViaOpenInspector(pid int) (bool, error) {
	injected := false

	err := netns.WithNetNS(pid, func() error {
		conn, err := connect("127.0.0.1", 9229)
		if err != nil {
			return nil
		}

		// Validate this is actually a Node.js inspector, not some other
		// service that happens to listen on port 9229.
		if !i.isNodeInspector(conn) {
			conn.Close()
			return nil
		}

		i.log.Debug("Node.js inspector already open, injecting directly", "pid", pid)
		injected = true
		return i.injectViaConn(conn)
	})

	return injected, err
}

const (
	refusalSignalIsFatal           = "SIGUSR1 is neither caught nor ignored, so it would terminate the process"
	refusalDispositionUnknown      = "the process caught and ignored signal sets could not be read"
	refusalHandlerFound            = "process has a custom SIGUSR1 handler"
	refusalSourceReferencesSIGUSR1 = "process source files reference SIGUSR1"
)

// dispositionWait bounds how long to wait for the runtime to install its own
// SIGUSR1 handler. Node installs it about 11ms after exec, and until then
// SIGUSR1 terminates the process, so a process discovered at exec time is
// otherwise refused for a condition that clears on its own.
const (
	dispositionWait     = 500 * time.Millisecond
	dispositionInterval = 10 * time.Millisecond
)

// sigusr1Refusal reports why the signal is withheld, or an empty reason when
// it is safe to send. Discovery has already established that this is a Node.js
// runtime; what is left is whether the signal would terminate it, and whether
// the application has taken the signal over.
func sigusr1Refusal(ctx context.Context, pid int, elfFile *elf.File) string {
	syms := readNodeSymbols(elfFile)

	switch awaitSignalDisposition(ctx, pid) {
	case signalDispositionFatal:
		return refusalSignalIsFatal
	case signalDispositionUnknown:
		return refusalDispositionUnknown
	case signalDispositionHandled:
	}

	switch hasUserSIGUSR1Handler(pid, elfFile, syms) {
	case signalCheckFound:
		return refusalHandlerFound
	case signalCheckFailed:
		// The runtime carries no readable libuv signal tree, so the
		// application's own files are the only remaining evidence.
		if sourceHasSIGUSR1Reference(pid) {
			return refusalSourceReferencesSIGUSR1
		}
	case signalCheckNotFound:
	}

	return ""
}

// awaitSignalDisposition waits out the window after exec in which a runtime
// has not yet installed its own SIGUSR1 handler, so a process discovered at
// exec time is not refused for a condition that clears on its own.
//
// Cancellation reports Unknown rather than the last reading: shutdown says
// nothing about the target, and claiming the signal would have killed it would
// log a conclusion never reached.
func awaitSignalDisposition(ctx context.Context, pid int) signalDisposition {
	deadline := time.Now().Add(dispositionWait)

	for {
		disposition := sigusr1Disposition(pid)
		if disposition != signalDispositionFatal || time.Now().After(deadline) {
			return disposition
		}

		select {
		case <-ctx.Done():
			return signalDispositionUnknown
		case <-time.After(dispositionInterval):
		}
	}
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
var _extractorCode string

//go:embed spanbridge.js
var _spanBridgeCode string

// Substituted at injection time so each injection installs only the
// machinery its configuration asks for (see the OBI_RT_ENABLED and
// OBI_TRACES_ENABLED comments in fdextractor.js).
const (
	rtEnabledPlaceholder     = "= false; /*OBI_RT_ENABLED*/"
	rtEnabledOn              = "= true; /*OBI_RT_ENABLED*/"
	tracesEnabledPlaceholder = "= false; /*OBI_TRACES_ENABLED*/"
	tracesEnabledOn          = "= true; /*OBI_TRACES_ENABLED*/"
)

// agentCode returns the extractor script with the RT gate substituted from
// the same predicate that sets the nodejs_runtime_metrics_enabled BPF
// constant, so the agent and the eBPF side cannot disagree. When manual
// spans are enabled the span bridge is appended as a second script: both are
// self-contained IIFEs, joined with an explicit ';' so the bridge's leading
// '(' is not parsed as a call of the extractor IIFE's return value.
func (i *NodeInjector) agentCode() string {
	code := _extractorCode
	if i.cfg.AppRuntimeMetricsEnabled() {
		code = strings.Replace(code, rtEnabledPlaceholder, rtEnabledOn, 1)
	}
	if i.cfg.Traces.Enabled() || i.cfg.TracePrinter.Enabled() {
		code = strings.Replace(code, tracesEnabledPlaceholder, tracesEnabledOn, 1)
	}
	if i.cfg.NodeJS.ManualSpans {
		code += ";\n" + _spanBridgeCode
	}
	return code
}
