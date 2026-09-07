// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package javaagent // import "go.opentelemetry.io/obi/pkg/internal/java"

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/internal/jvmtools/jvm"
	"go.opentelemetry.io/obi/pkg/internal/procs"
	"go.opentelemetry.io/obi/pkg/obi"
)

const (
	ObiJavaAgentFileName      = "obi-java-agent.jar"
	javaAgentEmbedPlaceholder = "OBI_JAVA_AGENT_PLACEHOLDER"
)

//go:embed embedded/obi-java-agent.jar
var embeddedJavaAgentBytes []byte

type JavaInjectError struct {
	Message string
}

func (e *JavaInjectError) Error() string {
	return e.Message
}

type JavaInjector struct {
	log             *slog.Logger
	cfg             *obi.Config
	agentVersion    string
	currentAttachID int64
	mu              sync.Mutex
	newAttacher     func(*slog.Logger, int64, func(int64, func() error) error) jvmAttacher
}

type jvmAttacher interface {
	Init()
	Cleanup(context.Context) error
	Terminate() error
	Attach(context.Context, *procs.ProcessHandle, []string, bool) (io.ReadCloser, error)
}

func NewJavaInjector(cfg *obi.Config) (*JavaInjector, error) {
	log := slog.With("component", "javaagent.Injector")
	if !cfg.Java.Enabled {
		if cfg.AppRuntimeMetricsEnabled() {
			log.Warn("application_runtime is enabled but the Java agent is disabled " +
				"(javaagent.enabled=false): JVM class loading, thread, and CPU metrics will not be collected")
		}
		return nil, nil
	}
	if err := ensureEmbeddedAgent(); err != nil {
		return nil, err
	}

	// A locally built or outdated agent JAR may carry no version marker. Injection still
	// works, we just cannot tell whether an agent already attached to a JVM is the one we
	// would inject.
	agentVersion, err := agentVersionFromJar(embeddedJavaAgentBytes)
	if err != nil {
		log.Debug("cannot read the embedded java agent version, compatibility checks are disabled", "error", err)
	}

	return &JavaInjector{
		cfg:             cfg,
		log:             log,
		agentVersion:    agentVersion,
		currentAttachID: 0,
	}, nil
}

func tempDirPath(root, dir string) (string, bool) {
	if root == "" {
		return "", false
	}

	cleanDir := filepath.Clean(dir)
	if !filepath.IsAbs(cleanDir) {
		return "", false
	}

	fullDir := filepath.Join(root, strings.TrimPrefix(cleanDir, "/"))
	rel, err := filepath.Rel(root, fullDir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}

	return fullDir, true
}

func dirOK(root, dir string) bool {
	fullDir, ok := tempDirPath(root, dir)
	if !ok {
		return false
	}

	info, err := os.Stat(fullDir)
	return err == nil && info.IsDir()
}

func (i *JavaInjector) findTempDir(root, tempDirEnv string) (string, error) {
	if tempDirEnv != "" && dirOK(root, tempDirEnv) {
		return tempDirEnv, nil
	}

	tmpDir := "/tmp"
	if dirOK(root, tmpDir) {
		return tmpDir, nil
	}

	tmpDir = "/var/tmp"
	if dirOK(root, tmpDir) {
		return tmpDir, nil
	}

	return "", errors.New("couldn't find suitable temp directory for injection")
}

func (i *JavaInjector) nextAttachID() int64 {
	i.mu.Lock()
	defer i.mu.Unlock()

	i.currentAttachID++
	return i.currentAttachID
}

func (i *JavaInjector) runIfCurrentAttach(
	attachID int64,
	fn func() error,
) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	if i.currentAttachID != attachID {
		return nil
	}

	return fn()
}

// verifyTargetIdentity fails when Pid no longer refers to the process that was
// queued for injection. Every attach-side operation (entering the target's
// namespaces, dropping to its credentials, writing the agent into its root
// filesystem, and signaling it with SIGQUIT) is destructive to an unrelated
// process, so it must be preceded by this check.
//
// A target whose start time was never captured cannot be checked at all, so it
// is refused rather than injected on the assumption that its PID still holds
// the process discovery saw.
func verifyTargetIdentity(target InjectionTarget) error {
	if target.StartTime == 0 || target.Process == nil {
		return &JavaInjectError{Message: fmt.Sprintf("identity of process %d was not captured, refusing to inject", target.Pid)}
	}

	if err := target.Process.Alive(); err != nil {
		return &JavaInjectError{Message: fmt.Sprintf("cannot confirm identity of process %d: %s", target.Pid, err)}
	}

	return nil
}

func (i *JavaInjector) makeAttacher(attachID int64) jvmAttacher {
	if i.newAttacher != nil {
		return i.newAttacher(i.log, attachID, i.runIfCurrentAttach)
	}
	return jvm.NewJAttacher(i.log, attachID, i.runIfCurrentAttach)
}

// NewExecutable injects the Java agent into target. The attach deadline is
// derived from ctx. Cancellation aborts any active response read and joins the
// attach goroutine before returning.
func (i *JavaInjector) NewExecutable(ctx context.Context, target InjectionTarget) error {
	if target.Type != svc.InstrumentableJava {
		return nil
	}

	// Nothing should signal a JVM once the caller has given up.
	if err := ctx.Err(); err != nil {
		return err
	}

	// Injection is queued by PID and can start long after discovery, so the
	// process must be proven to be the one we discovered before we touch it.
	if err := verifyTargetIdentity(target); err != nil {
		return err
	}

	agentOpts := i.attachOpts(target.RuntimeMetricsEnabled)
	attachID := i.nextAttachID()

	ctx, cancel := context.WithTimeout(ctx, i.cfg.Java.Timeout)
	defer cancel()

	// Channel to receive the result
	type result struct {
		attached bool
		err      error
	}

	resultChan := make(chan result, 1)

	attacher := i.makeAttacher(attachID)

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// We need to call cleanup here even though init may not have
	// happened, to ensure the case when the JVM never responds and
	// we've terminated with a timeout. Cleanup() is idempotent.
	defer func() {
		if err := attacher.Terminate(); err != nil {
			i.log.Warn("error on JVM attach cleanup", "error", err)
		}
	}()

	// Run the attach procedure in a goroutine, so that we can terminate on stuck attach
	go func() {
		defer func() {
			if r := recover(); r != nil {
				resultChan <- result{err: &JavaInjectError{Message: "attach failed"}}
			}
		}()

		ok, jdk8 := i.verifyJVMVersion(ctx, attacher, target.Process, target.Pid)
		if !ok {
			resultChan <- result{err: &JavaInjectError{Message: "unsupported Java version for OpenTelemetry eBPF instrumentation"}}
			return
		}

		var loaded bool
		var err error
		if jdk8 {
			loaded, err = i.jdkAgentAlreadyLoadedHotspot8(ctx, attacher, target.Process, target.Pid)
		} else {
			loaded, err = i.jdkAgentAlreadyLoaded(ctx, attacher, target.Process, target.Pid)
		}

		if err != nil {
			resultChan <- result{err: err}
			return
		}

		if loaded {
			if err := i.verifyLoadedAgentVersion(ctx, attacher, target.Process, target.Pid); err != nil {
				resultChan <- result{err: err}
				return
			}

			i.log.Info("OpenTelemetry eBPF Java Agent already loaded, not reloading")
			resultChan <- result{attached: false}
			return
		}

		i.log.Info("injecting OpenTelemetry eBPF instrumentation for Java process", "pid", target.Pid)

		// The handshake above can block for the whole attach timeout, which is
		// long enough for the PID to be recycled before we write into the
		// target's root filesystem and load the agent.
		if err := verifyTargetIdentity(target); err != nil {
			resultChan <- result{err: err}
			return
		}
		if err := ctx.Err(); err != nil {
			resultChan <- result{err: err}
			return
		}

		root, err := target.Process.Open("root", unix.O_PATH|unix.O_DIRECTORY)
		if err != nil {
			resultChan <- result{err: fmt.Errorf("opening root of process %d: %w", target.Pid, err)}
			return
		}
		rootPath := fmt.Sprintf("/proc/self/fd/%d", root.Fd())
		agentPath, err := i.copyAgent(rootPath, target.Pid, target.TempDirEnv)
		rootCloseErr := root.Close()
		if err != nil {
			i.log.Error("failed to extract java agent", "pid", target.Pid, "error", err)
			resultChan <- result{err: err}
			return
		}
		if rootCloseErr != nil {
			resultChan <- result{err: fmt.Errorf("closing root of process %d: %w", target.Pid, rootCloseErr)}
			return
		}

		if err = i.attachJDKAgent(ctx, attacher, target.Process, target.Pid, agentPath, agentOpts); err != nil {
			i.log.Error("couldn't attach OpenTelemetry eBPF Java Agent", "pid", target.Pid, "path", agentPath, "error", err)
			resultChan <- result{err: err}
			return
		}

		resultChan <- result{attached: true}
	}()

	// Wait for either completion or timeout
	select {
	case result := <-resultChan:
		return result.err
	case <-ctx.Done():
		if err := attacher.Terminate(); err != nil {
			i.log.Warn("error terminating canceled JVM attach", "pid", target.Pid, "error", err)
		}
		// Cancellation closes an active response reader. Join the attach
		// goroutine before returning so the serialized worker owns the full
		// credential and filesystem lifetime, not just the outer call.
		<-resultChan
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			i.log.Warn("java attach timed out", "timeout", i.cfg.Java.Timeout, "pid", target.Pid)
			return &JavaInjectError{Message: "java attach timed out"}
		}
		i.log.Debug("java attach abandoned", "pid", target.Pid, "error", ctx.Err())
		return &JavaInjectError{Message: "java attach canceled"}
	}
}

func ensureEmbeddedAgent() error {
	if len(embeddedJavaAgentBytes) == 0 || strings.TrimSpace(string(embeddedJavaAgentBytes)) == javaAgentEmbedPlaceholder {
		return errors.New("embedded OBI java agent artifact is missing from this build; Java TLS telemetry generation will be disabled")
	}

	return nil
}

func (i *JavaInjector) copyAgent(root string, pid app.PID, tempDirEnv string) (string, error) {
	tempDir, err := i.findTempDir(root, tempDirEnv)
	if err != nil {
		return "", fmt.Errorf("error accessing temp directory: %w", err)
	}

	fullTempDir, ok := tempDirPath(root, tempDir)
	if !ok {
		return "", fmt.Errorf("invalid temp directory for injection: %q", tempDir)
	}

	i.log.Info("found injection directory for process", "pid", pid, "path", fullTempDir)

	agentPathHost := filepath.Join(fullTempDir, ObiJavaAgentFileName)

	source := bytes.NewReader(embeddedJavaAgentBytes)
	target, err := os.CreateTemp(fullTempDir, ObiJavaAgentFileName+".tmp-*")
	if err != nil {
		return "", fmt.Errorf("unable to create target OBI java agent: %w", err)
	}
	tmpTargetPath := target.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpTargetPath)
		}
	}()

	if _, err = target.ReadFrom(source); err != nil {
		return "", fmt.Errorf("error writing java agent to target location: %w", err)
	}

	if err = target.Chmod(0o644); err != nil {
		return "", fmt.Errorf("error setting permissions on target OBI java agent: %w", err)
	}

	if err = target.Close(); err != nil {
		return "", fmt.Errorf("error closing target OBI java agent: %w", err)
	}

	if err = os.Rename(tmpTargetPath, agentPathHost); err != nil {
		return "", fmt.Errorf("unable to move target OBI java agent into place: %w", err)
	}
	cleanup = false

	agentPathContainer := filepath.Join(tempDir, ObiJavaAgentFileName)

	return agentPathContainer, nil
}

func returnCodeLine(line string) (bool, error) {
	if strings.Contains(line, "return code: 0") || strings.Contains(line, "ATTACH_ACK") {
		return true, nil
	} else if strings.Contains(line, "return code:") {
		return true, fmt.Errorf("error executing command for the JVM %s", line)
	}

	return false, nil
}

func (i *JavaInjector) attachOpts(runtimeMetricsEnabled bool) string {
	var opts []string
	if i.cfg.Java.Debug {
		opts = append(opts, "debug=true")
	}
	if i.cfg.Java.DebugInstrumentation {
		opts = append(opts, "debugBB=true")
	}
	if runtimeMetricsEnabled {
		opts = append(opts, "runtimeMetrics=true")
		opts = append(opts, fmt.Sprintf("runtimeMetricsIntervalNanos=%d",
			i.cfg.JVMRuntimeMetrics.SamplingInterval.Nanoseconds()))
	}

	if len(opts) == 0 {
		return ""
	}

	return "=" + strings.Join(opts, ",")
}

func (i *JavaInjector) attachJDKAgent(
	ctx context.Context,
	attacher jvmAttacher,
	process *procs.ProcessHandle,
	pid app.PID,
	path string,
	agentOpts string,
) error {
	attacher.Init()

	defer func() {
		if err := attacher.Cleanup(ctx); err != nil {
			slog.Warn("error on JVM attach cleanup", "error", err)
		}
	}()
	out, err := attacher.Attach(ctx, process, []string{"load", "instrument", "false", path + agentOpts}, false)
	if err != nil {
		i.log.Error("error executing command for the JVM", "pid", pid, "error", err)
		return err
	}

	defer out.Close()

	reader := bufio.NewReader(out)
	buf := bytes.Buffer{}
	for {
		b, err := reader.ReadByte()
		if err != nil {
			if err == io.EOF { // hotspot terminates with EOF
				_, err := returnCodeLine(buf.String())
				if err != nil {
					return err
				}
				break
			}
			return fmt.Errorf("error reading line %w", err)
		}

		buf.WriteByte(b)
		if b == '\n' {
			if end, err := returnCodeLine(buf.String()); end {
				return err
			}

			buf.Reset()
		} else if b == 0 { // j9 terminates with 0
			if end, err := returnCodeLine(buf.String()); end {
				return err
			}
			break
		}
	}

	return nil
}

func (i *JavaInjector) jdkAgentAlreadyLoaded(
	ctx context.Context,
	attacher jvmAttacher,
	process *procs.ProcessHandle,
	pid app.PID,
) (bool, error) {
	attacher.Init()

	defer func() {
		if err := attacher.Cleanup(ctx); err != nil {
			slog.Warn("error on JVM attach cleanup", "error", err)
		}
	}()
	// OpenJ9 doesn't support listing loaded classes
	out, err := attacher.Attach(ctx, process, []string{"jcmd", "VM.class_hierarchy"}, true)
	if err != nil {
		i.log.Error("error executing command for the JVM", "pid", pid, "error", err)
		return false, err
	}

	if out == nil {
		return false, nil
	}
	defer out.Close()

	scanner := bufio.NewScanner(out)
	for scanner.Scan() {
		s := scanner.Text()
		// We check for io.opentelemetry.obi.java.Agent/0x<address>
		if strings.Contains(s, "io.opentelemetry.obi.java.Agent/0x") {
			return true, nil
		}
	}

	if err := scanner.Err(); err != nil {
		i.log.Error("error reading JVM command output", "pid", pid, "error", err)
		return false, err
	}

	return false, nil
}

// Hotspot version 8 doesn't support VM.class_hierarchy, we use GC.class_histogram and look for the class itself
// without the address
func (i *JavaInjector) jdkAgentAlreadyLoadedHotspot8(
	ctx context.Context,
	attacher jvmAttacher,
	process *procs.ProcessHandle,
	pid app.PID,
) (bool, error) {
	attacher.Init()

	defer func() {
		if err := attacher.Cleanup(ctx); err != nil {
			slog.Warn("error on JVM attach cleanup", "error", err)
		}
	}()
	// OpenJ9 doesn't support listing loaded classes
	out, err := attacher.Attach(ctx, process, []string{"jcmd", "GC.class_histogram"}, true)
	if err != nil {
		i.log.Error("error executing command for the JVM", "pid", pid, "error", err)
		return false, err
	}

	if out == nil {
		return false, nil
	}
	defer out.Close()

	scanner := bufio.NewScanner(out)
	for scanner.Scan() {
		s := scanner.Text()
		// We check for io.opentelemetry.obi.java.Agent
		if strings.Contains(s, "io.opentelemetry.obi.java.Agent") {
			return true, nil
		}
	}

	if err := scanner.Err(); err != nil {
		i.log.Error("error reading JVM command output", "pid", pid, "error", err)
		return false, err
	}

	return false, nil
}

// verifyLoadedAgentVersion checks the agent a JVM already runs against the agent OBI would
// inject. A Java agent cannot be unloaded or upgraded in place, so on a mismatch the process
// keeps reporting through an agent this OBI build does not understand until it is restarted.
func (i *JavaInjector) verifyLoadedAgentVersion(
	ctx context.Context,
	attacher jvmAttacher,
	process *procs.ProcessHandle,
	pid app.PID,
) error {
	// nothing to compare against when the embedded agent carries no version marker
	if i.agentVersion == "" {
		return nil
	}

	loadedVersion, err := i.loadedAgentVersion(ctx, attacher, process, pid)
	if err != nil {
		return err
	}

	return i.verifyAgentVersion(pid, loadedVersion)
}

func (i *JavaInjector) verifyAgentVersion(pid app.PID, loadedVersion string) error {
	if loadedVersion == i.agentVersion {
		return nil
	}

	// Agents older than the version marker publish no version at all.
	if loadedVersion == "" {
		loadedVersion = "unknown"
	}

	i.log.Error("the JVM already runs an incompatible OpenTelemetry eBPF Java Agent, restart the process to instrument it with this OBI version",
		"pid", pid, "loadedVersion", loadedVersion, "expectedVersion", i.agentVersion)

	return &JavaInjectError{
		Message: fmt.Sprintf("incompatible OpenTelemetry eBPF Java Agent already loaded: version %s, expected %s", loadedVersion, i.agentVersion),
	}
}

func (i *JavaInjector) loadedAgentVersion(
	ctx context.Context,
	attacher jvmAttacher,
	process *procs.ProcessHandle,
	pid app.PID,
) (string, error) {
	attacher.Init()

	defer func() {
		if err := attacher.Cleanup(ctx); err != nil {
			slog.Warn("error on JVM attach cleanup", "error", err)
		}
	}()
	// OpenJ9 doesn't answer jcmd queries, but we only get here after a probe that uses them
	out, err := attacher.Attach(ctx, process, []string{"jcmd", "VM.system_properties"}, true)
	if err != nil {
		i.log.Error("error executing command for the JVM", "pid", pid, "error", err)
		return "", err
	}

	if out == nil {
		return "", nil
	}
	defer out.Close()

	return javaProperty(out, agentVersionProperty)
}

func (i *JavaInjector) verifyJVMVersion(
	ctx context.Context,
	attacher jvmAttacher,
	process *procs.ProcessHandle,
	pid app.PID,
) (bool, bool) {
	attacher.Init()

	defer func() {
		if err := attacher.Cleanup(ctx); err != nil {
			slog.Warn("error on JVM attach cleanup", "error", err)
		}
	}()
	// OpenJ9 doesn't support VM.version command
	out, err := attacher.Attach(ctx, process, []string{"jcmd", "VM.version"}, true)
	if err != nil {
		i.log.Error("error executing command for the JVM", "pid", pid, "error", err)
		return false, false
	}

	if out == nil {
		return true, false
	}
	defer out.Close()

	scanner := bufio.NewScanner(out)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "JDK ") {
			// JDK 8 is special, failing to properly detect it can cause errors in applications if they are
			// loaded more than once
			return !strings.HasPrefix(line, "JDK 28"), strings.HasPrefix(line, "JDK 8")
		}
	}
	if err := scanner.Err(); err != nil {
		i.log.Error("error reading from scanner", "error", err)
	}

	return false, false
}
