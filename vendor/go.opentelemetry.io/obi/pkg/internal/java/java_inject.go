// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package javaagent // import "go.opentelemetry.io/obi/pkg/internal/java"

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/grafana/jvmtools/jvm"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/obi"
)

const ObiJavaAgentFileName = "obi-java-agent.jar"

type JavaInjectError struct {
	Message string
}

func (e *JavaInjectError) Error() string {
	return e.Message
}

type JavaInjector struct {
	log       *slog.Logger
	cfg       *obi.Config
	agentPath string
}

func NewJavaInjector(cfg *obi.Config) (*JavaInjector, error) {
	if !cfg.Java.Enabled {
		return nil, nil
	}

	agentPath, err := getLocalAgentPath()
	if err != nil {
		return nil, fmt.Errorf("unable to find the local OBI java agent jar, error %w", err)
	}

	if _, err := os.Stat(agentPath); err != nil {
		return nil, fmt.Errorf("OBI java agent jar not found in build, error %w", err)
	}

	return &JavaInjector{
		cfg:       cfg,
		log:       slog.With("component", "javaagent.Injector"),
		agentPath: agentPath,
	}, nil
}

func dirOK(root, dir string) bool {
	fullDir := filepath.Join(root, dir)

	info, err := os.Stat(fullDir)
	return err == nil && info.IsDir()
}

func (i *JavaInjector) findTempDir(root string, ie *ebpf.Instrumentable) (string, error) {
	if tmpDir, ok := ie.FileInfo.Service.EnvVars["TMPDIR"]; ok {
		if dirOK(root, tmpDir) {
			return tmpDir, nil
		}
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

func (i *JavaInjector) NewExecutable(ie *ebpf.Instrumentable) error {
	ctx, cancel := context.WithTimeout(context.Background(), i.cfg.Java.Timeout)
	defer cancel()

	// Channel to receive the result
	type result struct {
		attached bool
		err      error
	}

	resultChan := make(chan result, 1)

	attacher := jvm.NewJAttacher(i.log)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	defer func() {
		if err := attacher.Cleanup(); err != nil {
			slog.Warn("error on JVM attach cleanup", "error", err)
		}
	}()

	if ie.Type == svc.InstrumentableJava {
		// Run the attach procedure in a goroutine, so that we can terminate on stuck attach
		go func() {
			defer func() {
				if r := recover(); r != nil {
					resultChan <- result{err: &JavaInjectError{Message: "attach failed"}}
				}
			}()

			ok, jdk8 := i.verifyJVMVersion(attacher, ie.FileInfo.Pid)
			if !ok {
				resultChan <- result{err: &JavaInjectError{Message: "unsupported Java version for OpenTelemetry eBPF instrumentation"}}
				return
			}

			var loaded bool
			var err error
			if jdk8 {
				loaded, err = i.jdkAgentAlreadyLoadedHotspot8(attacher, ie.FileInfo.Pid)
			} else {
				loaded, err = i.jdkAgentAlreadyLoaded(attacher, ie.FileInfo.Pid)
			}

			if err != nil {
				resultChan <- result{err: err}
				return
			}

			if loaded {
				i.log.Info("OpenTelemetry eBPF Java Agent already loaded, not reloading")
				resultChan <- result{attached: false}
				return
			}

			i.log.Info("injecting OpenTelemetry eBPF instrumentation for Java process", "pid", ie.FileInfo.Pid)

			agentPath, err := i.copyAgent(ie)
			if err != nil {
				i.log.Error("failed to extract java agent", "pid", ie.FileInfo.Pid, "error", err)
				resultChan <- result{err: err}
				return
			}

			if err = i.attachJDKAgent(attacher, ie.FileInfo.Pid, agentPath); err != nil {
				i.log.Error("couldn't attach OpenTelemetry eBPF Java Agent", "pid", ie.FileInfo.Pid, "path", agentPath, "error", err)
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
			i.log.Warn("java attach timed out", "timeout", i.cfg.Java.Timeout, "pid", ie.FileInfo.Pid)
			return &JavaInjectError{Message: "java attach timed out"}
		}
	}

	return nil
}

func getLocalAgentPath() (string, error) {
	// Get the path to OBI
	exePath, err := os.Executable()
	if err != nil {
		return "", err
	}

	// Resolve any symlinks
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		return "", err
	}

	// Get the directory containing OBI
	exeDir := filepath.Dir(exePath)

	// Construct the path to the file relative to OBI
	filePath := filepath.Join(exeDir, ObiJavaAgentFileName)

	return filePath, nil
}

// to be changed in tests
var rootDirForPID func(int32) string = ebpfcommon.RootDirectoryForPID

func (i *JavaInjector) copyAgent(ie *ebpf.Instrumentable) (string, error) {
	root := rootDirForPID(ie.FileInfo.Pid)
	tempDir, err := i.findTempDir(root, ie)
	if err != nil {
		return "", fmt.Errorf("error accessing temp directory: %w", err)
	}

	fullTempDir := filepath.Join(root, tempDir)

	i.log.Info("found injection directory for process", "pid", ie.FileInfo.Pid, "path", fullTempDir)

	agentPathHost := filepath.Join(fullTempDir, ObiJavaAgentFileName)

	source, err := os.Open(i.agentPath)
	if err != nil {
		return "", fmt.Errorf("unable to access OBI java agent: %w", err)
	}

	defer source.Close()
	// Create file with read permissions for owner, group, and others (0644)
	target, err := os.OpenFile(agentPathHost, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return "", fmt.Errorf("unable to create target OBI java agent: %w", err)
	}
	defer target.Close()
	if _, err = target.ReadFrom(source); err != nil {
		return "", fmt.Errorf("error writing java agent to target location: %w", err)
	}

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

func (i *JavaInjector) attachOpts() string {
	var opts []string
	if i.cfg.Java.Debug {
		opts = append(opts, "debug=true")
	}
	if i.cfg.Java.DebugInstrumentation {
		opts = append(opts, "debugBB=true")
	}

	if len(opts) == 0 {
		return ""
	}

	return "=" + strings.Join(opts, ",")
}

func (i *JavaInjector) attachJDKAgent(attacher *jvm.JAttacher, pid int32, path string) error {
	attacher.Init()

	defer func() {
		if err := attacher.Cleanup(); err != nil {
			slog.Warn("error on JVM attach cleanup", "error", err)
		}
	}()
	out, err := attacher.Attach(int(pid), []string{"load", "instrument", "false", path + i.attachOpts()}, false)
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

func (i *JavaInjector) jdkAgentAlreadyLoaded(attacher *jvm.JAttacher, pid int32) (bool, error) {
	attacher.Init()

	defer func() {
		if err := attacher.Cleanup(); err != nil {
			slog.Warn("error on JVM attach cleanup", "error", err)
		}
	}()
	// OpenJ9 doesn't support listing loaded classes
	out, err := attacher.Attach(int(pid), []string{"jcmd", "VM.class_hierarchy"}, true)
	if err != nil {
		i.log.Error("error executing command for the JVM", "pid", pid, "error", err)
		return false, err
	}

	if out == nil {
		return false, nil
	}

	scanner := bufio.NewScanner(out)
	for scanner.Scan() {
		s := scanner.Text()
		// We check for io.opentelemetry.obi.java.Agent/0x<address>
		if strings.Contains(s, "io.opentelemetry.obi.java.Agent/0x") {
			return true, nil
		}
	}

	return false, nil
}

// Hotspot version 8 doesn't support VM.class_hierarchy, we use GC.class_histogram and look for the class itself
// without the address
func (i *JavaInjector) jdkAgentAlreadyLoadedHotspot8(attacher *jvm.JAttacher, pid int32) (bool, error) {
	attacher.Init()

	defer func() {
		if err := attacher.Cleanup(); err != nil {
			slog.Warn("error on JVM attach cleanup", "error", err)
		}
	}()
	// OpenJ9 doesn't support listing loaded classes
	out, err := attacher.Attach(int(pid), []string{"jcmd", "GC.class_histogram"}, true)
	if err != nil {
		i.log.Error("error executing command for the JVM", "pid", pid, "error", err)
		return false, err
	}

	if out == nil {
		return false, nil
	}

	scanner := bufio.NewScanner(out)
	for scanner.Scan() {
		s := scanner.Text()
		// We check for io.opentelemetry.obi.java.Agent
		if strings.Contains(s, "io.opentelemetry.obi.java.Agent") {
			return true, nil
		}
	}

	return false, nil
}

func (i *JavaInjector) verifyJVMVersion(attacher *jvm.JAttacher, pid int32) (bool, bool) {
	attacher.Init()

	defer func() {
		if err := attacher.Cleanup(); err != nil {
			slog.Warn("error on JVM attach cleanup", "error", err)
		}
	}()
	// OpenJ9 doesn't support VM.version command
	out, err := attacher.Attach(int(pid), []string{"jcmd", "VM.version"}, true)
	if err != nil {
		i.log.Error("error executing command for the JVM", "pid", pid, "error", err)
		return false, false
	}

	if out == nil {
		return true, false
	}

	scanner := bufio.NewScanner(out)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "JDK ") {
			// JDK 8 is special, failing to properly detect it can cause errors in applications if they are
			// loaded more than once
			return !strings.HasPrefix(line, "JDK 26"), strings.HasPrefix(line, "JDK 8")
		}
	}
	if err := scanner.Err(); err != nil {
		i.log.Error("error reading from scanner", "error", err)
	}

	return false, false
}
