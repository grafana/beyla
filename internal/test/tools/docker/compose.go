// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package docker provides some helpers to manage docker-compose clusters from the test suites
package docker // import "go.opentelemetry.io/obi/internal/test/integration/components/docker"

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/grafana/beyla/v3/internal/test/tools"
)

type Compose struct {
	Path   string
	Logger io.WriteCloser
	Env    []string
}

func defaultEnv() []string {
	env := os.Environ()
	env = append(env, "OTEL_EBPF_EXECUTABLE_PATH=testserver")
	env = append(env, "JAVA_EXECUTABLE_PATH=greeting")
	return env
}

func ComposeSuite(composeFile, logFile string) (*Compose, error) {
	logs, err := os.OpenFile(logFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o666)
	if err != nil {
		return nil, err
	}

	// Construct the full path to the Docker Compose file
	projectRoot := tools.ProjectDir()
	composePath := filepath.Join(projectRoot, "internal", "test", "integration", composeFile)

	return &Compose{
		Path:   composePath,
		Logger: logs,
		Env:    defaultEnv(),
	}, nil
}

func (c *Compose) Up() error {
	// When SKIP_DOCKER_BUILD is set, Docker images have been pre-built on the host
	// and loaded into the VM's Docker daemon. Skip --build to avoid rebuilding them
	// inside the VM (which is extremely slow under TCG/software CPU emulation).
	// Without --build, compose will still auto-build any missing images.
	if os.Getenv("SKIP_DOCKER_BUILD") != "" {
		return c.command("up", "--detach", "--quiet-pull")
	}
	return c.command("up", "--build", "--detach", "--quiet-pull")
}

func (c *Compose) Logs() error {
	return c.command("logs")
}

func (c *Compose) Stop() error {
	return c.command("stop")
}

func (c *Compose) Remove() error {
	return c.command("rm", "-f", "-v")
}

func (c *Compose) command(args ...string) error {
	cmdArgs := []string{"compose", "--ansi", "never", "-f", c.Path}
	cmdArgs = append(cmdArgs, args...)
	cmd := exec.Command("docker", cmdArgs...)
	cmd.Env = c.Env
	if c.Logger != nil {
		cmd.Stdout = c.Logger
		cmd.Stderr = c.Logger
	}
	return cmd.Run()
}

func (c *Compose) Close() error {
	var errs []string
	if err := c.Logs(); err != nil {
		errs = append(errs, err.Error())
	}
	if err := c.Stop(); err != nil {
		errs = append(errs, err.Error())
	}
	if err := c.Remove(); err != nil {
		errs = append(errs, err.Error())
	}
	if err := c.Logger.Close(); err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) == 0 {
		return nil
	}
	return errors.New(strings.Join(errs, " / "))
}
