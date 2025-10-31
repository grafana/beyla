// Package docker provides some helpers to manage docker-compose clusters from the test suites
package docker

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/grafana/beyla/v2/internal/test/tools"
)

type Compose struct {
	Path   string
	Logger io.WriteCloser
	Env    []string
}

func defaultEnv() []string {
	env := os.Environ()
	env = append(env, "BEYLA_EXECUTABLE_NAME=testserver")
	env = append(env, "JAVA_EXECUTABLE_NAME=greeting")
	return env
}

func ComposeSuite(composeFile, logFile string) (*Compose, error) {
	logs, err := os.OpenFile(logFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0666)
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
