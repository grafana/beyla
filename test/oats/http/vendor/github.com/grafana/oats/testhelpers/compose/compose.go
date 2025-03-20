// Package docker provides some helpers to manage docker-compose clusters from the test suites
package compose

import (
	"errors"
	"fmt"
	"github.com/onsi/ginkgo/v2"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
)

type Compose struct {
	Command     string
	DefaultArgs []string
	Path        string
	Logger      io.WriteCloser
	Env         []string
}

func defaultEnv() []string {
	return os.Environ()
}

func ComposeSuite(composeFile, logFile string) (*Compose, error) {
	logs, err := os.OpenFile(logFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0666)
	if err != nil {
		return nil, err
	}
	abs, _ := filepath.Abs(logFile)
	ginkgo.GinkgoWriter.Printf("Logging to %s\n", abs)

	command := "docker"
	defaultArgs := []string{"compose"}

	return &Compose{
		Command:     command,
		DefaultArgs: defaultArgs,
		Path:        path.Join(composeFile),
		Logger:      logs,
		Env:         defaultEnv(),
	}, nil
}

func (c *Compose) Up() error {
	//networks accumulate over time and can cause issues with the tests
	configuration, _ := ginkgo.GinkgoConfiguration()
	if configuration.ParallelProcess == 1 {
		//don't do this in parallel, it can cause issues
		err := c.runDocker(false, "network", "prune", "-f", "--filter", "until=5m")
		if err != nil {
			return fmt.Errorf("failed to prune docker networks: %w", err)
		}
	}

	return c.command("up", "--build", "--detach", "--force-recreate")
}

func (c *Compose) Logs() error {
	return c.command("logs")
}

func (c *Compose) Stop() error {
	return c.command("stop")
}

func (c *Compose) Remove() error {
	return c.command("rm", "-f")
}

func (c *Compose) command(args ...string) error {
	return c.runDocker(true, args...)
}

func (c *Compose) runDocker(composeCommand bool, args ...string) error {
	var cmdArgs []string
	if composeCommand {
		cmdArgs = c.DefaultArgs
		cmdArgs = append(cmdArgs, "-f", c.Path)
	}
	cmdArgs = append(cmdArgs, args...)
	cmd := exec.Command(c.Command, cmdArgs...)
	cmd.Env = c.Env
	if c.Logger != nil {
		cmd.Stdout = c.Logger
		cmd.Stderr = c.Logger
		fmt.Fprintf(c.Logger, "Running: docker %s\n", cmd.String())
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
