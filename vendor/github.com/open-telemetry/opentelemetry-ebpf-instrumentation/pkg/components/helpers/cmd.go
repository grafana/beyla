// Copyright 2020 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
package helpers

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
)

type Command struct {
	*exec.Cmd
}

func NewCommand(command string, arguments ...string) *Command {
	return &Command{Cmd: exec.Command(command, arguments...)}
}

func (c *Command) WithStdin(stdin string) *Command {
	c.Stdin = bytes.NewBufferString(stdin)
	return c
}

func (c *Command) Run() (string, error) {
	// Set the locale
	c.Env = append(os.Environ(), "LANG=en_US.utf8")
	outputCommand, errorCommand := c.CombinedOutput()
	return strings.TrimSpace(string(outputCommand)), errorCommand
}

func RunCommand(command string, stdin string, arguments ...string) (string, error) {
	return NewCommand(command, arguments...).WithStdin(stdin).Run()
}
