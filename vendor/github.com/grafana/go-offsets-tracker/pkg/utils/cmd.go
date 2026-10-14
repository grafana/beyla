package utils

import (
	"bytes"
	"os/exec"
)

const ShellToUse = "bash"

func RunCommand(command string, dir string) (string, error) {
	var output bytes.Buffer
	cmd := exec.Command(ShellToUse, "-c", command)
	if dir != "" {
		cmd.Dir = dir
	}

	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	return output.String(), err
}
