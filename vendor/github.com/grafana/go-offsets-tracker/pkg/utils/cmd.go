package utils

import (
	"bytes"
	"os/exec"
)

const ShellToUse = "bash"

func RunCommand(command string, dir string) (error, string, string) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := exec.Command(ShellToUse, "-c", command)
	if dir != "" {
		cmd.Dir = dir
	}

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return err, stdout.String(), stderr.String()
}
