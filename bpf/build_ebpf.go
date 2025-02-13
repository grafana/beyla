//go:build beyla_gen_bpf

//go:generate go run build_ebpf.go

package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

const OCI_BIN = "docker"
const GEN_IMG = "ghcr.io/grafana/beyla-ebpf-generator:main"

func getPipes(cmd *exec.Cmd) (io.ReadCloser, io.ReadCloser, error) {
	stdout, err := cmd.StdoutPipe()

	if err != nil {
		return nil, nil, fmt.Errorf("error getting stdout pipe: %v", err)
	}

	stderr, err := cmd.StderrPipe()

	if err != nil {
		stdout.Close()
		return nil, nil, fmt.Errorf("error getting stderr pipe: %v", err)
	}

	return stdout, stderr, nil
}

func moduleRoot() (string, error) {
	wd, err := os.Getwd()

	if err != nil {
		return "", fmt.Errorf("could not get current working directory: %v", err)
	}

	for {
		if _, err := os.Stat(filepath.Join(wd, "LICENSE")); err == nil {
			// Found LICENSE, we are at the module root
			break
		}
		wd = filepath.Dir(wd)
		if wd == "/" || wd == "." {
			return "", fmt.Errorf("could not find module root")
		}
	}

	return wd, nil
}

func main() {
	if runtime.GOOS != "linux" {
		return
	}

	wd, err := moduleRoot()

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	cmd := exec.Command(OCI_BIN, "run", "--rm", "-v", wd+":/src", GEN_IMG)

	stdoutPipe, stderrPipe, err := getPipes(cmd)

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	defer stdoutPipe.Close()
	defer stderrPipe.Close()

	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to start program:", err)
		os.Exit(1)
	}

	go io.Copy(os.Stdout, stdoutPipe)
	go io.Copy(os.Stderr, stderrPipe)

	if err := cmd.Wait(); err != nil {
		fmt.Fprintln(os.Stderr, "Error waiting for child process:", err)
	}
}
