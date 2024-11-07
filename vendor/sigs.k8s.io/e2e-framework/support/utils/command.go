/*
Copyright 2023 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"fmt"
	"io"

	"github.com/vladimirvivien/gexe"
	"github.com/vladimirvivien/gexe/exec"
	log "k8s.io/klog/v2"
)

var commandRunner = gexe.New()

// FindOrInstallGoBasedProvider check if the provider specified by the pPath executable exists or not.
// If it exists, it returns the path with no error and if not, it uses the `go install` capabilities to
// install the provider and setup the required binaries to perform the tests. In case if the install
// is done by this helper, it will return the value for installed binary as provider which can then
// be set in the in the invoker to make sure the right path is used for the binaries while invoking
// rest of the workfow after this helper is triggered.
func FindOrInstallGoBasedProvider(pPath, provider, module, version string) (string, error) {
	if commandRunner.Prog().Avail(pPath) != "" {
		log.V(4).InfoS("Found Provider tooling already installed on the machine", "command", pPath)
		return pPath, nil
	}

	installCommand := fmt.Sprintf("go install %s@%s", module, version)
	log.V(4).InfoS("Installing provider tooling using go install", "command", installCommand)
	p := commandRunner.RunProc(installCommand)
	if p.Err() != nil {
		return "", fmt.Errorf("failed to install %s: %s", pPath, p.Err())
	}

	if !p.IsSuccess() || p.ExitCode() != 0 {
		return "", fmt.Errorf("failed to install %s: %s", pPath, p.Result())
	}

	if providerPath := commandRunner.Prog().Avail(provider); providerPath != "" {
		log.V(4).Infof("Installed %s at %s", pPath, providerPath)
		return provider, nil
	}

	p = commandRunner.RunProc("ls $GOPATH/bin")
	if p.Err() != nil {
		return "", fmt.Errorf("failed to install %s: %s", pPath, p.Err())
	}

	p = commandRunner.RunProc("echo $PATH:$GOPATH/bin")
	if p.Err() != nil {
		return "", fmt.Errorf("failed to install %s: %s", pPath, p.Err())
	}

	log.V(4).Info(`Setting path to include $GOPATH/bin:`, p.Result())
	commandRunner.SetEnv("PATH", p.Result())

	if providerPath := commandRunner.Prog().Avail(provider); providerPath != "" {
		log.V(4).Infof("Installed %s at %s", pPath, providerPath)
		return provider, nil
	}

	return "", fmt.Errorf("%s not available even after installation", provider)
}

// RunCommand run command and returns an *exec.Proc with information about the executed process.
func RunCommand(command string) *exec.Proc {
	return commandRunner.RunProc(command)
}

// RunCommandWithSeperatedOutput run command and returns the results to the provided
// stdout and stderr io.Writer.
func RunCommandWithSeperatedOutput(command string, stdout, stderr io.Writer) error {
	p := commandRunner.NewProc(command)
	p.SetStdout(stdout)
	p.SetStderr(stderr)
	result := p.Run()

	return result.Err()
}

// FetchCommandOutput run command and returns the combined stderr and stdout output.
func FetchCommandOutput(command string) string {
	return commandRunner.Run(command)
}
