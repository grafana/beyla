// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package container provides helper tools to inspect container information
package container

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strconv"

	"go.opentelemetry.io/obi/pkg/components/exec"
)

// injectable values for testing
var (
	procRoot        = "/proc/"
	namespaceFinder = exec.FindNamespace
)

// Info that we need to keep from a container: its ContainerID in Kubernetes and
// the PIDNamespace of its processes.
// Many containers in the same pod will have different ContainerID but the same
// PIDNamespace
type Info struct {
	ContainerID  string
	PIDNamespace uint32
}

var cgroupFormats = []*regexp.Regexp{
	// 0::/docker/<hex...>/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-pod<hex...>.slice/cri-containerd-<hex...>.scope
	// where the last <hex...> chain is the container ID inside its Pod
	regexp.MustCompile(`^\d+:.*:.*/.*-([\da-fA-F]+)\.scope`),

	// formats for other Kubernetes distributions
	// GKE: /kubepods/burstable/pod4a163a05-439d-484b-8e53-2968bc15824f/cde6dfaf5007ed65aad2d6aed72af91b0f3d95813492f773286e29ae145d20f4
	// GKE-containerd: /kubepods/burstable/podb53dfa9e2dc9b890f7fadb2770857b03/bb959773d06ad1a07d469bced637bbc49b6f8573c493fd0548d7f5810eb3e5a8
	// EKS: /kubepods.slice/kubepods-burstable.slice/kubepods-burstable-poddde1244b_5bb5_4297_b544_85f3bc0d80bf.slice/cri-containerd-acb62391578595ec849d87d8556369cee7f935f0425097fd5f870df0e8aabd3c.scope
	// Containerd: /kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod7260904bbd08e72e4dff95d9fccd2ee8.slice/cri-containerd-d36686f9785534531160dc936aec9d711a26eb37f4fc7752a2ae27d0a24345c1.scope
	regexp.MustCompile(`^\d+:.*:/kubepods.*([0-9a-f]{64})`),

	// formats for other Cgroup v2 implementations
	regexp.MustCompile(`^\d+:.*:/k8s\.io/([0-9a-f]{64})`),

	// as fallback, other formats for cgroup which might appear in other Docker implementations
	// 0::/../../pode039200acb850c82bb901653cc38ff6e/58452031ab6dcaa4fe3ff91f8a46fd41a4a2405586f3cf3d5cb9c93b5bcf62cc
	regexp.MustCompile(`^\d+:.*:.*/.*/.*/([0-9a-fA-F]{64})`),
}

// InfoForPID returns the container ID and PID namespace for the given PID.
func InfoForPID(pid uint32) (Info, error) {
	ns, err := namespaceFinder(int32(pid))
	if err != nil {
		return Info{}, fmt.Errorf("finding PID %d namespace: %w", pid, err)
	}
	cgroupFile := procRoot + strconv.Itoa(int(pid)) + "/cgroup"
	cgroupBytes, err := os.ReadFile(cgroupFile)
	if err != nil {
		return Info{}, fmt.Errorf("reading %s: %w", cgroupFile, err)
	}

	for _, cgroupEntry := range bytes.Split(cgroupBytes, []byte{'\n'}) {
		if cgroupID, ok := findCgroup(string(cgroupEntry)); ok {
			return Info{PIDNamespace: ns, ContainerID: cgroupID}, nil
		}
	}
	return Info{}, fmt.Errorf("%s: couldn't find any docker entry for process with PID %d", cgroupFile, pid)
}

// look for a cgroup ID on all the possible formats
func findCgroup(cgroupEntry string) (string, bool) {
	for _, re := range cgroupFormats {
		submatches := re.FindStringSubmatch(cgroupEntry)
		if len(submatches) < 2 {
			continue
		}
		return submatches[1], true
	}
	return "", false
}
