// Package container provides helper tools to inspect container information
package container

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strconv"

	ebpfcommon "github.com/grafana/beyla/pkg/internal/ebpf/common"
)

// injectable values for testing
var procRoot = "/proc/"
var namespaceFinder = ebpfcommon.FindNamespace

// Info that we need to keep from a container: its ContainerID in Kubernetes and
// the PIDNamespace of its processes.
// Many containers in the same pod will have different ContainerID but the same
// PIDNamespace
type Info struct {
	ContainerID  string
	PIDNamespace uint32
}

// A docker cgroup entry is a string like - when running beyla as a process on the node:
// 0::/docker/<hex...>/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-pod<hex...>.slice/cri-containerd-<hex...>.scope
// where the last <hex...> chain is the container ID inside its Pod
var dockerCgroup = regexp.MustCompile(`^\d+:.*:.*/docker.*-([\da-fA-F]+)\.scope`)

// A k8s cgroup entry is a string like - when running beyla as daemonset in k8s:
// GKE: /kubepods/burstable/pod4a163a05-439d-484b-8e53-2968bc15824f/cde6dfaf5007ed65aad2d6aed72af91b0f3d95813492f773286e29ae145d20f4
// GKE-containerd: /kubepods/burstable/podb53dfa9e2dc9b890f7fadb2770857b03/bb959773d06ad1a07d469bced637bbc49b6f8573c493fd0548d7f5810eb3e5a8
// EKS: /kubepods.slice/kubepods-burstable.slice/kubepods-burstable-poddde1244b_5bb5_4297_b544_85f3bc0d80bf.slice/cri-containerd-acb62391578595ec849d87d8556369cee7f935f0425097fd5f870df0e8aabd3c.scope
// Containerd: /kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod7260904bbd08e72e4dff95d9fccd2ee8.slice/cri-containerd-d36686f9785534531160dc936aec9d711a26eb37f4fc7752a2ae27d0a24345c1.scope
var k8sCgroup = regexp.MustCompile(`\d+:.*:/kubepods.*([0-9a-f]{64})`)

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
	// We look for the docker cgroup entry first, as it's the most common
	for _, cgroupEntry := range bytes.Split(cgroupBytes, []byte{'\n'}) {
		submatches := dockerCgroup.FindSubmatch(cgroupEntry)
		if len(submatches) < 2 {
			continue
		}
		return Info{PIDNamespace: ns, ContainerID: string(submatches[1])}, nil
	}
	// If we didn't find a docker entry, we look for a k8s entry
	for _, cgroupEntry := range bytes.Split(cgroupBytes, []byte{'\n'}) {
		submatches := k8sCgroup.FindSubmatch(cgroupEntry)
		if len(submatches) < 2 {
			continue
		}
		return Info{PIDNamespace: ns, ContainerID: string(submatches[1])}, nil
	}
	return Info{}, fmt.Errorf("%s: couldn't find any docker entry for process with PID %d", cgroupFile, pid)
}
