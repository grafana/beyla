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

// A docker cgroup entry is a string like:
// 0::/docker/<hex...>/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/
// kubelet-kubepods-besteffort-pod<hex...>.slice/cri-containerd-<hex...>.scope
// where the last <hex...> chain is the container ID inside its Pod
// The /docker/<hex...> part might not be visible inside the Pod (e.g. deploying Beyla
// as a sidecar). That's why we search for the "kubelet.slice" string.
var dockerCgroup = regexp.MustCompile(`^\d+:.*:.*/.*-(.+)\.scope$`)

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
		submatches := dockerCgroup.FindSubmatch(cgroupEntry)
		if len(submatches) < 2 {
			continue
		}
		return Info{PIDNamespace: ns, ContainerID: string(submatches[1])}, nil
	}
	return Info{}, fmt.Errorf("%s: couldn't find any docker entry for process with PID %d", cgroupFile, pid)
}
