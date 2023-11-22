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

type Info struct {
	ContainerID  string
	PIDNamespace uint32
}

// A docker cgroup entry is a string like:
// 0::/docker/<hex...>/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/
// kubelet-kubepods-besteffort-pod<hex...>.slice/cri-containerd-<hex...>.scope
// where the last <hex...> chain is the container ID inside its Pod
var dockerCgroup = regexp.MustCompile(`^\d+:.*:.*/kubelet\.slice/.*-(.+)\.scope$`)

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
