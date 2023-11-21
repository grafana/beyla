// Package container provides helper tools to inspect container information
package container

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strconv"
)

var procRoot = "/proc/"

type Info struct {
	ContainerID string
}

// A docker cgroup entry is a string like:
// 0::/docker/<hex...>/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/
// kubelet-kubepods-besteffort-pod<hex...>.slice/cri-containerd-<hex...>.scope
// where the last <hex...> chain is the container ID inside its Pod
var dockerCgroup = regexp.MustCompile(`^\d+:.*:.*/kubelet.slice/.*-(.+).scope$`)

func InfoForPID(pid uint32) (Info, error) {
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
		return Info{ContainerID: string(submatches[1])}, nil
	}
	return Info{}, fmt.Errorf("%s: couldn't find any docker entry for process with PID %d", cgroupFile, pid)
}
