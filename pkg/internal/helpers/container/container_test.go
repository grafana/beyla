package container

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fixtureContainerID = "40c03570b6f4c30bc8d69923d37ee698f5cfcced92c7b7df1c47f6f7887378a9"

// key: process ID/folder inside the /proc filesystem
// value: content of the cgroup file
var fixturesWithContainer = map[uint32]string{
	123: `0::/docker/8afe480d66074930353da456a1344caca810fe31c1e31f6e08c95a66887235d6/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-pod44c76ce5_f953_4bd3_bc89_12621681af49.slice/cri-containerd-40c03570b6f4c30bc8d69923d37ee698f5cfcced92c7b7df1c47f6f7887378a9.scope`,
	456: `12:rdma:/
11:perf_event:
10:freezer:/docker/a2ffe0e97ac22657a2a023ad628e9df837c38a03b1ebc904d3f6d644eb1a1a81
9:memory:/docker/a2ffe0e97ac22657a2a023ad628e9df837c38a03b1ebc904d3f6d644eb1a1a81
8:cpuset:/docker/a2ffe0e97ac22657a2a023ad628e9df837c38a03b1ebc904d3f6d644eb1a1a81
7:devices:/docker/a2ffe0e97ac22657a2a023ad628e9df837c38a03b1ebc904d3f6d644eb1a1a81
0::/docker/8afe480d66074930353da456a1344caca810fe31c1e31f6e08c95a66887235d6/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-pod44c76ce5_f953_4bd3_bc89_12621681af49.slice/cri-containerd-40c03570b6f4c30bc8d69923d37ee698f5cfcced92c7b7df1c47f6f7887378a9.scope
6:net_cls,net_prio:/docker/a2ffe0e97ac22657a2a023ad628e9df837c38a03b1ebc904d3f6d644eb1a1a81
5:hugetlb:/docker/a2ffe0e97ac22657a2a023ad628e9df837c38a03b1ebc904d3f6d644eb1a1a81
4:pids:/docker/a2ffe0e97ac22657a2a023ad628e9df837c38a03b1ebc904d3f6d644eb1a1a81
3:cpu,cpuacct:/docker/a2ffe0e97ac22657a2a023ad628e9df837c38a03b1ebc904d3f6d644eb1a1a81
2:blkio:/docker/a2ffe0e97ac22657a2a023ad628e9df837c38a03b1ebc904d3f6d644eb1a1a81
1:name=systemd:/docker/a2ffe0e97ac22657a2a023ad628e9df837c38a03b1ebc904d3f6d644eb1a1a81
0::/system.slice/containerd.service`,
	789: `0::/../cri-containerd-40c03570b6f4c30bc8d69923d37ee698f5cfcced92c7b7df1c47f6f7887378a9.scope`,
	999: `0::/system.slice/docker-40c03570b6f4c30bc8d69923d37ee698f5cfcced92c7b7df1c47f6f7887378a9.scope/kubepods/burstable/podc55ba69a-e39f-44af-925d-c4794fd57878/264c1e319d1f6080a48a9fabcf9ac8fd9afd9a5930cf35e8d0eeb03b258c3152`,
	// GKE cgroup entry
	589: `0::/kubepods/burstable/pod4a163a05-439d-484b-8e53-2968bc15824f/40c03570b6f4c30bc8d69923d37ee698f5cfcced92c7b7df1c47f6f7887378a9`,
	// GKE-containerd cgroup entry
	689: `0::/kubepods/burstable/podb53dfa9e2dc9b890f7fadb2770857b03/40c03570b6f4c30bc8d69923d37ee698f5cfcced92c7b7df1c47f6f7887378a9`,
	// EKS cgroup entry
	788: `0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-poddde1244b_5bb5_4297_b544_85f3bc0d80bf.slice/cri-containerd-40c03570b6f4c30bc8d69923d37ee698f5cfcced92c7b7df1c47f6f7887378a9.scope`,
	// Containerd cgroup entry
	889: `0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod7260904bbd08e72e4dff95d9fccd2ee8.slice/cri-containerd-40c03570b6f4c30bc8d69923d37ee698f5cfcced92c7b7df1c47f6f7887378a9.scope`,
	// Docker 27+
	899: `0::/../../pode039200acb850c82bb901653cc38ff6e/40c03570b6f4c30bc8d69923d37ee698f5cfcced92c7b7df1c47f6f7887378a9`,
}

var fixturesWithoutContainer = map[uint32]string{
	1011: `12:rdma:/
11:perf_event:
10:freezer:/docker/a2ffe0e97ac22657a2a023ad628e9df837c38a03b1ebc904d3f6d644eb1a1a81
9:memory:/docker/a2ffe0e97ac22657a2a023ad628e9df837c38a03b1ebc904d3f6d644eb1a1a81
8:cpuset:/docker/a2ffe0e97ac22657a2a023ad628e9df837c38a03b1ebc904d3f6d644eb1a1a81
7:devices:/docker/a2ffe0e97ac22657a2a023ad628e9df837c38a03b1ebc904d3f6d644eb1a1a81
6:net_cls,net_prio:/docker/a2ffe0e97ac22657a2a023ad628e9df837c38a03b1ebc904d3f6d644eb1a1a81
5:hugetlb:/docker/a2ffe0e97ac22657a2a023ad628e9df837c38a03b1ebc904d3f6d644eb1a1a81
4:pids:/docker/a2ffe0e97ac22657a2a023ad628e9df837c38a03b1ebc904d3f6d644eb1a1a81
3:cpu,cpuacct:/docker/a2ffe0e97ac22657a2a023ad628e9df837c38a03b1ebc904d3f6d644eb1a1a81
2:blkio:/docker/a2ffe0e97ac22657a2a023ad628e9df837c38a03b1ebc904d3f6d644eb1a1a81
1:name=systemd:/docker/a2ffe0e97ac22657a2a023ad628e9df837c38a03b1ebc904d3f6d644eb1a1a81
0::/system.slice/containerd.service`,
}

func mountFixtures(t *testing.T) string {
	dir, err := os.MkdirTemp("", "container_test_ids")
	require.NoError(t, err)

	for _, fixtures := range []map[uint32]string{fixturesWithContainer, fixturesWithoutContainer} {
		for pid, cgroup := range fixtures {
			pdir := fmt.Sprintf("%s/%d", dir, pid)
			require.NoError(t, os.Mkdir(pdir, 0777))
			require.NoError(t, os.WriteFile(pdir+"/cgroup", []byte(cgroup), 0666))
		}
	}
	return dir
}

func TestContainerID(t *testing.T) {
	procRoot = mountFixtures(t) + "/"
	namespaceFinder = func(_ int32) (uint32, error) { return 0, nil }

	for pid := range fixturesWithContainer {
		t.Run(fmt.Sprintf("must find container. PID %d", pid), func(t *testing.T) {
			info, err := InfoForPID(pid)
			require.NoError(t, err)
			assert.Equal(t, fixtureContainerID, info.ContainerID)
		})
	}
	for pid := range fixturesWithoutContainer {
		t.Run(fmt.Sprintf("must not find container. PID %d", pid), func(t *testing.T) {
			_, err := InfoForPID(pid)
			require.Error(t, err)
		})
	}

	_, err := InfoForPID(12345)
	require.Error(t, err)

}
