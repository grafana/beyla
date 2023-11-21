package kube

import (
	"fmt"
	"log/slog"
	"time"

	ebpfcommon "github.com/grafana/beyla/pkg/internal/ebpf/common"
	"github.com/grafana/beyla/pkg/internal/helpers/container"
)

func dblog() *slog.Logger {
	return slog.With("component", "kube.Database")
}

type nsPid struct {
	ns  uint32
	pid uint32
}
type Database struct {
	informer      Metadata
	containerPIDs ebpfcommon.NSPIDsMap[*container.Info]

	fetchedContainersCache map[nsPid]*PodInfo
}

func StartDatabase(kubeConfigPath string, informersTimeout time.Duration) (*Database, error) {
	db := Database{
		fetchedContainersCache: map[nsPid]*PodInfo{},
		containerPIDs:          ebpfcommon.NewNSPIDsMap[*container.Info](),
	}
	if err := db.informer.InitFromConfig(kubeConfigPath, informersTimeout); err != nil {
		return nil, fmt.Errorf("starting informers' database: %w", err)
	}
	return &db, nil
}

// AddProcess also searches for the container.Info of the passed PID
func (id *Database) AddProcess(pid uint32) {
	ifp, err := container.InfoForPID(pid)
	if err != nil {
		dblog().Debug("failing to get container information", "pid", pid, "error", err)
		return
	}
	if err := id.containerPIDs.AddPID(pid, &ifp); err != nil {
		dblog().Debug("failing to associate container info to PID", "pid", pid, "error", err)
	}
}

func (id *Database) DeleteProcess(pid uint32) {
	ns, err := id.containerPIDs.RemovePID(pid)
	if err != nil {
		dblog().Debug("failing to remove container info from PID", "pid", pid, "error", err)
	}
	delete(id.fetchedContainersCache, nsPid{ns: ns, pid: pid})
}

func (id *Database) OwnerPodInfo(namespace, pid uint32) (*PodInfo, bool) {
	nsp := nsPid{ns: namespace, pid: pid}
	pod, ok := id.fetchedContainersCache[nsp]
	if !ok {
		info, ok := id.containerPIDs.Get(namespace, pid)
		if !ok {
			return nil, false
		}
		pod, ok = id.informer.GetContainerPod(info.ContainerID)
		if !ok {
			return nil, false
		}
		id.fetchedContainersCache[nsp] = pod
	}
	// we check DeploymentName after caching, as the replicasetInfo might be
	// received late
	if pod.DeploymentName == "" && pod.ReplicaSetName != "" {
		if rsi, ok := id.informer.GetReplicaSetInfo(pod.ReplicaSetName); ok {
			pod.DeploymentName = rsi.DeploymentName
		}
	}
	return pod, true
}
