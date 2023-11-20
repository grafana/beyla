package kube

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/grafana/beyla/pkg/internal/helpers/container"
)

func dblog() *slog.Logger {
	return slog.With("component", "kube.Database")
}

type Database struct {
	informer      Metadata
	containerPIDs map[int]container.Info

	fetchedContainersCache map[int]*PodInfo
}

func StartDatabase(kubeConfigPath string, informersTimeout time.Duration) (*Database, error) {
	db := Database{
		fetchedContainersCache: map[int]*PodInfo{},
		containerPIDs:          map[int]container.Info{},
	}
	if err := db.informer.InitFromConfig(kubeConfigPath, informersTimeout); err != nil {
		return nil, fmt.Errorf("starting informers' database: %w", err)
	}
	return &db, nil
}

// AddProcess also searches for the container.Info of the passed PID
func (id *Database) AddProcess(pid int) {
	ifp, err := container.InfoForPID(pid)
	if err != nil {
		dblog().Debug("failing to get container information", "pid", pid, "error", err)
		return
	}
	id.containerPIDs[pid] = ifp
}

func (id *Database) DeleteProcess(pid int) {
	delete(id.containerPIDs, pid)
	delete(id.fetchedContainersCache, pid)
}

func (id *Database) OwnerPodInfo(pid int) (*PodInfo, bool) {
	pod, ok := id.fetchedContainersCache[pid]
	if !ok {
		info, ok := id.containerPIDs[pid]
		if !ok {
			return nil, false
		}
		pod, ok = id.informer.GetContanerPod(info.ContainerID)
		if !ok {
			return nil, false
		}
		id.fetchedContainersCache[pid] = pod
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
