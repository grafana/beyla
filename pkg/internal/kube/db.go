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
	informer Metadata

	containerIDs map[string]*container.Info
	namespaces   map[uint32]*container.Info

	fetchedPodsCache map[uint32]*PodInfo
}

func StartDatabase(kubeConfigPath string, informersTimeout time.Duration) (*Database, error) {
	db := Database{
		fetchedPodsCache: map[uint32]*PodInfo{},
		containerIDs:     map[string]*container.Info{},
		namespaces:       map[uint32]*container.Info{},
	}
	db.informer.AddContainerEventHandler(&db)
	if err := db.informer.InitFromConfig(kubeConfigPath, informersTimeout); err != nil {
		return nil, fmt.Errorf("starting informers' database: %w", err)
	}
	return &db, nil
}

func (id *Database) OnRemoval(containerID ...string) {
	for _, cid := range containerID {
		if info, ok := id.containerIDs[cid]; ok {
			delete(id.namespaces, info.PIDNamespace)
		}
		delete(id.containerIDs, cid)
	}
}

// AddProcess also searches for the container.Info of the passed PID
func (id *Database) AddProcess(pid uint32) {
	ifp, err := container.InfoForPID(pid)
	if err != nil {
		dblog().Debug("failing to get container information", "pid", pid, "error", err)
		return
	}
	id.namespaces[ifp.PIDNamespace] = &ifp
	id.containerIDs[ifp.ContainerID] = &ifp
}

func (id *Database) OwnerPodInfo(pidNamespace uint32) (*PodInfo, bool) {
	pod, ok := id.fetchedPodsCache[pidNamespace]
	if !ok {
		info, ok := id.namespaces[pidNamespace]
		if !ok {
			return nil, false
		}
		pod, ok = id.informer.GetContainerPod(info.ContainerID)
		if !ok {
			return nil, false
		}
		id.fetchedPodsCache[pidNamespace] = pod
	}
	// we check DeploymentName after caching, as the replicasetInfo might be
	// received late by the other informer
	if pod.DeploymentName == "" && pod.ReplicaSetName != "" {
		if rsi, ok := id.informer.GetReplicaSetInfo(pod.ReplicaSetName); ok {
			pod.DeploymentName = rsi.DeploymentName
		}
	}
	return pod, true
}
