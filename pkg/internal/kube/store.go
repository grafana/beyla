package kube

import (
	"log/slog"
	"sync"

	"github.com/grafana/beyla-k8s-cache/pkg/informer"
	"github.com/grafana/beyla-k8s-cache/pkg/meta"

	"github.com/grafana/beyla/pkg/internal/helpers/container"
)

func dblog() *slog.Logger {
	return slog.With("component", "kube.Store")
}

// Store aggregates Kubernetes information from multiple sources:
// - the informer that keep an indexed copy of the existing pods and replicasets.
// - the inspected container.Info objects, indexed either by container ID and PID namespace
// - a cache of decorated PodInfo that would avoid reconstructing them on each trace decoration
type Store struct {
	access sync.RWMutex

	metadataNotifier MetadataNotifier

	containerIDs map[string]*container.Info

	// a single namespace will point to any container inside the pod
	// but we don't care which one
	namespaces map[uint32]*container.Info

	// container ID to pod matcher
	podsByContainer map[string]*informer.ObjectMeta

	// ip to generic IP info (Node, Service, *including* Pods)
	ipInfos map[string]*informer.ObjectMeta

	// Instead of subscribing to the informer directly, the rest of components
	// will subscribe to this store, to make sure that any "new object" notification
	// they receive is already present in the store
	meta.BaseNotifier
}

func NewStore(kubeMetadata MetadataNotifier) *Store {
	db := &Store{
		containerIDs:     map[string]*container.Info{},
		namespaces:       map[uint32]*container.Info{},
		podsByContainer:  map[string]*informer.ObjectMeta{},
		ipInfos:          map[string]*informer.ObjectMeta{},
		metadataNotifier: kubeMetadata,
		BaseNotifier:     meta.NewBaseNotifier(),
	}
	kubeMetadata.Subscribe(db)
	return db
}

func (s *Store) ID() string {
	return "unique-metadata-observer"
}

func (s *Store) On(event *informer.Event) {
	switch event.Type {
	case informer.EventType_CREATED, informer.EventType_UPDATED:
		s.updateNewObjectMetaByIPIndex(event.Resource)
		// TODO: if the updated message lacks an IP that was previously present in the pod
		// this might cause a memory leak, as we are not removing old entries
		// this is very unlikely and the IP could be reused by another pod later
	case informer.EventType_DELETED:
		s.updateDeletedObjectMetaByIPIndex(event.Resource)
	}
	s.BaseNotifier.Notify(event)
}

// InfoForPID is an injectable dependency for system-independent testing
var InfoForPID = container.InfoForPID

func (s *Store) AddProcess(pid uint32) {
	ifp, err := InfoForPID(pid)
	if err != nil {
		dblog().Debug("failing to get container information", "pid", pid, "error", err)
		return
	}

	s.access.Lock()
	defer s.access.Unlock()
	s.namespaces[ifp.PIDNamespace] = &ifp
	s.containerIDs[ifp.ContainerID] = &ifp
}

func (s *Store) updateNewObjectMetaByIPIndex(meta *informer.ObjectMeta) {
	s.access.Lock()
	defer s.access.Unlock()
	for _, ip := range meta.Ips {
		s.ipInfos[ip] = meta
	}
	if meta.Pod != nil {
		for _, cid := range meta.Pod.ContainerIds {
			s.podsByContainer[cid] = meta
			// TODO: make sure we can handle when the containerIDs is set after this function is triggered
			info, ok := s.containerIDs[cid]
			if ok {
				s.namespaces[info.PIDNamespace] = info
			}
		}
	}
}

func (s *Store) updateDeletedObjectMetaByIPIndex(meta *informer.ObjectMeta) {
	s.access.Lock()
	defer s.access.Unlock()
	for _, ip := range meta.Ips {
		delete(s.ipInfos, ip)
	}
	if meta.Pod != nil {
		for _, cid := range meta.Pod.ContainerIds {
			info, ok := s.containerIDs[cid]
			if ok {
				delete(s.containerIDs, cid)
				delete(s.namespaces, info.PIDNamespace)
			}
		}
	}
}

func (s *Store) PodByContainerID(cid string) *informer.ObjectMeta {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.podsByContainer[cid]
}

func (s *Store) PodByPIDNs(pidns uint32) *informer.ObjectMeta {
	s.access.RLock()
	defer s.access.RUnlock()
	if info, ok := s.namespaces[pidns]; ok {
		return s.podsByContainer[info.ContainerID]
	}
	return nil
}

func (s *Store) ObjectMetaByIP(ip string) *informer.ObjectMeta {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.ipInfos[ip]
}

// ServiceNameNamespaceForIP returns the service name and namespace for a given IP address
// This means that, for a given Pod, we will not return the Pod Name, but the Pod Owner Name
func (s *Store) ServiceNameNamespaceForIP(ip string) (string, string) {
	if om := s.ObjectMetaByIP(ip); om != nil {
		if owner := TopOwner(om.Pod); owner != nil {
			return owner.Name, om.Namespace
		}
		return om.Name, om.Namespace
	}
	return "", ""
}

// Subscribe overrides BaseNotifier to send a "welcome message" to each new observer
// containing the whole metadata store
func (s *Store) Subscribe(observer meta.Observer) {
	s.access.RLock()
	defer s.access.RUnlock()
	s.BaseNotifier.Subscribe(observer)
	for _, pod := range s.podsByContainer {
		observer.On(&informer.Event{Type: informer.EventType_CREATED, Resource: pod})
	}
	// the IPInfos could contain IPInfo data from Pods already sent in the previous loop
	// is the subscriber the one that should decide whether to ignore such duplicates or
	// incomplete info
	for _, ips := range s.ipInfos {
		observer.On(&informer.Event{Type: informer.EventType_CREATED, Resource: ips})
	}
}
