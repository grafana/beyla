package kube

import (
	"log/slog"
	"strings"
	"sync"

	"github.com/grafana/beyla/pkg/export/attributes"
	"github.com/grafana/beyla/pkg/internal/helpers/container"
	"github.com/grafana/beyla/pkg/kubecache/informer"
	"github.com/grafana/beyla/pkg/kubecache/meta"
)

func dblog() *slog.Logger {
	return slog.With("component", "kube.Store")
}

const (
	envServiceName      = "OTEL_SERVICE_NAME"
	envResourceAttrs    = "OTEL_RESOURCE_ATTRIBUTES"
	serviceNameKey      = "service.name"
	serviceNamespaceKey = "service.namespace"
)

type OTelServiceNamePair struct {
	Name      string
	Namespace string
}

// Store aggregates Kubernetes information from multiple sources:
// - the informer that keep an indexed copy of the existing pods and replicasets.
// - the inspected container.Info objects, indexed either by container ID and PID namespace
// - a cache of decorated PodInfo that would avoid reconstructing them on each trace decoration
type Store struct {
	log    *slog.Logger
	access sync.RWMutex

	metadataNotifier meta.Notifier

	containerIDs map[string]*container.Info

	// stores container info by PID. It is only required for
	// deleting entries in namespaces and podsByContainer when DeleteProcess is called
	containerByPID map[uint32]*container.Info

	// a single namespace will point to any container inside the pod
	// but we don't care which one
	namespaces map[uint32]*container.Info

	// container ID to pod matcher
	podsByContainer   map[string]*informer.ObjectMeta
	containersByOwner map[string][]*informer.ContainerInfo

	// ip to generic IP info (Node, Service, *including* Pods)
	ipInfos             map[string]*informer.ObjectMeta
	otelServiceInfoByIP map[string]OTelServiceNamePair

	// Instead of subscribing to the informer directly, the rest of components
	// will subscribe to this store, to make sure that any "new object" notification
	// they receive is already present in the store
	meta.BaseNotifier
}

func NewStore(kubeMetadata meta.Notifier) *Store {
	db := &Store{
		log:                 dblog(),
		containerIDs:        map[string]*container.Info{},
		namespaces:          map[uint32]*container.Info{},
		podsByContainer:     map[string]*informer.ObjectMeta{},
		containerByPID:      map[uint32]*container.Info{},
		ipInfos:             map[string]*informer.ObjectMeta{},
		containersByOwner:   map[string][]*informer.ContainerInfo{},
		otelServiceInfoByIP: map[string]OTelServiceNamePair{},
		metadataNotifier:    kubeMetadata,
		BaseNotifier:        meta.NewBaseNotifier(),
	}
	kubeMetadata.Subscribe(db)
	return db
}

func (s *Store) ID() string { return "unique-metadata-observer" }

// On is invoked by the informer when a new Kube object is created, updated or deleted.
// It will forward the notification to all the Stroe subscribers
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
		s.log.Debug("failing to get container information", "pid", pid, "error", err)
		return
	}

	s.log.Debug("Adding containerID for process", "pid", pid, "containerID", ifp.ContainerID, "pidNs", ifp.PIDNamespace)

	s.access.Lock()
	defer s.access.Unlock()
	s.namespaces[ifp.PIDNamespace] = &ifp
	s.containerIDs[ifp.ContainerID] = &ifp
	s.containerByPID[pid] = &ifp
}

func (s *Store) DeleteProcess(pid uint32) {
	s.access.Lock()
	defer s.access.Unlock()
	info, ok := s.containerByPID[pid]
	if !ok {
		return
	}
	delete(s.containerByPID, pid)
	delete(s.namespaces, info.PIDNamespace)
	delete(s.containerIDs, info.ContainerID)
}

func (s *Store) updateNewObjectMetaByIPIndex(meta *informer.ObjectMeta) {
	s.access.Lock()
	defer s.access.Unlock()
	for _, ip := range meta.Ips {
		s.ipInfos[ip] = meta
	}

	s.otelServiceInfoByIP = map[string]OTelServiceNamePair{}

	if meta.Pod != nil {
		s.log.Debug("adding pod to store",
			"ips", meta.Ips, "pod", meta.Name, "namespace", meta.Namespace, "containers", meta.Pod.Containers)
		for _, c := range meta.Pod.Containers {
			s.podsByContainer[c.Id] = meta
			// TODO: make sure we can handle when the containerIDs is set after this function is triggered
			info, ok := s.containerIDs[c.Id]
			if ok {
				s.namespaces[info.PIDNamespace] = info
			}
		}
		if owner := TopOwner(meta.Pod); owner != nil {
			oID := ownerID(meta.Namespace, owner.Name)
			containers, ok := s.containersByOwner[oID]
			if !ok {
				containers = []*informer.ContainerInfo{}
			}
			containers = append(containers, meta.Pod.Containers...)
			s.containersByOwner[oID] = containers
		}
	}
}

func (s *Store) updateDeletedObjectMetaByIPIndex(meta *informer.ObjectMeta) {
	s.access.Lock()
	defer s.access.Unlock()
	// clean up the IP to service cache, we have to clean everything since
	// Otel variables on specific pods can change the outcome.
	s.otelServiceInfoByIP = map[string]OTelServiceNamePair{}

	for _, ip := range meta.Ips {
		delete(s.ipInfos, ip)
	}
	if meta.Pod != nil {
		s.log.Debug("deleting pod from store",
			"ips", meta.Ips, "pod", meta.Name, "namespace", meta.Namespace, "containers", meta.Pod.Containers)
		toRemove := map[string]struct{}{}
		for _, c := range meta.Pod.Containers {
			toRemove[c.Id] = struct{}{}

			info, ok := s.containerIDs[c.Id]
			if ok {
				delete(s.containerIDs, c.Id)
				delete(s.namespaces, info.PIDNamespace)
			}
			delete(s.podsByContainer, c.Id)
		}

		// clean up the owner to container map
		if owner := TopOwner(meta.Pod); owner != nil {
			oID := ownerID(meta.Namespace, owner.Name)
			if containers, ok := s.containersByOwner[oID]; ok {
				withoutPod := []*informer.ContainerInfo{}
				// filter out all containers owned by this pod
				for _, c := range containers {
					if _, ok := toRemove[c.Id]; !ok {
						withoutPod = append(withoutPod, c)
					}
				}
				// update the owner to container mapping or remove if empty
				if len(withoutPod) > 0 {
					s.containersByOwner[oID] = withoutPod
				} else {
					delete(s.containersByOwner, oID)
				}
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
	return s.objectMetaByIP(ip)
}

func (s *Store) objectMetaByIP(ip string) *informer.ObjectMeta {
	return s.ipInfos[ip]
}

func (s *Store) ServiceNameNamespaceForMetadata(om *informer.ObjectMeta) (string, string) {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.serviceNameNamespaceForMetadata(om)
}

func (s *Store) serviceNameNamespaceForMetadata(om *informer.ObjectMeta) (string, string) {
	var name string
	var namespace string
	if owner := TopOwner(om.Pod); owner != nil {
		name, namespace = s.serviceNameNamespaceForPod(om, owner)
	} else {
		name, namespace = s.serviceNameNamespaceForOwner(om)
	}
	return name, namespace
}

// ServiceNameNamespaceForIP returns the service name and namespace for a given IP address
// This means that, for a given Pod, we will not return the Pod Name, but the Pod Owner Name
func (s *Store) ServiceNameNamespaceForIP(ip string) (string, string) {
	s.access.RLock()
	if serviceInfo, ok := s.otelServiceInfoByIP[ip]; ok {
		s.access.RUnlock()
		return serviceInfo.Name, serviceInfo.Namespace
	}

	name, namespace := "", ""
	if om := s.objectMetaByIP(ip); om != nil {
		name, namespace = s.serviceNameNamespaceForMetadata(om)
	}
	s.access.RUnlock()

	s.access.Lock()
	s.otelServiceInfoByIP[ip] = OTelServiceNamePair{Name: name, Namespace: namespace}
	s.access.Unlock()

	return name, namespace
}

func (s *Store) serviceNameNamespaceForOwner(om *informer.ObjectMeta) (string, string) {
	ownerKey := ownerID(om.Namespace, om.Name)
	return s.serviceNameNamespaceOwnerID(ownerKey, om.Name, om.Namespace)
}

func (s *Store) serviceNameNamespaceForPod(om *informer.ObjectMeta, owner *informer.Owner) (string, string) {
	ownerKey := ownerID(om.Namespace, owner.Name)
	return s.serviceNameNamespaceOwnerID(ownerKey, owner.Name, om.Namespace)
}

func (s *Store) serviceNameNamespaceOwnerID(ownerKey, name, namespace string) (string, string) {
	serviceName := name
	serviceNamespace := namespace

	if envName, ok := s.serviceNameFromEnv(ownerKey); ok {
		serviceName = envName
	}
	if envName, ok := s.serviceNamespaceFromEnv(ownerKey); ok {
		serviceNamespace = envName
	}

	return serviceName, serviceNamespace
}

func (s *Store) nameFromResourceAttrs(variable string, c *informer.ContainerInfo) (string, bool) {
	if resourceVars, ok := c.Env[envResourceAttrs]; ok {
		allVars := map[string]string{}
		collect := func(k string, v string) {
			allVars[k] = v
		}
		attributes.ParseOTELResourceVariable(resourceVars, collect)
		if result, ok := allVars[variable]; ok {
			return result, true
		}
	}

	return "", false
}

func isValidServiceName(name string) bool {
	return name != "" && !strings.HasPrefix(name, "$(")
}

func (s *Store) serviceNameFromEnv(ownerKey string) (string, bool) {
	if containers, ok := s.containersByOwner[ownerKey]; ok {
		for _, c := range containers {
			if serviceName, ok := c.Env[envServiceName]; ok {
				return serviceName, isValidServiceName(serviceName)
			}

			if serviceName, ok := s.nameFromResourceAttrs(serviceNameKey, c); ok {
				return serviceName, isValidServiceName(serviceName)
			}
		}
	}
	return "", false
}

func (s *Store) serviceNamespaceFromEnv(ownerKey string) (string, bool) {
	if containers, ok := s.containersByOwner[ownerKey]; ok {
		for _, c := range containers {
			if namespace, ok := s.nameFromResourceAttrs(serviceNamespaceKey, c); ok {
				return namespace, isValidServiceName(namespace)
			}
		}
	}
	return "", false
}

func ownerID(namespace, name string) string {
	return namespace + "." + name
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
