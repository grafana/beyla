package kube

import (
	"log/slog"
	"strings"
	"sync"

	"github.com/grafana/beyla/pkg/export/attributes"
	"github.com/grafana/beyla/pkg/internal/helpers/container"
	"github.com/grafana/beyla/pkg/internal/helpers/maps"
	"github.com/grafana/beyla/pkg/kubecache/informer"
	"github.com/grafana/beyla/pkg/kubecache/meta"
)

func dblog() *slog.Logger {
	return slog.With("component", "kube.Store")
}

const (
	serviceNameKey      = "service.name"
	serviceNamespaceKey = "service.namespace"
)

type OTelServiceNamePair struct {
	Name      string
	Namespace string
}

type qualifiedName struct {
	name      string
	namespace string
	kind      string
}

func qName(om *informer.ObjectMeta) qualifiedName {
	return qualifiedName{name: om.Name, namespace: om.Namespace, kind: om.Kind}
}

// MetadataSources allow overriding some metadata from kubernetes labels and annotations
type MetadataSources struct {
	Annotations AnnotationSources `yaml:"annotations"`
	Labels      LabelSources      `yaml:"labels"`
}

type LabelSources struct {
	ServiceName      []string `yaml:"service_name" env:"BEYLA_KUBE_LABELS_SERVICE_NAME" envSeparator:","`
	ServiceNamespace []string `yaml:"service_namespace" env:"BEYLA_KUBE_LABELS_SERVICE_NAMESPACE" envSeparator:","`
}

type AnnotationSources struct {
	ServiceName      []string `yaml:"service_name" env:"BEYLA_KUBE_ANNOTATIONS_SERVICE_NAME" envSeparator:","`
	ServiceNamespace []string `yaml:"service_namespace" env:"BEYLA_KUBE_ANNOTATIONS_SERVICE_NAMESPACE" envSeparator:","`
}

var DefaultMetadataSources = MetadataSources{
	Annotations: AnnotationSources{
		ServiceName:      []string{"resource.opentelemetry.io/service.name"},
		ServiceNamespace: []string{"resource.opentelemetry.io/service.namespace"},
	},
	// If a user sets useLabelsForResourceAttributes: false it its OTEL operator, is the task of the
	// OTEL operator to provide empty values for this.
	Labels: LabelSources{
		ServiceName:      []string{"app.kubernetes.io/name"},
		ServiceNamespace: []string{"app.kubernetes.io/part-of"},
	},
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
	podsByContainer map[string]*informer.ObjectMeta
	// first key: pod owner ID, second key: container ID
	containersByOwner maps.Map2[string, string, *informer.ContainerInfo]

	// ip to generic IP info (Node, Service, *including* Pods)
	objectMetaByIP map[string]*informer.ObjectMeta
	// used to track the changed/removed IPs of a given object
	// and remove them from objectMetaByIP on update or deletion
	objectMetaByQName   map[qualifiedName]*informer.ObjectMeta
	otelServiceInfoByIP map[string]OTelServiceNamePair

	// Instead of subscribing to the informer directly, the rest of components
	// will subscribe to this store, to make sure that any "new object" notification
	// they receive is already present in the store
	meta.BaseNotifier

	metadataSources MetadataSources
}

func NewStore(kubeMetadata meta.Notifier, metadataSources MetadataSources) *Store {
	log := dblog()
	db := &Store{
		log:                 log,
		containerIDs:        map[string]*container.Info{},
		namespaces:          map[uint32]*container.Info{},
		podsByContainer:     map[string]*informer.ObjectMeta{},
		containerByPID:      map[uint32]*container.Info{},
		objectMetaByIP:      map[string]*informer.ObjectMeta{},
		objectMetaByQName:   map[qualifiedName]*informer.ObjectMeta{},
		containersByOwner:   maps.Map2[string, string, *informer.ContainerInfo]{},
		otelServiceInfoByIP: map[string]OTelServiceNamePair{},
		metadataNotifier:    kubeMetadata,
		BaseNotifier:        meta.NewBaseNotifier(log),
		metadataSources:     metadataSources,
	}
	kubeMetadata.Subscribe(db)
	return db
}

func (s *Store) ID() string { return "unique-metadata-observer" }

// On is invoked by the informer when a new Kube object is created, updated or deleted.
// It will forward the notification to all the Store subscribers
func (s *Store) On(event *informer.Event) error {
	switch event.Type {
	case informer.EventType_CREATED:
		s.addObjectMeta(event.Resource)
	case informer.EventType_UPDATED:
		s.updateObjectMeta(event.Resource)
	case informer.EventType_DELETED:
		s.deleteObjectMeta(event.Resource)
	}
	s.BaseNotifier.Notify(event)
	return nil
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

func (s *Store) addObjectMeta(meta *informer.ObjectMeta) {
	s.access.Lock()
	defer s.access.Unlock()

	s.unlockedAddObjectMeta(meta)
}

func (s *Store) updateObjectMeta(meta *informer.ObjectMeta) {
	s.access.Lock()
	defer s.access.Unlock()

	// atomically remove the previously stored version of the updated object
	// then re-adding it
	// this will avoid to leak some IPs and containers that exist in the
	// stored snapshot but not in the updated snapshot
	if previousObject, ok := s.objectMetaByQName[qName(meta)]; ok {
		s.unlockedDeleteObjectMeta(previousObject)
	}
	s.unlockedAddObjectMeta(meta)
}

// it's important to make sure that any element added here is removed when
// calling unlockedDeleteObjectMeta with the same ObjectMeta
func (s *Store) unlockedAddObjectMeta(meta *informer.ObjectMeta) {
	qn := qName(meta)
	s.objectMetaByQName[qn] = meta

	for _, ip := range meta.Ips {
		s.objectMetaByIP[ip] = meta
	}

	s.otelServiceInfoByIP = map[string]OTelServiceNamePair{}

	if meta.Pod != nil {
		oID := fetchOwnerID(meta)
		s.log.Debug("adding pod to store",
			"ips", meta.Ips, "pod", meta.Name, "namespace", meta.Namespace, "containers", meta.Pod.Containers)
		for _, c := range meta.Pod.Containers {
			s.podsByContainer[c.Id] = meta
			// TODO: make sure we can handle when the containerIDs is set after this function is triggered
			info, ok := s.containerIDs[c.Id]
			if ok {
				s.namespaces[info.PIDNamespace] = info
			}
			s.containersByOwner.Put(oID, c.Id, c)
		}
	}
}

func (s *Store) deleteObjectMeta(meta *informer.ObjectMeta) {
	s.access.Lock()
	defer s.access.Unlock()
	// clean up the IP to service cache, we have to clean everything since
	// Otel variables on specific pods can change the outcome.
	s.otelServiceInfoByIP = map[string]OTelServiceNamePair{}

	// cleanup both the objectMeta information from the received event
	// as well as from any previous snapshot in the system whose IPs and/or
	// containers could have been removed in the last snapshot

	if previousObject, ok := s.objectMetaByQName[qName(meta)]; ok {
		s.unlockedDeleteObjectMeta(previousObject)
	}
	s.unlockedDeleteObjectMeta(meta)
}

func (s *Store) unlockedDeleteObjectMeta(meta *informer.ObjectMeta) {
	delete(s.objectMetaByQName, qName(meta))
	for _, ip := range meta.Ips {
		delete(s.objectMetaByIP, ip)
	}
	if meta.Pod != nil {
		oID := fetchOwnerID(meta)
		s.log.Debug("deleting pod from store",
			"ips", meta.Ips, "pod", meta.Name, "namespace", meta.Namespace, "containers", meta.Pod.Containers)
		for _, c := range meta.Pod.Containers {
			info, ok := s.containerIDs[c.Id]
			if ok {
				delete(s.containerIDs, c.Id)
				delete(s.namespaces, info.PIDNamespace)
			}
			delete(s.podsByContainer, c.Id)
			s.containersByOwner.Delete(oID, c.Id)
		}
	}
}

func fetchOwnerID(meta *informer.ObjectMeta) string {
	ownerName := meta.Name
	if owner := TopOwner(meta.Pod); owner != nil {
		ownerName = owner.Name
	}
	oID := ownerID(meta.Namespace, ownerName)
	return oID
}

func (s *Store) PodByContainerID(cid string) *informer.ObjectMeta {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.podsByContainer[cid]
}

// PodContainerByPIDNs second return value: container Name
func (s *Store) PodContainerByPIDNs(pidns uint32) (*informer.ObjectMeta, string) {
	s.access.RLock()
	defer s.access.RUnlock()
	if info, ok := s.namespaces[pidns]; ok {
		if om, ok := s.podsByContainer[info.ContainerID]; ok {
			oID := fetchOwnerID(om)
			containerName := ""
			if containerInfo, ok := s.containersByOwner.Get(oID, info.ContainerID); ok {
				containerName = containerInfo.Name
			}
			return om, containerName
		}
	}
	return nil, ""
}

func (s *Store) ObjectMetaByIP(ip string) *informer.ObjectMeta {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.objectMetaByIP[ip]
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
		name, namespace = s.serviceNameNamespaceOwnerID(om, owner.Name)
	} else {
		name, namespace = s.serviceNameNamespaceOwnerID(om, om.Name)
	}
	return name, namespace
}

// function implemented to provide consistent service metadata naming across multiple
// OTEL implementations: OTEL operator, Loki and Beyla
// https://github.com/grafana/k8s-monitoring-helm/issues/942
func (s *Store) valueFromMetadata(om *informer.ObjectMeta, annotationNames, labelNames []string) string {
	for _, key := range annotationNames {
		if val, ok := om.Annotations[key]; ok {
			return val
		}
	}
	for _, key := range labelNames {
		if val, ok := om.Labels[key]; ok {
			return val
		}
	}
	return ""
}

// ServiceNameNamespaceForIP returns the service name and namespace for a given IP address
// This means that, for a given Pod, we will not return the Pod Name, but the Pod Owner Name
func (s *Store) ServiceNameNamespaceForIP(ip string) (string, string) {
	s.access.RLock()
	if serviceInfo, ok := s.otelServiceInfoByIP[ip]; ok {
		s.access.RUnlock()
		return serviceInfo.Name, serviceInfo.Namespace
	}
	s.access.RUnlock()

	s.access.Lock()
	defer s.access.Unlock()

	name, namespace := "", ""
	if om, ok := s.objectMetaByIP[ip]; ok {
		name, namespace = s.serviceNameNamespaceForMetadata(om)
	}

	s.otelServiceInfoByIP[ip] = OTelServiceNamePair{Name: name, Namespace: namespace}

	return name, namespace
}

func (s *Store) serviceNameNamespaceOwnerID(om *informer.ObjectMeta, ownerName string) (string, string) {
	// ownerName can be the top Owner name, or om.Name in case it's a pod without owner
	serviceName := ownerName
	serviceNamespace := om.Namespace
	ownerKey := ownerID(serviceNamespace, serviceName)

	// OTEL_SERVICE_NAME and OTEL_SERVICE_NAMESPACE variables take precedence over user-configured annotations
	// and labels
	if envName, ok := s.serviceNameFromEnv(ownerKey); ok {
		serviceName = envName
	} else if nameFromMeta := s.valueFromMetadata(om,
		s.metadataSources.Annotations.ServiceName,
		s.metadataSources.Labels.ServiceName,
	); nameFromMeta != "" {
		serviceName = nameFromMeta
	}
	if envName, ok := s.serviceNamespaceFromEnv(ownerKey); ok {
		serviceNamespace = envName
	} else if nsFromMeta := s.valueFromMetadata(om,
		s.metadataSources.Annotations.ServiceNamespace,
		s.metadataSources.Labels.ServiceNamespace,
	); nsFromMeta != "" {
		serviceNamespace = nsFromMeta
	}

	return serviceName, serviceNamespace
}

func (s *Store) nameFromResourceAttrs(variable string, c *informer.ContainerInfo) (string, bool) {
	if resourceVars, ok := c.Env[meta.EnvResourceAttrs]; ok {
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
			if serviceName, ok := c.Env[meta.EnvServiceName]; ok {
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
		if err := observer.On(&informer.Event{Type: informer.EventType_CREATED, Resource: pod}); err != nil {
			s.log.Debug("observer failed sending Pod info. Unsubscribing it", "observer", observer.ID(), "error", err)
			s.BaseNotifier.Unsubscribe(observer)
			return
		}
	}
	// the IPInfos could contain IPInfo data from Pods already sent in the previous loop
	// is the subscriber the one that should decide whether to ignore such duplicates or
	// incomplete info
	for _, ips := range s.objectMetaByIP {
		if err := observer.On(&informer.Event{Type: informer.EventType_CREATED, Resource: ips}); err != nil {
			s.log.Debug("observer failed sending Object Meta. Unsubscribing it", "observer", observer.ID(), "error", err)
			s.BaseNotifier.Unsubscribe(observer)
			return
		}
	}
}
