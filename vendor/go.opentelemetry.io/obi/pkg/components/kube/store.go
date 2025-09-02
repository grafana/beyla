// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kube

import (
	"bytes"
	"iter"
	"log/slog"
	gomaps "maps"
	"slices"
	"strings"
	"sync"
	"text/template"

	"go.opentelemetry.io/obi/pkg/components/helpers/container"
	"go.opentelemetry.io/obi/pkg/components/helpers/maps"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/kubecache/informer"
	"go.opentelemetry.io/obi/pkg/kubecache/meta"
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

// MetaSourceLabels allow overriding some metadata from kubernetes labels
// Deprecated. Left here for backwards-compatibility.
type MetaSourceLabels struct {
	ServiceName      string `yaml:"service_name" env:"OTEL_EBPF_KUBE_META_SOURCE_LABEL_SERVICE_NAME"`
	ServiceNamespace string `yaml:"service_namespace" env:"OTEL_EBPF_KUBE_META_SOURCE_LABEL_SERVICE_NAMESPACE"`
}

type ResourceLabels map[string][]string

const (
	ResourceAttributesPrefix   = "resource.opentelemetry.io/"
	ServiceNameAnnotation      = ResourceAttributesPrefix + serviceNameKey
	ServiceNamespaceAnnotation = ResourceAttributesPrefix + serviceNamespaceKey

	EnvResourceAttributes = "OTEL_RESOURCE_ATTRIBUTES"
	EnvServiceName        = "OTEL_SERVICE_NAME"
	EnvServiceNamespace   = "OTEL_SERVICE_NAMESPACE"
)

var DefaultResourceLabels = ResourceLabels{
	// If a user sets useLabelsForResourceAttributes: false in its OTEL operator config, is the task of the
	// OTEL operator to provide empty values for this.
	"service.name":      []string{"app.kubernetes.io/name"},
	"service.namespace": []string{"app.kubernetes.io/part-of"},
	"service.version":   []string{"app.kubernetes.io/version"},
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
	podsByContainer map[string]*CachedObjMeta
	// first key: pod owner ID, second key: container ID
	containersByOwner maps.Map2[string, string, *informer.ContainerInfo]

	// ip to generic IP info (Node, Service, *including* Pods)
	objectMetaByIP map[string]*CachedObjMeta
	// used to track the changed/removed IPs of a given object
	// and remove them from objectMetaByIP on update or deletion
	objectMetaByQName map[qualifiedName]*CachedObjMeta
	// todo: can be probably removed as objectMetaByIP already caches the service name/namespace
	otelServiceInfoByIP map[string]OTelServiceNamePair

	// Instead of subscribing to the informer directly, the rest of components
	// will subscribe to this store, to make sure that any "new object" notification
	// they receive is already present in the store
	meta.BaseNotifier

	resourceLabels ResourceLabels

	// A go template that, if set, is used to create the service name
	serviceNameTemplate *template.Template
}

type CachedObjMeta struct {
	Meta             *informer.ObjectMeta
	OTELResourceMeta map[attr.Name]string
}

func NewStore(kubeMetadata meta.Notifier, resourceLabels ResourceLabels, serviceNameTemplate *template.Template) *Store {
	log := dblog()

	db := &Store{
		log:                 log,
		containerIDs:        map[string]*container.Info{},
		namespaces:          map[uint32]*container.Info{},
		podsByContainer:     map[string]*CachedObjMeta{},
		containerByPID:      map[uint32]*container.Info{},
		objectMetaByIP:      map[string]*CachedObjMeta{},
		objectMetaByQName:   map[qualifiedName]*CachedObjMeta{},
		containersByOwner:   maps.Map2[string, string, *informer.ContainerInfo]{},
		otelServiceInfoByIP: map[string]OTelServiceNamePair{},
		metadataNotifier:    kubeMetadata,
		BaseNotifier:        meta.NewBaseNotifier(log),
		resourceLabels:      resourceLabels,
		serviceNameTemplate: serviceNameTemplate,
	}
	kubeMetadata.Subscribe(db)
	return db
}

func (s *Store) ID() string { return "unique-metadata-observer" }

// cacheResourceMetadata extracts the resource attribute from different standard OTEL sources, in order of preference:
// 1. Resource attributes set via OTEL_RESOURCE_ATTRIBUTES and OTEL_SERVICE_NAME* environment variables
// 2. Resource attributes set via annotations (with the resource.opentelemetry.io/ prefix)
// 3. Resource attributes set via labels (e.g. app.kubernetes.io/name)
func (s *Store) cacheResourceMetadata(meta *informer.ObjectMeta) *CachedObjMeta {
	// store metadata from labels, if set
	com := CachedObjMeta{
		Meta:             meta,
		OTELResourceMeta: map[attr.Name]string{},
	}
	if len(meta.Labels) > 0 {
		for propertyName, labels := range s.resourceLabels {
			for _, label := range labels {
				if val := meta.Labels[label]; val != "" {
					com.OTELResourceMeta[attr.Name(propertyName)] = val
					break
				}
			}
		}
	}
	// override with metadata from annotations
	for labelName, labelValue := range meta.Annotations {
		if !strings.HasPrefix(labelName, ResourceAttributesPrefix) {
			continue
		}
		propertyName := labelName[len(ResourceAttributesPrefix):]
		com.OTELResourceMeta[attr.Name(propertyName)] = labelValue
	}
	// override with metadata from OTEL_RESOURCE_ATTRIBUTES, OTEL_SERVICE_NAME and OTEL_SERVICE_NAMESPACE
	for _, cnt := range meta.GetPod().GetContainers() {
		if len(cnt.Env) == 0 {
			continue
		}
		attributes.ParseOTELResourceVariable(cnt.Env[EnvResourceAttributes], func(k, v string) {
			com.OTELResourceMeta[attr.Name(k)] = v
		})
		if val := cnt.Env[EnvServiceName]; val != "" {
			com.OTELResourceMeta[serviceNameKey] = val
		}
		if val := cnt.Env[EnvServiceNamespace]; val != "" {
			com.OTELResourceMeta[serviceNamespaceKey] = val
		}
	}

	return &com
}

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
	s.Notify(event)
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
		s.unlockedDeleteObjectMeta(previousObject.Meta)
	}
	s.unlockedAddObjectMeta(meta)
}

// it's important to make sure that any element added here is removed when
// calling unlockedDeleteObjectMeta with the same ObjectMeta
func (s *Store) unlockedAddObjectMeta(meta *informer.ObjectMeta) {
	cmeta := s.cacheResourceMetadata(meta)
	qn := qName(meta)
	s.objectMetaByQName[qn] = cmeta

	for _, ip := range meta.Ips {
		s.objectMetaByIP[ip] = cmeta
	}

	s.otelServiceInfoByIP = map[string]OTelServiceNamePair{}

	if meta.Pod != nil {
		oID := fetchOwnerID(meta)
		s.log.Debug("adding pod to store",
			"ips", meta.Ips, "pod", meta.Name, "namespace", meta.Namespace, "containers", meta.Pod.Containers)
		for _, c := range meta.Pod.Containers {
			s.podsByContainer[c.Id] = cmeta
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
		s.unlockedDeleteObjectMeta(previousObject.Meta)
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

func (s *Store) PodByContainerID(cid string) *CachedObjMeta {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.podsByContainer[cid]
}

// PodContainerByPIDNs second return value: container Name
func (s *Store) PodContainerByPIDNs(pidns uint32) (*CachedObjMeta, string) {
	s.access.RLock()
	defer s.access.RUnlock()
	if info, ok := s.namespaces[pidns]; ok {
		if om, ok := s.podsByContainer[info.ContainerID]; ok {
			oID := fetchOwnerID(om.Meta)
			containerName := ""
			if containerInfo, ok := s.containersByOwner.Get(oID, info.ContainerID); ok {
				containerName = containerInfo.Name
			}
			return om, containerName
		}
	}
	return nil, ""
}

func (s *Store) ObjectMetaByIP(ip string) *CachedObjMeta {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.objectMetaByIP[ip]
}

func (s *Store) ServiceNameNamespaceForMetadata(om *informer.ObjectMeta, containerName string) (string, string) {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.serviceNameNamespaceOwnerID(om, containerName)
}

// function implemented to provide consistent service metadata naming across multiple
// OTEL implementations: OTEL operator, Loki and Beyla
// https://github.com/grafana/k8s-monitoring-helm/issues/942
func (s *Store) valueFromMetadata(om *informer.ObjectMeta, annotationName string, labelNames []string) string {
	// if this object meta is not a pod, we ignore the metadata
	if om.Pod == nil {
		return ""
	}
	if val, ok := om.Annotations[annotationName]; ok {
		return val
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
		name, namespace = s.serviceNameNamespaceOwnerID(om.Meta, "")
	}

	s.otelServiceInfoByIP[ip] = OTelServiceNamePair{Name: name, Namespace: namespace}

	return name, namespace
}

// serviceNameNamespaceOwnerID takes service name and namespace from diverse sources according to the
// OTEL specification: https://github.com/open-telemetry/opentelemetry-operator/blob/main/README.md
// 1. Resource attributes set via OTEL_RESOURCE_ATTRIBUTES and OTEL_SERVICE_NAME environment variables
// 2. Resource attributes set via annotations (with the resource.opentelemetry.io/ prefix)
// 3. Resource attributes set via labels (e.g. app.kubernetes.io/name)
// 4. Resource attributes calculated from the owner's metadata (e.g. k8s.deployment.name) or pod's metadata (e.g. k8s.pod.name)
func (s *Store) serviceNameNamespaceOwnerID(om *informer.ObjectMeta, containerName string) (string, string) {
	// ownerName can be the top Owner name, or om.Name in case it's a pod without owner
	serviceName := om.Name
	serviceNamespace := om.Namespace

	// OTEL_SERVICE_NAME and OTEL_SERVICE_NAMESPACE variables take precedence over user-configured annotations
	// and labels
	if envName, ok := s.serviceNameFromEnv(om, containerName); ok {
		serviceName = envName
	} else if s.serviceNameTemplate != nil {
		// defining a serviceNameTemplate disables the resolution via annotation + label (this can be implemented in the template)
		var serviceNameBuffer bytes.Buffer
		ctx := struct {
			Meta          *informer.ObjectMeta
			ContainerName string
		}{
			Meta:          om,
			ContainerName: containerName,
		}
		err := s.serviceNameTemplate.Execute(&serviceNameBuffer, ctx)

		if err != nil {
			s.log.Error("error executing service name template", "error", err)
		} else {
			parts := strings.Split(serviceNameBuffer.String(), "\n")

			if len(parts) > 0 {
				// take only first line, and trim
				serviceName = strings.TrimSpace(parts[0])
			}
		}

	} else if nameFromMeta := s.valueFromMetadata(om,
		ServiceNameAnnotation,
		s.resourceLabels["service.name"],
	); nameFromMeta != "" {
		serviceName = nameFromMeta
	} else if own := TopOwner(om.Pod); own != nil {
		serviceName = own.Name
	}
	if envName, ok := s.serviceNamespaceFromEnv(om, containerName); ok {
		serviceNamespace = envName
	} else if nsFromMeta := s.valueFromMetadata(om,
		ServiceNamespaceAnnotation,
		s.resourceLabels["service.namespace"],
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

// if the object is not a pod, we would need to dig into the internal owner:containers store
func (s *Store) containersFor(om *informer.ObjectMeta) iter.Seq[*informer.ContainerInfo] {
	if om.Pod != nil {
		return slices.Values(om.Pod.Containers)
	}
	return gomaps.Values(s.containersByOwner[ownerID(om.Namespace, om.Name)])
}

func (s *Store) serviceNameFromEnv(om *informer.ObjectMeta, containerName string) (string, bool) {
	// for eBPF application data, we know the container name.
	// However, when we only know the IP address (e.g. when we are checking the Peer address), we still
	// need to override the service name from the environment variables; otherwise service graph metrics
	// won't be consistent with the rest of application metrics.
	// If the container is empty and the pod has multiple containers, we will pickup the last matching
	// environment variable overriding the service name.
	// There is a known limitation with this approach: if a pod has multiple containers defining
	// OTEL_SERVICE_NAME with different values, we might get the wrong service name.
	// However, this looks as an edge case that shouldn't happen in practice.
	for c := range s.containersFor(om) {
		if containerName == "" || c.Name == containerName {
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

func (s *Store) serviceNamespaceFromEnv(om *informer.ObjectMeta, containerName string) (string, bool) {
	// when containerName is empty, we will follow the same assumption as serviceNameFromEnv
	for c := range s.containersFor(om) {
		if containerName == "" || c.Name == containerName {
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
		if err := observer.On(&informer.Event{Type: informer.EventType_CREATED, Resource: pod.Meta}); err != nil {
			s.log.Debug("observer failed sending Pod info. Unsubscribing it", "observer", observer.ID(), "error", err)
			s.Unsubscribe(observer)
			return
		}
	}
	// the IPInfos could contain IPInfo data from Pods already sent in the previous loop
	// is the subscriber the one that should decide whether to ignore such duplicates or
	// incomplete info
	for _, ips := range s.objectMetaByIP {
		if err := observer.On(&informer.Event{Type: informer.EventType_CREATED, Resource: ips.Meta}); err != nil {
			s.log.Debug("observer failed sending Object Meta. Unsubscribing it", "observer", observer.ID(), "error", err)
			s.Unsubscribe(observer)
			return
		}
	}
}
