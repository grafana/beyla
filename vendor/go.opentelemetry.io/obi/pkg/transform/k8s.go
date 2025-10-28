// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package transform

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"sync"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/helpers/container"
	maps2 "go.opentelemetry.io/obi/pkg/internal/helpers/maps"
	ikube "go.opentelemetry.io/obi/pkg/internal/kube"
	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
	"go.opentelemetry.io/obi/pkg/kube/kubeflags"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
)

var containerInfoForPID = container.InfoForPID

func klog() *slog.Logger {
	return slog.With("component", "transform.KubernetesDecorator")
}

type KubernetesDecorator struct {
	Enable kubeflags.EnableFlag `yaml:"enable" env:"OTEL_EBPF_KUBE_METADATA_ENABLE"`

	// ClusterName overrides cluster name. If empty, the NetO11y module will try to retrieve
	// it from the Cloud Provider Metadata (EC2, GCP and Azure), and leave it empty if it fails to.
	ClusterName string `yaml:"cluster_name" env:"OTEL_EBPF_KUBE_CLUSTER_NAME"`

	// KubeconfigPath is optional. If unset, it will look in the usual location.
	KubeconfigPath string `yaml:"kubeconfig_path" env:"KUBECONFIG"`

	InformersSyncTimeout time.Duration `yaml:"informers_sync_timeout" env:"OTEL_EBPF_KUBE_INFORMERS_SYNC_TIMEOUT"`

	// InformersResyncPeriod defaults to 30m. Higher values will reduce the load on the Kube API.
	InformersResyncPeriod time.Duration `yaml:"informers_resync_period" env:"OTEL_EBPF_KUBE_INFORMERS_RESYNC_PERIOD"`

	// DropExternal will drop, in NetO11y component, any flow where the source or destination
	// IPs are not matched to any kubernetes entity, assuming they are cluster-external
	DropExternal bool `yaml:"drop_external" env:"OTEL_EBPF_NETWORK_DROP_EXTERNAL"`

	// DisableInformers allows selectively disabling some informers. Accepted value is a list
	// that might contain node or service. Disabling any of them
	// will cause metadata to be incomplete but will reduce the load of the Kube API.
	// Pods informer can't be disabled. For that purpose, you should disable the whole
	// kubernetes metadata decoration.
	DisableInformers []string `yaml:"disable_informers" env:"OTEL_EBPF_KUBE_DISABLE_INFORMERS"`

	// MetaCacheAddress is the host:port address of the beyla-k8s-cache service instance
	MetaCacheAddress string `yaml:"meta_cache_address" env:"OTEL_EBPF_KUBE_META_CACHE_ADDRESS"`

	// MetaRestrictLocalNode will download only the metadata from the Pods that are located in the same
	// node as the Beyla instance. It will also restrict the Node information to the local node.
	MetaRestrictLocalNode bool `yaml:"meta_restrict_local_node" env:"OTEL_EBPF_KUBE_META_RESTRICT_LOCAL_NODE"`

	// MetaSourceLabels allows Beyla overriding the service name and namespace of an application from
	// the given labels.
	// Deprecated: kept for backwards-compatibility with Beyla 1.9
	MetaSourceLabels kube.MetaSourceLabels `yaml:"meta_source_labels"`

	// ResourceLabels allows Beyla overriding the OTEL Resource attributes from a map of user-defined labels.
	ResourceLabels kube.ResourceLabels `yaml:"resource_labels"`

	// ServiceNameTemplate allows to override the service.name with a custom value. Uses the go template language.
	ServiceNameTemplate string `yaml:"service_name_template" env:"OTEL_EBPF_SERVICE_NAME_TEMPLATE"`
}

const (
	clusterMetadataRetries       = 5
	clusterMetadataFailRetryTime = 500 * time.Millisecond
)

func KubeDecoratorProvider(
	ctxInfo *global.ContextInfo,
	cfg *KubernetesDecorator,
	input, output *msg.Queue[[]request.Span],
) swarm.InstanceFunc {
	return func(ctx context.Context) (swarm.RunFunc, error) {
		if !ctxInfo.K8sInformer.IsKubeEnabled() {
			// if kubernetes decoration is disabled, we just bypass the node
			return swarm.Bypass(input, output)
		}
		metaStore, err := ctxInfo.K8sInformer.Get(ctx)
		if err != nil {
			return nil, fmt.Errorf("initializing KubeDecoratorProvider: %w", err)
		}
		decorator := &metadataDecorator{
			db:          metaStore,
			clusterName: KubeClusterName(ctx, cfg, ctxInfo.K8sInformer),
			input:       input.Subscribe(msg.SubscriberName("transform.KubeDecorator")),
			output:      output,
		}
		return decorator.nodeLoop, nil
	}
}

func KubeProcessEventDecoratorProvider(
	ctxInfo *global.ContextInfo,
	cfg *KubernetesDecorator,
	input, output *msg.Queue[exec.ProcessEvent],
) swarm.InstanceFunc {
	return func(ctx context.Context) (swarm.RunFunc, error) {
		if !ctxInfo.K8sInformer.IsKubeEnabled() {
			return swarm.Bypass(input, output)
		}
		metaStore, err := ctxInfo.K8sInformer.Get(ctx)
		if err != nil {
			return nil, fmt.Errorf("initializing KubeDecoratorProvider: %w", err)
		}

		decorator := &procEventMetadataDecorator{
			log:         slog.With("component", "transform.KubeProcessEventDecoratorProvider"),
			db:          metaStore,
			clusterName: KubeClusterName(ctx, cfg, ctxInfo.K8sInformer),
			input:       input.Subscribe(msg.SubscriberName("transform.KubeProcessEventDecorator")),
			output:      output,
			podsInfoCh:  make(chan Event[*informer.ObjectMeta]),
			tracker:     newPidContainerTracker(),
		}

		decorator.log.Debug("starting KubeDecoratorProvider")
		return decorator.k8sLoop, nil
	}
}

type metadataDecorator struct {
	db          *kube.Store
	clusterName string
	input       <-chan []request.Span
	output      *msg.Queue[[]request.Span]
}

func (md *metadataDecorator) nodeLoop(ctx context.Context) {
	// output channel must be closed so later stages in the pipeline can finish in cascade
	defer md.output.Close()
	swarms.ForEachInput(ctx, md.input, klog().Debug, func(spans []request.Span) {
		// in-place decoration and forwarding
		for i := range spans {
			md.do(&spans[i])
		}
		md.output.Send(spans)
	})
}

func (md *metadataDecorator) do(span *request.Span) {
	if podMeta, containerName := md.db.PodContainerByPIDNs(span.Pid.Namespace); podMeta != nil {
		AppendKubeMetadata(md.db, &span.Service, podMeta, md.clusterName, containerName)
	} else {
		// do not leave the service attributes map as nil
		span.Service.Metadata = map[attr.Name]string{}
	}
	// override the peer and host names from Kubernetes metadata, if found
	if span.Host != "" {
		if name, _ := md.db.ServiceNameNamespaceForIP(span.Host); name != "" {
			span.HostName = name
		}
	}
	if span.Peer != "" {
		if name, _ := md.db.ServiceNameNamespaceForIP(span.Peer); name != "" {
			span.PeerName = name
		}
	}
}

type PodEventType int

const (
	EventCreated = PodEventType(iota)
	EventDeleted
	EventInstanceDeleted
)

type Event[T any] struct {
	Type PodEventType
	Obj  T
}

type procEventMetadataDecorator struct {
	log         *slog.Logger
	db          *kube.Store
	clusterName string
	input       <-chan exec.ProcessEvent
	output      *msg.Queue[exec.ProcessEvent]
	podsInfoCh  chan Event[*informer.ObjectMeta]
	tracker     *pidContainerTracker
}

type pidContainerTracker struct {
	missedPods    maps2.Map2[string, int32, *exec.ProcessEvent]
	missedPodsMux sync.Mutex
	missedPodPids map[int32]string
}

func newPidContainerTracker() *pidContainerTracker {
	return &pidContainerTracker{
		missedPods:    maps2.Map2[string, int32, *exec.ProcessEvent]{},
		missedPodsMux: sync.Mutex{},
		missedPodPids: map[int32]string{},
	}
}

func (t *pidContainerTracker) track(containerID string, pe *exec.ProcessEvent) {
	if pe == nil {
		return
	}
	t.missedPodsMux.Lock()
	defer t.missedPodsMux.Unlock()
	t.missedPods.Put(containerID, pe.File.Pid, pe)
	t.missedPodPids[pe.File.Pid] = containerID
}

func (t *pidContainerTracker) remove(pid int32) {
	t.missedPodsMux.Lock()
	defer t.missedPodsMux.Unlock()
	if containerID, ok := t.missedPodPids[pid]; ok {
		t.missedPods.Delete(containerID, pid)
	}
	delete(t.missedPodPids, pid)
}

func (t *pidContainerTracker) removeAll(containerID string) {
	t.missedPodsMux.Lock()
	defer t.missedPodsMux.Unlock()

	if pids, exists := t.missedPods[containerID]; exists {
		for pid := range pids {
			delete(t.missedPodPids, pid)
		}
	}

	t.missedPods.DeleteAll(containerID)
}

func (t *pidContainerTracker) info(containerID string) (map[int32]*exec.ProcessEvent, bool) {
	t.missedPodsMux.Lock()
	defer t.missedPodsMux.Unlock()

	m, ok := t.missedPods[containerID]

	return m, ok
}

func (md *procEventMetadataDecorator) ID() string { return "unique-proc-event-metadata-decorator-id" }

func (md *procEventMetadataDecorator) On(event *informer.Event) error {
	// ignoring updates on non-pod resources
	if event.Resource == nil || event.GetResource().GetPod() == nil {
		return nil
	}
	switch event.Type {
	case informer.EventType_CREATED, informer.EventType_UPDATED:
		md.podsInfoCh <- Event[*informer.ObjectMeta]{Type: EventCreated, Obj: event.Resource}
	case informer.EventType_DELETED:
		md.podsInfoCh <- Event[*informer.ObjectMeta]{Type: EventDeleted, Obj: event.Resource}
	}
	return nil
}

func (md *procEventMetadataDecorator) k8sLoop(ctx context.Context) {
	// output channel must be closed so later stages in the pipeline can finish in cascade
	defer md.output.Close()

	md.log.Debug("starting kubernetes process event decoration loop")
	go md.db.Subscribe(md)

mainLoop:
	for {
		select {
		case <-ctx.Done():
			break mainLoop
		case pe, ok := <-md.input:
			if !ok {
				break mainLoop
			}
			md.log.Debug("annotating process event", "event", pe)

			if podMeta, containerName := md.db.PodContainerByPIDNs(pe.File.Ns); podMeta != nil {
				AppendKubeMetadata(md.db, &pe.File.Service, podMeta, md.clusterName, containerName)
			} else {
				// do not leave the service attributes map as nil
				pe.File.Service.Metadata = map[attr.Name]string{}

				md.log.Debug("no metadata for event", "event", pe)

				if pe.Type == exec.ProcessEventCreated {
					if containerInfo, err := md.getContainerInfo(pe.File.Pid); err == nil {
						md.log.Debug("storing pid info", "pid", pe.File.Pid, "containerId", containerInfo.ContainerID)
						md.tracker.track(containerInfo.ContainerID, &pe)
					}
				} else {
					md.tracker.remove(pe.File.Pid)
				}
			}

			// in-place decoration and forwarding
			md.output.Send(pe)
		case podEvent := <-md.podsInfoCh:
			switch podEvent.Type {
			case EventCreated:
				md.log.Debug("created pod event", "event", podEvent.Obj)
				md.handlePodUpdateEvent(podEvent.Obj)
			case EventDeleted:
				md.cleanupPodData(podEvent.Obj)
				md.log.Debug("deleted pod event", "event", podEvent.Obj)
			}
		}
	}

	md.log.Debug("stopping kubernetes process event decoration loop")
}

func (md *procEventMetadataDecorator) getContainerInfo(pid int32) (container.Info, error) {
	cntInfo, err := containerInfoForPID(uint32(pid))
	if err != nil {
		return container.Info{}, err
	}
	return cntInfo, nil
}

func (md *procEventMetadataDecorator) handlePodUpdateEvent(pod *informer.ObjectMeta) {
	for _, cnt := range pod.Pod.Containers {
		md.log.Debug("looking up running process for pod container", "container", cnt.Id)
		if peMap, ok := md.tracker.info(cnt.Id); ok {
			md.log.Debug("found missed pid info", "containerId", cnt.Id)
			for _, pe := range peMap {
				if podMeta, containerName := md.db.PodContainerByPIDNs(pe.File.Ns); podMeta != nil {
					md.log.Debug("resubmitting process event", "event", pe)
					AppendKubeMetadata(md.db, &pe.File.Service, podMeta, md.clusterName, containerName)
					md.output.Send(*pe)
				}
			}
			md.tracker.removeAll(cnt.Id)
		}
	}
}

func (md *procEventMetadataDecorator) cleanupPodData(pod *informer.ObjectMeta) {
	for _, cnt := range pod.Pod.Containers {
		md.log.Debug("deleting info for pod container", "container", cnt.Id)
		md.tracker.removeAll(cnt.Id)
	}
}

// AppendKubeMetadata populates some metadata values in the passed svc.Attrs.
// This method should be invoked by any entity willing to follow a common policy for
// setting metadata attributes. For example this metadataDecorator or the survey informer
func AppendKubeMetadata(db *kube.Store, svc *svc.Attrs, meta *ikube.CachedObjMeta, clusterName, containerName string) {
	if meta.Meta.Pod == nil {
		// if this message happen, there is a bug
		klog().Debug("pod metadata for is nil. Ignoring decoration", "meta", meta)
		return
	}
	topOwner := ikube.TopOwner(meta.Meta.Pod)
	name, namespace := db.ServiceNameNamespaceForMetadata(meta.Meta, containerName)
	// If the user has not defined criteria values for the reported
	// service name and namespace, we will automatically set it from
	// the kubernetes metadata
	if svc.AutoName() {
		svc.UID.Name = name
	}
	if svc.UID.Namespace == "" {
		svc.UID.Namespace = namespace
	}
	// overriding the Instance here will avoid reusing the OTEL resource reporter
	// if the application/process was discovered and reported information
	// before the kubernetes metadata was available
	// (related issue: https://github.com/grafana/beyla/issues/1124)
	// Service Instance ID is set according to OTEL collector conventions:
	// (related issue: https://github.com/grafana/k8s-monitoring-helm/issues/942)
	svc.UID.Instance = meta.Meta.Namespace + "." + meta.Meta.Name + "." + containerName

	// if, in the future, other pipeline steps modify the service metadata, we should
	// replace the map literal by individual entry insertions
	svc.Metadata = map[attr.Name]string{
		attr.K8sNamespaceName: meta.Meta.Namespace,
		attr.K8sPodName:       meta.Meta.Name,
		attr.K8sContainerName: containerName,
		attr.K8sNodeName:      meta.Meta.Pod.NodeName,
		attr.K8sPodUID:        meta.Meta.Pod.Uid,
		attr.K8sPodStartTime:  meta.Meta.Pod.StartTimeStr,
		attr.K8sClusterName:   clusterName,
	}

	// ownerKind could be also "Pod", but we won't insert it as "owner" label to avoid
	// growing cardinality
	if topOwner != nil {
		svc.Metadata[attr.K8sOwnerName] = topOwner.Name
		svc.Metadata[attr.K8sKind] = topOwner.Kind
	}

	for _, owner := range meta.Meta.Pod.Owners {
		if _, ok := svc.Metadata[attr.K8sKind]; !ok {
			svc.Metadata[attr.K8sKind] = owner.Kind
		}
		if kindLabel := OwnerLabelName(owner.Kind); kindLabel != "" {
			svc.Metadata[kindLabel] = owner.Name
		}
	}

	// append resource metadata from cached object
	maps.Copy(svc.Metadata, meta.OTELResourceMeta)

	// override hostname by the Pod name
	svc.HostName = meta.Meta.Name
}

func OwnerLabelName(kind string) attr.Name {
	switch kind {
	case "Deployment":
		return attr.K8sDeploymentName
	case "StatefulSet":
		return attr.K8sStatefulSetName
	case "DaemonSet":
		return attr.K8sDaemonSetName
	case "ReplicaSet":
		return attr.K8sReplicaSetName
	case "Job":
		return attr.K8sJobName
	case "CronJob":
		return attr.K8sCronJobName
	default:
		return ""
	}
}

func KubeClusterName(ctx context.Context, cfg *KubernetesDecorator, k8sInformer *kube.MetadataProvider) string {
	log := klog().With("func", "KubeClusterName")
	if cfg.ClusterName != "" {
		log.Debug("using cluster name from configuration", "cluster_name", cfg.ClusterName)
		return cfg.ClusterName
	}
	retries := 0
	for retries < clusterMetadataRetries {
		if clusterName := fetchClusterName(ctx, k8sInformer); clusterName != "" {
			return clusterName
		}
		retries++
		log.Debug("retrying cluster name fetching in 500 ms...")
		select {
		case <-ctx.Done():
			log.Debug("context canceled before starting the kubernetes decorator node")
			return ""
		case <-time.After(clusterMetadataFailRetryTime):
			// retry or end!
		}
	}
	log.Warn("can't fetch Kubernetes Cluster Name." +
		" Network metrics won't contain k8s.cluster.name attribute unless you explicitly set " +
		" the OTEL_EBPF_KUBE_CLUSTER_NAME environment variable")
	return ""
}
