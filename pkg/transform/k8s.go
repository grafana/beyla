package transform

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"time"

	attr "github.com/grafana/beyla/v2/pkg/export/attributes/names"
	"github.com/grafana/beyla/v2/pkg/internal/exec"
	"github.com/grafana/beyla/v2/pkg/internal/kube"
	"github.com/grafana/beyla/v2/pkg/internal/pipe/global"
	"github.com/grafana/beyla/v2/pkg/internal/request"
	"github.com/grafana/beyla/v2/pkg/internal/svc"
	"github.com/grafana/beyla/v2/pkg/kubeflags"
	"github.com/grafana/beyla/v2/pkg/pipe/msg"
	"github.com/grafana/beyla/v2/pkg/pipe/swarm"
)

func klog() *slog.Logger {
	return slog.With("component", "transform.KubernetesDecorator")
}

type KubernetesDecorator struct {
	Enable kubeflags.EnableFlag `yaml:"enable" env:"BEYLA_KUBE_METADATA_ENABLE"`

	// K8sClusterName overrides cluster name. If empty, the NetO11y module will try to retrieve
	// it from the Cloud Provider Metadata (EC2, GCP and Azure), and leave it empty if it fails to.
	// nolint:undoc
	K8sClusterName string `yaml:"cluster_name" env:"BEYLA_KUBE_CLUSTER_NAME"`

	// KubeconfigPath is optional. If unset, it will look in the usual location.
	KubeconfigPath string `yaml:"kubeconfig_path" env:"KUBECONFIG"`

	InformersSyncTimeout time.Duration `yaml:"informers_sync_timeout" env:"BEYLA_KUBE_INFORMERS_SYNC_TIMEOUT"`

	// InformersResyncPeriod defaults to 30m. Higher values will reduce the load on the Kube API.
	InformersResyncPeriod time.Duration `yaml:"informers_resync_period" env:"BEYLA_KUBE_INFORMERS_RESYNC_PERIOD"`

	// DropExternal will drop, in NetO11y component, any flow where the source or destination
	// IPs are not matched to any kubernetes entity, assuming they are cluster-external
	// nolint:undoc
	DropExternal bool `yaml:"drop_external" env:"BEYLA_NETWORK_DROP_EXTERNAL"`

	// DisableInformers allows selectively disabling some informers. Accepted value is a list
	// that might contain node or service. Disabling any of them
	// will cause metadata to be incomplete but will reduce the load of the Kube API.
	// Pods informer can't be disabled. For that purpose, you should disable the whole
	// kubernetes metadata decoration.
	DisableInformers []string `yaml:"disable_informers" env:"BEYLA_KUBE_DISABLE_INFORMERS"`

	// MetaCacheAddress is the host:port address of the beyla-k8s-cache service instance
	// nolint:undoc
	MetaCacheAddress string `yaml:"meta_cache_address" env:"BEYLA_KUBE_META_CACHE_ADDRESS"`

	// MetaRestrictLocalNode will download only the metadata from the Pods that are located in the same
	// node as the Beyla instance. It will also restrict the Node information to the local node.
	MetaRestrictLocalNode bool `yaml:"meta_restrict_local_node" env:"BEYLA_KUBE_META_RESTRICT_LOCAL_NODE"`

	// MetaSourceLabels allows Beyla overriding the service name and namespace of an application from
	// the given labels.
	// Deprecated: kept for backwards-compatibility with Beyla 1.9
	MetaSourceLabels kube.MetaSourceLabels `yaml:"meta_source_labels"`

	// ResourceLabels allows Beyla overriding the OTEL Resource attributes from a map of user-defined labels.
	// nolint:undoc
	ResourceLabels kube.ResourceLabels `yaml:"resource_labels"`

	// ServiceNameTemplate allows to override the service.name with a custom value. Uses the go template language.
	ServiceNameTemplate string `yaml:"service_name_template" env:"BEYLA_SERVICE_NAME_TEMPLATE"`
}

const (
	clusterMetadataRetries       = 5
	clusterMetadataFailRetryTime = 500 * time.Millisecond
)

func KubeDecoratorProvider(
	ctxInfo *global.ContextInfo,
	clusterName string,
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
		decorator := &k8sMetadataDecorator{
			db:             metaStore,
			clusterName:    KubeClusterName(ctx, clusterName, cfg, ctxInfo.K8sInformer, false),
			k8sClusterName: KubeClusterName(ctx, clusterName, cfg, ctxInfo.K8sInformer, true),
			input:          input.Subscribe(),
			output:         output,
		}
		return decorator.nodeLoop, nil
	}
}

func KubeProcessEventDecoratorProvider(
	ctxInfo *global.ContextInfo,
	clusterName string,
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
			db:             metaStore,
			clusterName:    KubeClusterName(ctx, clusterName, cfg, ctxInfo.K8sInformer, false),
			k8sClusterName: KubeClusterName(ctx, clusterName, cfg, ctxInfo.K8sInformer, true),
			input:          input.Subscribe(),
			output:         output,
		}
		return decorator.k8sLoop, nil
	}
}

type k8sMetadataDecorator struct {
	db             *kube.Store
	clusterName    string
	k8sClusterName string
	input          <-chan []request.Span
	output         *msg.Queue[[]request.Span]
}

type procEventMetadataDecorator struct {
	db             *kube.Store
	clusterName    string
	k8sClusterName string
	input          <-chan exec.ProcessEvent
	output         *msg.Queue[exec.ProcessEvent]
}

func (md *k8sMetadataDecorator) nodeLoop(_ context.Context) {
	// output channel must be closed so later stages in the pipeline can finish in cascade
	defer md.output.Close()
	klog().Debug("starting kubernetes span decoration loop")
	for spans := range md.input {
		// in-place decoration and forwarding
		for i := range spans {
			md.do(&spans[i])
		}
		md.output.Send(spans)
	}
	klog().Debug("stopping kubernetes span decoration loop")
}

func (md *procEventMetadataDecorator) k8sLoop(_ context.Context) {
	// output channel must be closed so later stages in the pipeline can finish in cascade
	defer md.output.Close()
	klog().Debug("starting kubernetes process event decoration loop")
	for pe := range md.input {
		klog().Debug("annotating process event", "event", pe)

		if podMeta, containerName := md.db.PodContainerByPIDNs(pe.File.Ns); podMeta != nil {
			appendMetadata(
				md.db,
				&pe.File.Service,
				podMeta,
				md.clusterName,
				md.k8sClusterName,
				containerName,
			)
		} else {
			// do not leave the service attributes map as nil
			pe.File.Service.Metadata = map[attr.Name]string{}
		}

		// in-place decoration and forwarding
		md.output.Send(pe)
	}
	klog().Debug("stopping kubernetes process event decoration loop")
}

func (md *k8sMetadataDecorator) do(span *request.Span) {
	if podMeta, containerName := md.db.PodContainerByPIDNs(span.Pid.Namespace); podMeta != nil {
		appendMetadata(
			md.db,
			&span.Service,
			podMeta,
			md.clusterName,
			md.k8sClusterName,
			containerName,
		)
	} else {
		// do not leave the service attributes map as nil
		span.Service.Metadata = map[attr.Name]string{}
	}
	// override the peer and host names from Kubernetes metadata, if found
	if name, _ := md.db.ServiceNameNamespaceForIP(span.Host); name != "" {
		span.HostName = name
	}
	if name, _ := md.db.ServiceNameNamespaceForIP(span.Peer); name != "" {
		span.PeerName = name
	}
}

func appendMetadata(
	db *kube.Store,
	svc *svc.Attrs,
	meta *kube.CachedObjMeta,
	clusterName,
	k8sClusterName,
	containerName string,
) {
	if meta.Meta.Pod == nil {
		// if this message happen, there is a bug
		klog().Debug("pod metadata for is nil. Ignoring decoration", "meta", meta)
		return
	}
	topOwner := kube.TopOwner(meta.Meta.Pod)
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
		attr.K8sClusterName:   k8sClusterName,
		attr.ClusterName:      clusterName,
	}

	// ownerKind could be also "Pod", but we won't insert it as "owner" label to avoid
	// growing cardinality
	if topOwner != nil {
		svc.Metadata[attr.K8sOwnerName] = topOwner.Name
	}

	for _, owner := range meta.Meta.Pod.Owners {
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
	default:
		return ""
	}
}

func KubeClusterName(
	ctx context.Context,
	clusterName string,
	cfg *KubernetesDecorator,
	k8sInformer *kube.MetadataProvider,
	isLegacy bool,
) string {
	log := klog().With("func", "KubeClusterName")

	isK8sClusterNameNotEmpty := cfg.K8sClusterName != "" && isLegacy
	isClusterNameNotEmpty := clusterName != "" && !isLegacy
	if isK8sClusterNameNotEmpty || isClusterNameNotEmpty {
		return clusterNameFromConfig(cfg, clusterName, isLegacy)
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
		" the BEYLA_KUBE_CLUSTER_NAME environment variable")

	return ""
}

func clusterNameFromConfig(cfg *KubernetesDecorator, clusterName string, isLegacy bool) string {
	log := klog().With("func", "clusterNameFromConfig")

	if isLegacy {
		log.Debug("using k8s cluster name from configuration", "k8s_cluster_name", cfg.K8sClusterName)
		return cfg.K8sClusterName
	}

	log.Debug("using cluster name from configuration", "cluster_name", clusterName)
	return clusterName
}
