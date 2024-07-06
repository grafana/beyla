package transform

import (
	"context"
	"log/slog"
	"time"

	"github.com/mariomac/pipes/pipe"

	attr "github.com/grafana/beyla/pkg/internal/export/attributes/names"
	"github.com/grafana/beyla/pkg/internal/kube"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/svc"
)

func klog() *slog.Logger {
	return slog.With("component", "transform.KubernetesDecorator")
}

type KubernetesDecorator struct {
	Enable kube.EnableFlag `yaml:"enable" env:"BEYLA_KUBE_METADATA_ENABLE"`

	// ClusterName overrides cluster name. If empty, the NetO11y module will try to retrieve
	// it from the Cloud Provider Metadata (EC2, GCP and Azure), and leave it empty if it fails to.
	ClusterName string `yaml:"cluster_name" env:"BEYLA_KUBE_CLUSTER_NAME"`

	// KubeconfigPath is optional. If unset, it will look in the usual location.
	KubeconfigPath string `yaml:"kubeconfig_path" env:"KUBECONFIG"`

	InformersSyncTimeout time.Duration `yaml:"informers_sync_timeout" env:"BEYLA_KUBE_INFORMERS_SYNC_TIMEOUT"`

	// DropExternal will drop, in NetO11y component, any flow where the source or destination
	// IPs are not matched to any kubernetes entity, assuming they are cluster-external
	DropExternal bool `yaml:"drop_external" env:"BEYLA_NETWORK_DROP_EXTERNAL"`

	// DisableInformers allow selectively disabling some informers. Accepted value is a list
	// that mitght contain replicaset, node, service. Disabling any of them
	// will cause metadata to be incomplete but will reduce the load of the Kube API.
	// Pods informer can't be disabled. For that purpose, you should disable the whole
	// kubernetes metadata decoration.
	DisableInformers []string `yaml:"disable_informers" env:"BEYLA_KUBE_DISABLE_INFORMERS"`
}

const (
	clusterMetadataRetries       = 5
	clusterMetadataFailRetryTime = 500 * time.Millisecond
)

func KubeDecoratorProvider(
	ctx context.Context,
	cfg *KubernetesDecorator,
	ctxInfo *global.ContextInfo,
) pipe.MiddleProvider[[]request.Span, []request.Span] {
	return func() (pipe.MiddleFunc[[]request.Span, []request.Span], error) {
		if !ctxInfo.K8sInformer.IsKubeEnabled() {
			// if kubernetes decoration is disabled, we just bypass the node
			return pipe.Bypass[[]request.Span](), nil
		}
		decorator := &metadataDecorator{db: ctxInfo.AppO11y.K8sDatabase, clusterName: KubeClusterName(ctx, cfg)}
		return decorator.nodeLoop, nil
	}
}

// production implementer: kube.Database
type kubeDatabase interface {
	OwnerPodInfo(pidNamespace uint32) (*kube.PodInfo, bool)
	HostNameForIP(ip string) string
}

type metadataDecorator struct {
	db          kubeDatabase
	clusterName string
}

func (md *metadataDecorator) nodeLoop(in <-chan []request.Span, out chan<- []request.Span) {
	klog().Debug("starting kubernetes decoration loop")
	for spans := range in {
		// in-place decoration and forwarding
		for i := range spans {
			md.do(&spans[i])
		}
		out <- spans
	}
	klog().Debug("stopping kubernetes decoration loop")
}

func (md *metadataDecorator) do(span *request.Span) {
	if podInfo, ok := md.db.OwnerPodInfo(span.Pid.Namespace); ok {
		md.appendMetadata(span, podInfo)
	} else {
		// do not leave the service attributes map as nil
		span.ServiceID.Metadata = map[attr.Name]string{}
	}
	// override the peer and host names from Kubernetes metadata, if found
	if hn := md.db.HostNameForIP(span.Host); hn != "" {
		span.HostName = hn
	}
	if pn := md.db.HostNameForIP(span.Peer); pn != "" {
		span.PeerName = pn
	}
}

func (md *metadataDecorator) appendMetadata(span *request.Span, info *kube.PodInfo) {
	// If the user has not defined criteria values for the reported
	// service name and namespace, we will automatically set it from
	// the kubernetes metadata
	if span.ServiceID.AutoName {
		span.ServiceID.Name = info.ServiceName()
	}
	if span.ServiceID.Namespace == "" {
		span.ServiceID.Namespace = info.Namespace
	}
	span.ServiceID.UID = svc.UID(info.UID)

	// if, in the future, other pipeline steps modify the service metadata, we should
	// replace the map literal by individual entry insertions
	span.ServiceID.Metadata = map[attr.Name]string{
		attr.K8sNamespaceName: info.Namespace,
		attr.K8sPodName:       info.Name,
		attr.K8sNodeName:      info.NodeName,
		attr.K8sPodUID:        string(info.UID),
		attr.K8sPodStartTime:  info.StartTimeStr,
		attr.K8sClusterName:   md.clusterName,
	}
	owner := info.Owner
	for owner != nil {
		span.ServiceID.Metadata[attr.Name(owner.LabelName)] = owner.Name
		owner = owner.Owner
	}
	// override hostname by the Pod name
	span.ServiceID.HostName = info.Name
}

func KubeClusterName(ctx context.Context, cfg *KubernetesDecorator) string {
	log := klog().With("func", "KubeClusterName")
	if cfg.ClusterName != "" {
		return cfg.ClusterName
	}
	retries := 0
	for retries < clusterMetadataRetries {
		if clusterName := fetchClusterName(ctx); clusterName != "" {
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
