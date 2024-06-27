package transform

import (
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
}

func KubeDecoratorProvider(ctxInfo *global.ContextInfo) pipe.MiddleProvider[[]request.Span, []request.Span] {
	return func() (pipe.MiddleFunc[[]request.Span, []request.Span], error) {
		if !ctxInfo.K8sInformer.IsKubeEnabled() {
			// if kubernetes decoration is disabled, we just bypass the node
			return pipe.Bypass[[]request.Span](), nil
		}
		decorator := &metadataDecorator{db: ctxInfo.AppO11y.K8sDatabase}
		return decorator.nodeLoop, nil
	}
}

// production implementer: kube.Database
type kubeDatabase interface {
	OwnerPodInfo(pidNamespace uint32) (*kube.PodInfo, bool)
	HostNameForIP(ip string) string
}

type metadataDecorator struct {
	db kubeDatabase
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
		appendMetadata(span, podInfo)
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

func appendMetadata(span *request.Span, info *kube.PodInfo) {
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
	}
	owner := info.Owner
	for owner != nil {
		span.ServiceID.Metadata[attr.Name(owner.LabelName)] = owner.Name
		owner = owner.Owner
	}
}
