package transform

import (
	"log/slog"
	"strings"
	"time"

	"github.com/mariomac/pipes/pkg/graph/stage"
	"github.com/mariomac/pipes/pkg/node"

	"github.com/grafana/beyla/pkg/internal/kube"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
	"github.com/grafana/beyla/pkg/internal/request"
)

type KubeEnableFlag string

const (
	EnabledTrue       = KubeEnableFlag("true")
	EnabledFalse      = KubeEnableFlag("false")
	EnabledAutodetect = KubeEnableFlag("autodetect")
	EnabledDefault    = EnabledFalse

	// TODO: let the user decide which attributes to add, as in https://opentelemetry.io/docs/kubernetes/collector/components/#kubernetes-attributes-processor
	NamespaceName  = "k8s.namespace.name"
	PodName        = "k8s.pod.name"
	DeploymentName = "k8s.deployment.name"
	NodeName       = "k8s.node.name"
	PodUID         = "k8s.pod.uid"
	PodStartTime   = "k8s.pod.start_time"
)

func klog() *slog.Logger {
	return slog.With("component", "transform.KubernetesDecorator")
}

type KubernetesDecorator struct {
	Enable KubeEnableFlag `yaml:"enable" env:"BEYLA_KUBE_METADATA_ENABLE"`
	// KubeconfigPath is optional. If unset, it will look in the usual location.
	KubeconfigPath string `yaml:"kubeconfig_path" env:"KUBECONFIG"`

	InformersSyncTimeout time.Duration `yaml:"informers_sync_timeout" env:"BEYLA_KUBE_INFORMERS_SYNC_TIMEOUT"`
}

func (d KubernetesDecorator) Enabled() bool {
	switch strings.ToLower(string(d.Enable)) {
	case string(EnabledTrue):
		return true
	case string(EnabledFalse), "": // empty value is disabled
		return false
	case string(EnabledAutodetect):
		// We autodetect that we are in a kubernetes if we can properly load a K8s configuration file
		_, err := kube.LoadConfig(d.KubeconfigPath)
		if err != nil {
			klog().Debug("kubeconfig can't be detected. Assuming we are not in Kubernetes", "error", err)
			return false
		}
		return true
	default:
		klog().Warn("invalid value for Enable value. Ignoring stage", "value", d.Enable)
		return false
	}
}

func KubeDecoratorProvider(
	ctxInfo *global.ContextInfo,
) stage.MiddleProvider[KubernetesDecorator, []request.Span, []request.Span] {
	return func(cfg KubernetesDecorator) (node.MiddleFunc[[]request.Span, []request.Span], error) {
		decorator := &metadataDecorator{db: ctxInfo.K8sDatabase}
		return decorator.nodeLoop, nil
	}
}

// production implementer: kube.Database
type kubeDatabase interface {
	OwnerPodInfo(pidNamespace uint32) (*kube.PodInfo, bool)
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
	if span.Metadata == nil {
		span.Metadata = make(map[string]string, 5)
	}
	if podInfo, ok := md.db.OwnerPodInfo(span.Pid.Namespace); ok {
		appendMetadata(span, podInfo)
	}
}

func appendMetadata(span *request.Span, info *kube.PodInfo) {
	// If the user has not defined criteria values for the reported
	// service name and namespace, we will automatically set it from
	// the kubernetes metadata
	if span.ServiceID.AutoName {
		if info.DeploymentName != "" {
			span.ServiceID.Name = info.DeploymentName
		} else if info.ReplicaSetName != "" {
			span.ServiceID.Name = info.ReplicaSetName
		} else {
			span.ServiceID.Name = info.Name
		}
	}
	if span.ServiceID.Namespace == "" {
		span.ServiceID.Namespace = info.Namespace
	}

	span.Metadata[NamespaceName] = info.Namespace
	span.Metadata[PodName] = info.Name
	span.Metadata[NodeName] = info.NodeName
	span.Metadata[PodUID] = string(info.UID)
	span.Metadata[PodStartTime] = info.StartTimeStr
	if info.DeploymentName != "" {
		span.Metadata[DeploymentName] = info.DeploymentName
	}
}
