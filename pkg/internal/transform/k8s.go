package transform

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/mariomac/pipes/pkg/node"
	"golang.org/x/exp/maps"

	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/transform/kube"
)

type KubeEnableFlag string

const (
	EnabledTrue       = KubeEnableFlag("true")
	EnabledFalse      = KubeEnableFlag("false")
	EnabledAutodetect = KubeEnableFlag("autodetect")
	EnabledDefault    = EnabledFalse

	SrcNameKey      = "k8s.src.name"
	SrcNamespaceKey = "k8s.src.namespace"
	DstNameKey      = "k8s.dst.name"
	DstNamespaceKey = "k8s.dst.namespace"
	DstTypeKey      = "k8s.dst.type"
)

func klog() *slog.Logger {
	return slog.With("component", "transform.KubernetesDecorator")
}

type KubernetesDecorator struct {
	Enable KubeEnableFlag `yaml:"enable" env:"KUBE_METADATA_ENABLE"`
	// KubeconfigPath is optional. If unset, it will look in the usual location.
	KubeconfigPath string `yaml:"kubeconfig_path" env:"KUBE_METADATA_KUBECONFIG_PATH"`

	InformersSyncTimeout time.Duration `yaml:"informers_sync_timeout" env:"KUBE_INFORMERS_SYNC_TIMEOUT"`
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

func KubeDecoratorProvider(cfg KubernetesDecorator) (node.MiddleFunc[[]request.Span, []request.Span], error) {
	decorator, err := newMetadataDecorator(&cfg)
	if err != nil {
		return nil, fmt.Errorf("instantiating kubernetes metadata decorator: %w", err)
	}
	return func(in <-chan []request.Span, out chan<- []request.Span) {
		decorator.refreshOwnPodMetadata()

		klog().Debug("starting kubernetes decoration loop")
		for spans := range in {
			// in-place decoration and forwarding
			for i := range spans {
				decorator.do(&spans[i])
			}
			out <- spans
		}
		klog().Debug("stopping kubernetes decoration loop")
	}, nil
}

type metadataDecorator struct {
	kube kube.Metadata
	cfg  *KubernetesDecorator

	ownMetadataAsSrc map[string]string
	ownMetadataAsDst map[string]string
}

func newMetadataDecorator(cfg *KubernetesDecorator) (*metadataDecorator, error) {
	dec := &metadataDecorator{cfg: cfg}
	if err := dec.kube.InitFromConfig(cfg.KubeconfigPath, cfg.InformersSyncTimeout); err != nil {
		return nil, err
	}
	return dec, nil
}

func (md *metadataDecorator) do(span *request.Span) {
	if span.Metadata == nil {
		span.Metadata = make(map[string]string, 5)
	}
	// We decorate each trace by looking up into the local kubernetes cache for the
	// Peer address, when we are instrumenting server-side traces, or the
	// Host name, when we are instrumenting client-side traces.
	// This assumption is a bit fragile and might break if the spanner.go
	// changes the way it works.
	// Extensive integration test cases are provided as a safeguard.
	switch span.Type {
	case request.EventTypeGRPC, request.EventTypeHTTP:
		if peerInfo, ok := md.kube.GetInfo(span.Peer); ok {
			appendSRCMetadata(span.Metadata, peerInfo)
		}
		maps.Copy(span.Metadata, md.ownMetadataAsDst)
	case request.EventTypeGRPCClient, request.EventTypeHTTPClient:
		if peerInfo, ok := md.kube.GetInfo(span.Host); ok {
			appendDSTMetadata(span.Metadata, peerInfo)
		}
		maps.Copy(span.Metadata, md.ownMetadataAsSrc)
	}
}

// TODO: allow users to filter which attributes they want, instead of adding all of them
// TODO: cache
func appendDSTMetadata(to map[string]string, info *kube.Info) {
	to[DstNameKey] = info.Name
	to[DstNamespaceKey] = info.Namespace
	to[DstTypeKey] = info.Type
}

func appendSRCMetadata(to map[string]string, info *kube.Info) {
	to[SrcNameKey] = info.Name
	to[SrcNamespaceKey] = info.Namespace
}

func (md *metadataDecorator) refreshOwnPodMetadata() {
	for {
		if info, ok := md.kube.GetInfo(getLocalIP()); ok {
			klog().Debug("found local pod metadata", "metadata", info)
			md.ownMetadataAsSrc = make(map[string]string, 2)
			md.ownMetadataAsDst = make(map[string]string, 2)
			appendSRCMetadata(md.ownMetadataAsSrc, info)
			appendDSTMetadata(md.ownMetadataAsDst, info)
			return
		}
		klog().Info("local pod metadata not yet found. Waiting 5s and trying again before starting the kubernetes decorator")
		time.Sleep(5 * time.Second)
	}
}

// getLocalIP returns the first non-loopback local IP of the pod
func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, address := range addrs {
		// check the address type and if it is not a loopback the display it
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return ""
}
