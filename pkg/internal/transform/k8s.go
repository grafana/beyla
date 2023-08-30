package transform

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/mariomac/pipes/pkg/node"
	"golang.org/x/exp/slog"

	"github.com/grafana/beyla/pkg/internal/transform/kube"
)

type KubeEnableFlag string

const (
	EnabledTrue       = KubeEnableFlag("true")
	EnabledFalse      = KubeEnableFlag("false")
	EnabledAutodetect = KubeEnableFlag("autodetect")
	EnabledDefault    = EnabledFalse
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
		klog().Warn("invalid value for Enable value: %s. Ignoring stage", d.Enable)
		return false
	}
}

func KubeDecoratorProvider(_ context.Context, cfg KubernetesDecorator) (node.MiddleFunc[[]HTTPRequestSpan, []HTTPRequestSpan], error) {
	decorator, err := newMetadataDecorator(&cfg)
	if err != nil {
		return nil, fmt.Errorf("instantiating kubernetes metadata decorator: %w", err)
	}
	return func(in <-chan []HTTPRequestSpan, out chan<- []HTTPRequestSpan) {
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

	ownMetadataAsSrc []MetadataTag
	ownMetadataAsDst []MetadataTag
}

func newMetadataDecorator(cfg *KubernetesDecorator) (*metadataDecorator, error) {
	dec := &metadataDecorator{cfg: cfg}
	if err := dec.kube.InitFromConfig(cfg.KubeconfigPath, cfg.InformersSyncTimeout); err != nil {
		return nil, err
	}
	return dec, nil
}

func (md *metadataDecorator) do(span *HTTPRequestSpan) {
	// We decorate each trace by looking up into the local kubernetes cache for the
	// Peer address, when we are instrumenting server-side traces, or the
	// Host name, when we are instrumenting client-side traces.
	// This assumption is a bit fragile and might break if the spanner.go
	// changes the way it works.
	// Extensive integration test cases are provided as a safeguard.
	switch span.Type {
	case EventTypeGRPC, EventTypeHTTP:
		if peerInfo, ok := md.kube.GetInfo(span.Peer); ok {
			span.Metadata = appendSRCMetadata(span.Metadata, peerInfo)
		}
		span.Metadata = append(span.Metadata, md.ownMetadataAsDst...)
	case EventTypeGRPCClient, EventTypeHTTPClient:
		if peerInfo, ok := md.kube.GetInfo(span.Host); ok {
			span.Metadata = appendDSTMetadata(span.Metadata, peerInfo)
		}
		span.Metadata = append(span.Metadata, md.ownMetadataAsSrc...)
	}
}

// TODO: allow users to filter which attributes they want, instead of adding all of them
// TODO: cache
func appendDSTMetadata(dst []MetadataTag, info *kube.Info) []MetadataTag {
	return append(dst,
		MetadataTag{Key: "k8s.dst.namespace", Val: info.Namespace},
		MetadataTag{Key: "k8s.dst.name", Val: info.Name},
		MetadataTag{Key: "k8s.dst.type", Val: info.Type},
	)
}

func appendSRCMetadata(dst []MetadataTag, info *kube.Info) []MetadataTag {
	return append(dst,
		MetadataTag{Key: "k8s.src.namespace", Val: info.Namespace},
		MetadataTag{Key: "k8s.src.name", Val: info.Name},
	)
}

func (md *metadataDecorator) refreshOwnPodMetadata() {
	for md.ownMetadataAsDst == nil {
		if info, ok := md.kube.GetInfo(getLocalIP()); ok {
			md.ownMetadataAsSrc = appendSRCMetadata(md.ownMetadataAsSrc, info)
			md.ownMetadataAsDst = appendDSTMetadata(md.ownMetadataAsDst, info)
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
