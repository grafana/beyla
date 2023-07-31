package transform

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/mariomac/pipes/pkg/node"
	"golang.org/x/exp/slog"

	"github.com/grafana/ebpf-autoinstrument/pkg/internal/transform/kube"
)

type KubeEnableFlag string

const (
	KubeEnabled    = KubeEnableFlag("true")
	KubeDisabled   = KubeEnableFlag("false")
	KubeAutodetect = KubeEnableFlag("autodetect")
)

const (
	k8sSrcPrefix = "k8s.src."
	k8sDstPrefix = "k8s.dst."
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
	case string(KubeEnabled):
		return true
	case string(KubeDisabled):
		return false
	case string(KubeAutodetect):
		// We autodetect that we are in a kubernetes if we can properly load a K8s configuration file
		_, err := kube.LoadConfig(d.KubeconfigPath)
		if err != nil {
			klog().Debug("kubeconfig can't be detected. Assuming we are not in kubernetes", "error", err)
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

type KubeInfo struct {
}

func (md *metadataDecorator) do(span *HTTPRequestSpan) {
	if peerInfo, ok := md.kube.GetInfo(span.Peer); ok {
		md.refreshOwnPodMetadata()
		switch span.Type {
		case EventTypeGRPC, EventTypeHTTP:
			span.Metadata = append(span.Metadata, asMap(k8sSrcPrefix, peerInfo), md.ownMetadataAsDst)
		case EventTypeGRPCClient, EventTypeHTTPClient:
			span.Metadata = append(span.Metadata, asMap(k8sDstPrefix, peerInfo), md.ownMetadataAsSrc)
		}
		fmt.Println("instrumented metadata", span.Metadata)
	} else {
		fmt.Println("couldn't find info for", span.Peer)
	}
}

// TODO: allow users to filter which attributes they want, instead of adding all of them
// TODO: cache
// TODO: local IP metadata
func asMap(keyPrefix string, info *kube.Info) map[string]string {
	meta := map[string]string{
		keyPrefix + "namespace":  info.Namespace,
		keyPrefix + "name":       info.Name,
		keyPrefix + "type":       info.Type,
		keyPrefix + "owner.name": info.Owner.Name,
		keyPrefix + "owner.type": info.Owner.Type,
	}
	// TODO: allow user defining labels to add as metadata
	if info.HostIP != "" {
		meta[keyPrefix+"node.ip"] = info.HostIP
		if info.HostName != "" {
			meta[keyPrefix+"node.name"] = info.HostName
		}
	}
	return meta
}

func (md *metadataDecorator) refreshOwnPodMetadata() {
	if md.ownMetadataAsDst != nil {
		return
	}
	if info, ok := md.kube.GetInfo(getLocalIP()); ok {
		md.ownMetadataAsSrc = asMap(k8sSrcPrefix, info)
		md.ownMetadataAsDst = asMap(k8sDstPrefix, info)
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
