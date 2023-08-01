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

type KubeInfo struct {
}

func (md *metadataDecorator) do(span *HTTPRequestSpan) {
	switch span.Type {
	case EventTypeGRPC, EventTypeHTTP:
		if peerInfo, ok := md.kube.GetInfo(span.Peer); ok {
			span.Metadata = append(span.Metadata, asSrcMap(peerInfo), md.ownMetadataAsDst)
		} else {
			span.Metadata = append(span.Metadata, md.ownMetadataAsDst)
		}
	case EventTypeGRPCClient, EventTypeHTTPClient:
		ay ke mirar el span jost este a ver si podemos hacerlo mas estable
		if peerInfo, ok := md.kube.GetServiceInfo(span.Host); ok {
			span.Metadata = append(span.Metadata, asDstMap(peerInfo), md.ownMetadataAsSrc)
		} else {
			span.Metadata = append(span.Metadata, md.ownMetadataAsSrc)
		}
	}
}

// TODO: allow users to filter which attributes they want, instead of adding all of them
// TODO: cache
func asDstMap(info *kube.Info) map[string]string {
	return map[string]string{
		"k8s.dst.namespace": info.Namespace,
		"k8s.dst.name":      info.Name,
		"k8s.dst.type":      info.Type,
	}
}

func asSrcMap(info *kube.Info) map[string]string {
	return map[string]string{
		"k8s.src.namespace": info.Namespace,
		"k8s.src.name":      info.Name,
	}
}

func (md *metadataDecorator) refreshOwnPodMetadata() {
	for md.ownMetadataAsDst == nil {
		if info, ok := md.kube.GetInfo(getLocalIP()); ok {
			md.ownMetadataAsSrc = asSrcMap(info)
			md.ownMetadataAsDst = asDstMap(info)
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
