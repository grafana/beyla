package kube

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"k8s.io/client-go/kubernetes"
)

type EnableFlag string

const (
	EnabledTrue       = EnableFlag("true")
	EnabledFalse      = EnableFlag("false")
	EnabledAutodetect = EnableFlag("autodetect")
	EnabledDefault    = EnabledFalse
)

type MetadataProvider struct {
	mt       sync.Mutex
	metadata *Metadata

	kubeConfigPath string
	syncTimeout    time.Duration

	enable            atomic.Value
	disabledInformers informerType
}

func NewMetadataProvider(
	enable EnableFlag,
	disabledInformers []string,
	kubeConfigPath string,
	syncTimeout time.Duration,
) *MetadataProvider {
	mp := &MetadataProvider{
		kubeConfigPath:    kubeConfigPath,
		syncTimeout:       syncTimeout,
		disabledInformers: informerTypes(disabledInformers),
	}
	mp.enable.Store(enable)
	return mp
}

func (mp *MetadataProvider) IsKubeEnabled() bool {
	if mp == nil {
		return false
	}
	switch strings.ToLower(string(mp.enable.Load().(EnableFlag))) {
	case string(EnabledTrue):
		return true
	case string(EnabledFalse), "": // empty value is disabled
		return false
	case string(EnabledAutodetect):
		// We autodetect that we are in a kubernetes if we can properly load a K8s configuration file
		_, err := LoadConfig(mp.kubeConfigPath)
		if err != nil {
			klog().Debug("kubeconfig can't be detected. Assuming we are not in Kubernetes", "error", err)
			mp.enable.Store(EnabledFalse)
			return false
		}
		mp.enable.Store(EnabledTrue)
		return true
	default:
		klog().Warn("invalid value for Enable value. Ignoring stage", "value", mp.enable.Load())
		return false
	}
}

func (mp *MetadataProvider) ForceDisable() {
	mp.enable.Store(EnabledFalse)
}

func (mp *MetadataProvider) Get(ctx context.Context) (*Metadata, error) {
	mp.mt.Lock()
	defer mp.mt.Unlock()

	if mp.metadata != nil {
		return mp.metadata, nil
	}

	restCfg, err := LoadConfig(mp.kubeConfigPath)
	if err != nil {
		return nil, fmt.Errorf("kubeconfig can't be detected: %w", err)
	}
	kubeClient, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("kubernetes client can't be initialized: %w", err)
	}
	mp.metadata = &Metadata{disabledInformers: mp.disabledInformers}
	if err := mp.metadata.InitFromClient(ctx, kubeClient, mp.syncTimeout); err != nil {
		return nil, fmt.Errorf("can't initialize kubernetes metadata: %w", err)
	}
	return mp.metadata, nil
}
