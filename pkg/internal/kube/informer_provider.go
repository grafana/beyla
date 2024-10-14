package kube

import (
	"context"
	"fmt"
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/grafana/beyla-k8s-cache/pkg/meta"
	"github.com/grafana/beyla/pkg/kubeflags"
)

type MetadataConfig struct {
	Enable            kubeflags.EnableFlag
	DisabledInformers []string
	KubeConfigPath    string
	SyncTimeout       time.Duration
	ResyncPeriod      time.Duration
}

type MetadataProvider struct {
	mt sync.Mutex

	metadata *Store
	informer *InformersMetadata

	kubeConfigPath string
	syncTimeout    time.Duration
	resyncPeriod   time.Duration

	enable atomic.Value
}

func NewMetadataProvider(config MetadataConfig) *MetadataProvider {
	if config.SyncTimeout == 0 {
		config.SyncTimeout = defaultSyncTimeout
	}
	if config.ResyncPeriod == 0 {
		config.ResyncPeriod = defaultResyncTime
	}
	mp := &MetadataProvider{
		kubeConfigPath: config.KubeConfigPath,
		syncTimeout:    config.SyncTimeout,
		resyncPeriod:   config.ResyncPeriod,
	}
	mp.enable.Store(config.Enable)
	return mp
}

func (mp *MetadataProvider) IsKubeEnabled() bool {
	if mp == nil {
		return false
	}
	switch strings.ToLower(string(mp.enable.Load().(kubeflags.EnableFlag))) {
	case string(kubeflags.EnabledTrue):
		return true
	case string(kubeflags.EnabledFalse), "": // empty value is disabled
		return false
	case string(kubeflags.EnabledAutodetect):
		// We autodetect that we are in a kubernetes if we can properly load a K8s configuration file
		_, err := LoadConfig(mp.kubeConfigPath)
		if err != nil {
			klog().Debug("kubeconfig can't be detected. Assuming we are not in Kubernetes", "error", err)
			mp.enable.Store(kubeflags.EnabledFalse)
			return false
		}
		mp.enable.Store(kubeflags.EnabledTrue)
		return true
	default:
		klog().Warn("invalid value for Enable value. Ignoring stage", "value", mp.enable.Load())
		return false
	}
}

func (mp *MetadataProvider) ForceDisable() {
	mp.enable.Store(kubeflags.EnabledFalse)
}

func (mp *MetadataProvider) KubeClient() (kubernetes.Interface, error) {
	restCfg, err := LoadConfig(mp.kubeConfigPath)
	if err != nil {
		return nil, fmt.Errorf("kubeconfig can't be detected: %w", err)
	}
	return kubernetes.NewForConfig(restCfg)
}

func (mp *MetadataProvider) Store(ctx context.Context) (*Store, error) {
	mp.mt.Lock()
	defer mp.mt.Unlock()

	if mp.metadata != nil {
		return mp.metadata, nil
	}

	informer, err := mp.getInformer(ctx)
	if err != nil {
		return nil, err
	}

	mp.metadata = NewStore(informer)

	return mp.metadata, nil
}

func (mp *MetadataProvider) Subscribe(ctx context.Context, observer meta.Observer) error {
	mp.mt.Lock()
	defer mp.mt.Unlock()
	if informer, err := mp.getInformer(ctx); err != nil {
		return fmt.Errorf("can't subscribe to informer: %w", err)
	} else {
		informer.Subscribe(observer)
	}
	return nil
}

func (mp *MetadataProvider) getInformer(ctx context.Context) (*InformersMetadata, error) {
	if mp.informer != nil {
		return mp.informer, nil
	}
	var err error
	mp.informer, err = NewInformersMetadata(ctx, mp.kubeConfigPath)
	if err != nil {
		return nil, fmt.Errorf("can't get informer: %w", err)
	}
	return mp.informer, nil
}

func (mp *MetadataProvider) CurrentNodeName(ctx context.Context) (string, error) {
	log := klog().With("func", "NodeName")
	kubeClient, err := mp.KubeClient()
	if err != nil {
		return "", fmt.Errorf("can't get kubernetes client: %w", err)
	}
	// fist: get the current pod name and namespace
	currentPod, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("can't get hostname of current pod: %w", err)
	}
	var currentNamespace string
	if nsBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err != nil {
		log.Warn("can't read service account namespace. Two Beyla pods with the same"+
			" name could result in inaccuracies in the host.id attribute", "error", err)
	} else {
		currentNamespace = string(nsBytes)
	}
	// second: get the node for the current Pod
	// using List instead of Store because to not require extra serviceaccount permissions
	pods, err := kubeClient.CoreV1().Pods(currentNamespace).List(ctx, metav1.ListOptions{
		FieldSelector: "metadata.name=" + currentPod,
	})
	if err != nil || len(pods.Items) == 0 {
		return "", fmt.Errorf("can't get pod %s/%s: %w", currentNamespace, currentPod, err)
	}
	return pods.Items[0].Spec.NodeName, nil
}

func LoadConfig(kubeConfigPath string) (*rest.Config, error) {
	// if no config path is provided, load it from the env variable
	if kubeConfigPath == "" {
		kubeConfigPath = os.Getenv(kubeConfigEnvVariable)
	}
	// otherwise, load it from the $HOME/.kube/config file
	if kubeConfigPath == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("can't get user home dir: %w", err)
		}
		kubeConfigPath = path.Join(homeDir, ".kube", "config")
	}
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigPath)
	if err == nil {
		return config, nil
	}
	// fallback: use in-cluster config
	config, err = rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("can't access kubenetes. Tried using config from: "+
			"config parameter, %s env, homedir and InClusterConfig. Got: %w",
			kubeConfigEnvVariable, err)
	}
	return config, nil
}
