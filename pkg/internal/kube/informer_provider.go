package kube

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/grafana/beyla/pkg/kubecache/meta"
	"github.com/grafana/beyla/pkg/kubeflags"
)

const (
	kubeConfigEnvVariable = "KUBECONFIG"
)

func klog() *slog.Logger {
	return slog.With("component", "kube.MetadataProvider")
}

type MetadataConfig struct {
	Enable            kubeflags.EnableFlag
	DisabledInformers []string
	KubeConfigPath    string
	SyncTimeout       time.Duration
	ResyncPeriod      time.Duration
	MetaCacheAddr     string
	MetadataSources   MetadataSources
}

type MetadataProvider struct {
	mt sync.Mutex

	metadata *Store
	informer meta.Notifier

	cfg *MetadataConfig
}

func NewMetadataProvider(config MetadataConfig) *MetadataProvider {
	return &MetadataProvider{cfg: &config}
}

func (mp *MetadataProvider) IsKubeEnabled() bool {
	if mp == nil || mp.cfg == nil {
		return false
	}
	mp.mt.Lock()
	defer mp.mt.Unlock()
	switch strings.ToLower(string(mp.cfg.Enable)) {
	case string(kubeflags.EnabledTrue):
		return true
	case string(kubeflags.EnabledFalse), "": // empty value is disabled
		return false
	case string(kubeflags.EnabledAutodetect):
		// We autodetect that we are in a kubernetes if we can properly load a K8s configuration file
		_, err := loadKubeConfig(mp.cfg.KubeConfigPath)
		if err != nil {
			klog().Debug("kubeconfig can't be detected. Assuming we are not in Kubernetes", "error", err)
			mp.cfg.Enable = kubeflags.EnabledFalse
			return false
		}
		mp.cfg.Enable = kubeflags.EnabledTrue
		return true
	default:
		klog().Warn("invalid value for Enable value. Ignoring stage", "value", mp.cfg.Enable)
		return false
	}
}

func (mp *MetadataProvider) ForceDisable() {
	mp.mt.Lock()
	defer mp.mt.Unlock()
	mp.cfg.Enable = kubeflags.EnabledFalse
}

func (mp *MetadataProvider) KubeClient() (kubernetes.Interface, error) {
	restCfg, err := loadKubeConfig(mp.cfg.KubeConfigPath)
	if err != nil {
		return nil, fmt.Errorf("kubeconfig can't be detected: %w", err)
	}
	return kubernetes.NewForConfig(restCfg)
}

func (mp *MetadataProvider) Get(ctx context.Context) (*Store, error) {
	mp.mt.Lock()
	defer mp.mt.Unlock()

	if mp.metadata != nil {
		return mp.metadata, nil
	}

	informer, err := mp.getInformer(ctx)
	if err != nil {
		return nil, err
	}

	mp.metadata = NewStore(informer, mp.cfg.MetadataSources)

	return mp.metadata, nil
}

func (mp *MetadataProvider) getInformer(ctx context.Context) (meta.Notifier, error) {
	if mp.informer != nil {
		return mp.informer, nil
	}
	if mp.cfg.MetaCacheAddr != "" {
		mp.informer = mp.initRemoteInformerCacheClient(ctx)
	} else {
		var err error
		mp.informer, err = mp.initLocalInformers(ctx)
		if err != nil {
			return nil, fmt.Errorf("can't get informer: %w", err)
		}
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
	// using List instead of Get because to not require extra serviceaccount permissions
	pods, err := kubeClient.CoreV1().Pods(currentNamespace).List(ctx, metav1.ListOptions{
		FieldSelector: "metadata.name=" + currentPod,
	})
	if err != nil || len(pods.Items) == 0 {
		log.Debug("attention: can't get Pod info. This is expected if the pod is using the host network. Will use the"+
			" host name as node name", "nodeName", currentPod, "namespace", currentNamespace, "error", err)
		return currentPod, nil
	}
	return pods.Items[0].Spec.NodeName, nil
}

// initLocalInformers initializes an informer client that directly connects to the Node Kube API
// for getting informer data
func (mp *MetadataProvider) initLocalInformers(ctx context.Context) (*meta.Informers, error) {
	opts := append(disabledInformerOpts(mp.cfg.DisabledInformers),
		meta.WithResyncPeriod(mp.cfg.ResyncPeriod),
		meta.WithKubeConfigPath(mp.cfg.KubeConfigPath),
		// we don't want that the informer starts decorating spans and flows
		// before getting all the existing K8s metadata
		meta.WaitForCacheSync(),
		meta.WithCacheSyncTimeout(mp.cfg.SyncTimeout),
	)
	return meta.InitInformers(ctx, opts...)
}

// initRemoteInformerCacheClient connects via gRPC/Protobuf to a remote beyla-k8s-cache service, to avoid that
// each Beyla instance connects to the Kube API informer on each node, which would overload the Kube API
func (mp *MetadataProvider) initRemoteInformerCacheClient(ctx context.Context) *cacheSvcClient {
	client := &cacheSvcClient{
		address:      mp.cfg.MetaCacheAddr,
		BaseNotifier: meta.NewBaseNotifier(klog()),
		syncTimeout:  mp.cfg.SyncTimeout,
	}
	client.Start(ctx)
	return client
}

func loadKubeConfig(kubeConfigPath string) (*rest.Config, error) {
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

func disabledInformerOpts(disabledInformers []string) []meta.InformerOption {
	var opts []meta.InformerOption
	for _, di := range disabledInformers {
		switch strings.ToLower(di) {
		case "node", "nodes":
			opts = append(opts, meta.WithoutNodes())
		case "service", "services":
			opts = append(opts, meta.WithoutServices())
		default:
			klog().Warn("invalid value for DisableInformers. Ignoring", "value", di)
		}
	}
	return opts
}
