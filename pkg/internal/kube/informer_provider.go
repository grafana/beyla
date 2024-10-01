package kube

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/grafana/beyla/pkg/internal/helpers/maps"
	"github.com/grafana/beyla/pkg/kubeflags"
)

type MetadataProvider struct {
	mt       sync.Mutex
	metadata *Metadata

	kubeConfigPath string
	syncTimeout    time.Duration

	enable            atomic.Value
	disabledInformers maps.Bits
	enableNetworkMeta bool
}

func NewMetadataProvider(
	enable kubeflags.EnableFlag,
	disabledInformers []string,
	kubeConfigPath string,
	enableNetworkMetadata bool,
	syncTimeout time.Duration,
) *MetadataProvider {
	mp := &MetadataProvider{
		enableNetworkMeta: enableNetworkMetadata,
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

func (mp *MetadataProvider) Get(ctx context.Context) (*Metadata, error) {
	mp.mt.Lock()
	defer mp.mt.Unlock()

	if mp.metadata != nil {
		return mp.metadata, nil
	}

	kubeClient, err := mp.KubeClient()
	if err != nil {
		return nil, fmt.Errorf("kubernetes client can't be initialized: %w", err)
	}

	// restricting the node name of the informers for App O11y, as we will only decorate
	// instances running on the same node that Beyla
	// however, for network o11y, we need to get all the nodes so the node name restriction
	// would remain unset
	restrictNodeName := ""
	if !mp.enableNetworkMeta {
		restrictNodeName, err = mp.CurrentNodeName(ctx)
		if err != nil {
			return nil, fmt.Errorf("can't get current node name: %w", err)
		}
	}
	mp.metadata = &Metadata{disabledInformers: mp.disabledInformers}
	if err := mp.metadata.InitFromClient(ctx, kubeClient, restrictNodeName, mp.syncTimeout); err != nil {
		return nil, fmt.Errorf("can't initialize kubernetes metadata: %w", err)
	}
	return mp.metadata, nil
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
		return "", fmt.Errorf("can't get pod %s/%s: %w", currentNamespace, currentPod, err)
	}
	return pods.Items[0].Spec.NodeName, nil
}
