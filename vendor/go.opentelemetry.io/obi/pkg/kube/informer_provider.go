// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kube

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path"
	"strings"
	"sync"
	"text/template"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/meta"
	"go.opentelemetry.io/obi/pkg/kube/kubeflags"
)

const (
	kubeConfigEnvVariable = "KUBECONFIG"
)

// Some cloud providers store the cluster name as a Node label.
// This greatly facilitates the retrieval of the cluster name, as we
// don't need to rely on provider-specific APIs.
// TODO: update with labels from other providers, or newer labels as long as specs are updated
var clusterNameNodeLabels = []string{
	"alpha.eksctl.io/cluster-name",
	"cluster.x-k8s.io/cluster-name",
	"kubernetes.azure.com/cluster",
}

func klog() *slog.Logger {
	return slog.With("component", "kube.MetadataProvider")
}

type MetadataConfig struct {
	Enable              kubeflags.EnableFlag
	DisabledInformers   []string
	KubeConfigPath      string
	SyncTimeout         time.Duration
	ResyncPeriod        time.Duration
	MetaCacheAddr       string
	ResourceLabels      ResourceLabels
	RestrictLocalNode   bool
	ServiceNameTemplate *template.Template
}

type MetadataProvider struct {
	mt sync.Mutex

	metadata *Store
	informer meta.Notifier

	localNodeName string
	clusterName   string

	cfg *MetadataConfig

	internalMetrics imetrics.Reporter
}

func NewMetadataProvider(config MetadataConfig, internalMetrics imetrics.Reporter) *MetadataProvider {
	return &MetadataProvider{cfg: &config, internalMetrics: internalMetrics}
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

	mp.metadata = NewStore(informer, mp.cfg.ResourceLabels, mp.cfg.ServiceNameTemplate, mp.internalMetrics)

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
	if mp.localNodeName != "" {
		return mp.localNodeName, nil
	}

	if nn, err := mp.fetchNodeName(ctx); err != nil {
		return "", err
	} else {
		mp.localNodeName = nn
	}
	return mp.localNodeName, nil
}

func (mp *MetadataProvider) ClusterName(ctx context.Context) (string, error) {
	if mp.clusterName != "" {
		return mp.clusterName, nil
	}
	// make sure that node name has been fetched and cached previously
	if _, err := mp.CurrentNodeName(ctx); err != nil {
		return "", fmt.Errorf("can't get node name before getting Cluster name: %w", err)
	}
	if cn, err := mp.fetchClusterNameFromNodeLabels(ctx); err != nil {
		return "", err
	} else {
		mp.clusterName = cn
	}
	return mp.clusterName, nil
}

func (mp *MetadataProvider) fetchNodeName(ctx context.Context) (string, error) {
	log := klog().With("func", "fetchNodeName")
	kubeClient, err := mp.KubeClient()
	if err != nil {
		return "", fmt.Errorf("can't get kubernetes client: %w", err)
	}
	// fist: get the current pod name and namespace
	podHostName, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("can't get hostname of current pod: %w", err)
	}
	namespace := currentNamespace(log)
	// second: get the node for the current Pod
	// using List instead of Get because to not require extra serviceaccount permissions
	pods, err := kubeClient.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		FieldSelector: "metadata.name=" + podHostName,
	})
	if err != nil || len(pods.Items) == 0 {
		log.Debug("can't get Pod info. This is expected if the pod is using the host network",
			"podHostName", podHostName, "namespace", namespace, "error", err)
		return checkLocalHostNameWithNodeName(ctx, log, kubeClient, podHostName)
	}
	return pods.Items[0].Spec.NodeName, nil
}

func (mp *MetadataProvider) fetchClusterNameFromNodeLabels(ctx context.Context) (string, error) {
	kubeClient, err := mp.KubeClient()
	if err != nil {
		return "", fmt.Errorf("can't get kubernetes client: %w", err)
	}
	nodes, err := kubeClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{
		FieldSelector: "metadata.name=" + mp.localNodeName,
	})
	if err != nil {
		return "", fmt.Errorf("fetchClusterNameFromNodeLabels getting node %s: %w", mp.localNodeName, err)
	}
	if len(nodes.Items) == 0 {
		return "", fmt.Errorf("fetchClusterNameFromNodeLabels can't find node %s", mp.localNodeName)
	}
	node := nodes.Items[0]
	for _, label := range clusterNameNodeLabels {
		if name, ok := node.Labels[label]; ok {
			return name, nil
		}
	}
	return "", errors.New("no cluster name found in node labels")
}

func currentNamespace(log *slog.Logger) string {
	if nsBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err != nil {
		log.Warn("can't read service account namespace. Two Beyla pods with the same"+
			" name could result in inaccuracies in the host.id attribute", "error", err)
		return ""
	} else {
		return string(nsBytes)
	}
}

// it might happen that the fetched hostName is not fully qualified and misses the localdomain
// suffix, so we will check either if it corresponds to a kubernetes node, or if there is a
// unique cluster node that starts with the fetched hostName
func checkLocalHostNameWithNodeName(
	ctx context.Context, log *slog.Logger, kubeClient kubernetes.Interface, podHostName string,
) (string, error) {
	nodes, err := kubeClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return "", fmt.Errorf("fetching local host node name: %w", err)
	}
	podHostName = strings.ToLower(podHostName)
	var submatches []string
	for i := range nodes.Items {
		nodeName := strings.ToLower(nodes.Items[i].Name)
		if nodeName == podHostName {
			return podHostName, nil
		}
		if strings.HasPrefix(nodeName, podHostName) {
			submatches = append(submatches, nodeName)
		}
	}
	switch len(submatches) {
	case 0:
		log.Warn("could not get any node name corresponding to the Beyla pod."+
			" This could involve missing or incorrect Kubernetes metadata", "hostName", podHostName)
	case 1:
		podHostName = submatches[0]
	default:
		podHostName = submatches[0]
		log.Warn("multiple node matches for the Beyla pod name. "+
			" This could involve missing or incorrect Kubernetes metadata",
			"matches", submatches, "hostName", podHostName)
	}

	return podHostName, nil
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
		meta.LocalInstance(),
		meta.WithCacheSyncTimeout(mp.cfg.SyncTimeout),
	)
	if mp.cfg.RestrictLocalNode {
		localNode, err := mp.CurrentNodeName(ctx)
		if err != nil {
			return nil, fmt.Errorf("getting local node name: %w", err)
		}
		opts = append(opts, meta.RestrictNode(localNode))
	}
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
