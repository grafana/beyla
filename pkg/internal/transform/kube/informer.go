package kube

import (
	"fmt"
	"log/slog"
	"os"
	"path"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	kubeConfigEnvVariable = "KUBECONFIG"
	syncTime              = 10 * time.Minute
	IndexPodIPs           = "idx_pod"
	IndexReplicaSetNames  = "idx_rs"
)

func klog() *slog.Logger {
	return slog.With("component", "kube.Metadata")
}

// Metadata stores an in-memory copy of the different Kubernetes objects whose metadata is relevant to us.
type Metadata struct {
	// pods and replicaSets cache the different K8s types to custom, smaller object types
	pods        cache.SharedIndexInformer
	replicaSets cache.SharedIndexInformer

	stopChan chan struct{}
}

// PodInfo contains precollected metadata for Pods, Nodes and Services.
// Not all the fields are populated for all the above types. To save
// memory, we just keep in memory the necessary data for each Type.
// For more information about which fields are set for each type, please
// refer to the instantiation function of the respective informers.
type PodInfo struct {
	// Informers need that internal object is an ObjectMeta instance
	metav1.ObjectMeta
	ReplicaSetName string
	// Pod Info includes the ReplicaSet as owner reference, and ReplicaSet info
	// has Deployment as owner reference. We initially do a two-steps lookup to
	// get the Pod's Deployment, but then cache the Deployment value here
	DeploymentName string
	ips            []string
}

type ReplicaSetInfo struct {
	metav1.ObjectMeta
	DeploymentName string
}

var podIndexer = cache.Indexers{
	IndexPodIPs: func(obj interface{}) ([]string, error) {
		return obj.(*PodInfo).ips, nil
	},
}

var rsIndexer = cache.Indexers{
	IndexReplicaSetNames: func(obj interface{}) ([]string, error) {
		// we don't index by namespace too, as name collisions are unlikely happening,
		// because the replicaset between a pod and its deployment has names like frontend-64f8f4c645
		return []string{obj.(*ReplicaSetInfo).Name}, nil
	},
}

// GetPodInfo fetches metadata from a Pod given its IP
func (k *Metadata) GetPodInfo(ip string) (*PodInfo, bool) {
	objs, err := k.pods.GetIndexer().ByIndex(IndexPodIPs, ip)
	if err != nil {
		klog().Debug("error accessing index by IP. Ignoring", "error", err, "ip", ip)
		return nil, false
	}
	if len(objs) == 0 {
		return nil, false
	}
	return objs[0].(*PodInfo), true
}

func (k *Metadata) initPodInformer(informerFactory informers.SharedInformerFactory) error {
	pods := informerFactory.Core().V1().Pods().Informer()
	// Transform any *v1.Pod instance into a *PodInfo instance to save space
	// in the informer's cache
	if err := pods.SetTransform(func(i interface{}) (interface{}, error) {
		pod, ok := i.(*v1.Pod)
		if !ok {
			return nil, fmt.Errorf("was expecting a Pod. Got: %T", i)
		}
		ips := make([]string, 0, len(pod.Status.PodIPs))
		for _, ip := range pod.Status.PodIPs {
			// ignoring host-networked Pod IPs
			if ip.IP != pod.Status.HostIP {
				ips = append(ips, ip.IP)
			}
		}
		var replicaSet string
		for i := range pod.OwnerReferences {
			or := &pod.OwnerReferences[i]
			if or.APIVersion == "apps/v1" && or.Kind == "ReplicaSet" {
				replicaSet = or.Name
				break
			}
		}
		return &PodInfo{
			ObjectMeta: metav1.ObjectMeta{
				Name:      pod.Name,
				Namespace: pod.Namespace,
			},
			ReplicaSetName: replicaSet,
			ips:            ips,
		}, nil
	}); err != nil {
		return fmt.Errorf("can't set pods transform: %w", err)
	}
	if err := pods.AddIndexers(podIndexer); err != nil {
		return fmt.Errorf("can't add %s indexer to Pods informer: %w", IndexPodIPs, err)
	}

	k.pods = pods
	return nil
}

// GetReplicaSetInfo fetches metadata from a ReplicaSet given its name
func (k *Metadata) GetReplicaSetInfo(name string) (*PodInfo, bool) {
	objs, err := k.replicaSets.GetIndexer().ByIndex(IndexReplicaSetNames, name)
	if err != nil {
		klog().Debug("error accessing ReplicaSet index by name. Ignoring",
			"error", err, "name", name)
		return nil, false
	}
	if len(objs) == 0 {
		return nil, false
	}
	return objs[0].(*PodInfo), true
}

func (k *Metadata) initReplicaSetInformer(informerFactory informers.SharedInformerFactory) error {
	rss := informerFactory.Apps().V1().ReplicaSets().Informer()
	// Transform any *appsv1.Replicaset instance into a *ReplicaSetInfo instance to save space
	// in the informer's cache
	if err := rss.SetTransform(func(i interface{}) (interface{}, error) {
		rs, ok := i.(*appsv1.ReplicaSet)
		if !ok {
			return nil, fmt.Errorf("was expecting a ReplicaSet. Got: %T", i)
		}
		var deployment string
		for i := range rs.OwnerReferences {
			or := &rs.OwnerReferences[i]
			if or.APIVersion == "apps/v1" && or.Kind == "Deployment" {
				deployment = or.Name
				break
			}
		}
		return &ReplicaSetInfo{
			ObjectMeta: metav1.ObjectMeta{
				Name:      rs.Name,
				Namespace: rs.Namespace,
			},
			DeploymentName: deployment,
		}, nil
	}); err != nil {
		return fmt.Errorf("can't set pods transform: %w", err)
	}
	if err := rss.AddIndexers(rsIndexer); err != nil {
		return fmt.Errorf("can't add %s indexer to ReplicaSets informer: %w", IndexReplicaSetNames, err)
	}

	k.replicaSets = rss
	return nil
}

func (k *Metadata) InitFromConfig(kubeConfigPath string, timeout time.Duration) error {
	// Initialization variables
	k.stopChan = make(chan struct{})

	config, err := LoadConfig(kubeConfigPath)
	if err != nil {
		return err
	}

	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	err = k.initInformers(kubeClient, timeout)
	if err != nil {
		return err
	}

	return nil
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

func (k *Metadata) initInformers(client kubernetes.Interface, timeout time.Duration) error {
	informerFactory := informers.NewSharedInformerFactory(client, syncTime)
	err := k.initPodInformer(informerFactory)
	if err != nil {
		return err
	}
	err = k.initReplicaSetInformer(informerFactory)
	if err != nil {
		return err
	}

	log := klog()
	log.Debug("starting kubernetes informers, waiting for syncronization")
	informerFactory.Start(k.stopChan)
	finishedCacheSync := make(chan struct{})
	go func() {
		informerFactory.WaitForCacheSync(k.stopChan)
		close(finishedCacheSync)
	}()
	select {
	case <-finishedCacheSync:
		log.Debug("kubernetes informers started")
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("kubernetes cache has not been synced after %s timeout", timeout)
	}

}
