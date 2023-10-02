package kube

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path"
	"time"

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
	IndexIPOrName         = "idx"
	typePod               = "Pod"
	typeService           = "Service"
)

func klog() *slog.Logger {
	return slog.With("component", "kube.Metadata")
}

// Metadata stores an in-memory copy of the different Kubernetes objects whose metadata is relevant to us.
type Metadata struct {
	// pods and services cache the different object types as *Info pointers
	pods     cache.SharedIndexInformer
	services cache.SharedIndexInformer

	stopChan chan struct{}
}

// Info contains precollected metadata for Pods, Nodes and Services.
// Not all the fields are populated for all the above types. To save
// memory, we just keep in memory the necessary data for each Type.
// For more information about which fields are set for each type, please
// refer to the instantiation function of the respective informers.
type Info struct {
	// Informers need that internal object is an ObjectMeta instance
	metav1.ObjectMeta
	Type string
	ips  []string
}

var indexers = cache.Indexers{
	IndexIPOrName: func(obj interface{}) ([]string, error) {
		oi := obj.(*Info)
		switch oi.Type {
		case typeService:
			// Known issues: two services with the same name would overwrite metadata unless they are accessed with the
			// namespace in the URL
			return append(
				oi.ips,
				// TODO: support subdomains and custom cluster domains: https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/
				oi.Name,
				oi.Name+"."+oi.Namespace,
				oi.Name+"."+oi.Namespace+".svc.cluster.local",
				oi.Name+"."+oi.Namespace+".cluster.local",
			), nil
		default:
			return oi.ips, nil
		}
	},
}

// GetInfo fetches metadata from Pod, Service given its IP or Service Name
func (k *Metadata) GetInfo(ipOrName string) (*Info, bool) {
	if info, ok := infoForIP(k.pods.GetIndexer(), ipOrName); ok {
		return info, true
	}
	if info, ok := infoForIP(k.services.GetIndexer(), ipOrName); ok {
		return info, true
	}
	return nil, false
}

func infoForIP(idx cache.Indexer, ip string) (*Info, bool) {
	objs, err := idx.ByIndex(IndexIPOrName, ip)
	if err != nil {
		klog().Debug("error accessing index by IP. Ignoring", "error", err, "ip", ip)
		return nil, false
	}
	if len(objs) == 0 {
		return nil, false
	}
	return objs[0].(*Info), true
}

func (k *Metadata) initPodInformer(informerFactory informers.SharedInformerFactory) error {
	pods := informerFactory.Core().V1().Pods().Informer()
	// Transform any *v1.Pod instance into a *Info instance to save space
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
		return &Info{
			ObjectMeta: metav1.ObjectMeta{
				Name:      pod.Name,
				Namespace: pod.Namespace,
			},
			Type: typePod,
			ips:  ips,
		}, nil
	}); err != nil {
		return fmt.Errorf("can't set pods transform: %w", err)
	}
	if err := pods.AddIndexers(indexers); err != nil {
		return fmt.Errorf("can't add %s indexer to Pods informer: %w", IndexIPOrName, err)
	}

	k.pods = pods
	return nil
}

func (k *Metadata) initServiceInformer(informerFactory informers.SharedInformerFactory) error {
	services := informerFactory.Core().V1().Services().Informer()
	// Transform any *v1.Service instance into a *Info instance to save space
	// in the informer's cache
	if err := services.SetTransform(func(i interface{}) (interface{}, error) {
		svc, ok := i.(*v1.Service)
		if !ok {
			return nil, fmt.Errorf("was expecting a Service. Got: %T", i)
		}
		if svc.Spec.ClusterIP == v1.ClusterIPNone {
			return nil, errors.New("not indexing service without ClusterIP")
		}
		return &Info{
			ObjectMeta: metav1.ObjectMeta{
				Name:      svc.Name,
				Namespace: svc.Namespace,
			},
			Type: typeService,
			ips:  svc.Spec.ClusterIPs,
		}, nil
	}); err != nil {
		return fmt.Errorf("can't set services transform: %w", err)
	}
	if err := services.AddIndexers(indexers); err != nil {
		return fmt.Errorf("can't add %s indexer to Services informer: %w", IndexIPOrName, err)
	}

	k.services = services
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
	err = k.initServiceInformer(informerFactory)
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
