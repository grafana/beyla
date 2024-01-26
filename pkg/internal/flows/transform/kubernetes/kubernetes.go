// Copyright Red Hat / IBM
// Copyright Grafana Labs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This implementation is a derivation of the code in
// https://github.com/netobserv/netobserv-ebpf-agent/tree/release-1.4

package kubernetes

import (
	"fmt"
	"log/slog"
	"net"
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

	"github.com/grafana/beyla/pkg/beyla/flows/transform/kubernetes/cni"
)

const (
	kubeConfigEnvVariable = "KUBECONFIG"
	syncTime              = 10 * time.Minute
	IndexIP               = "byIP"
	typeNode              = "Node"
	typePod               = "Pod"
	typeService           = "Service"
)

type kubeDataInterface interface {
	GetInfo(string) (*Info, error)
	InitFromConfig(string) error
}

type KubeData struct {
	kubeDataInterface
	log *slog.Logger
	// pods, nodes and services cache the different object types as *Info pointers
	pods     cache.SharedIndexInformer
	nodes    cache.SharedIndexInformer
	services cache.SharedIndexInformer
	// replicaSets caches the ReplicaSets as partially-filled *ObjectMeta pointers
	replicaSets cache.SharedIndexInformer
	stopChan    chan struct{}
}

type Owner struct {
	Type string
	Name string
}

// Info contains precollected metadata for Pods, Nodes and Services.
// Not all the fields are populated for all the above types. To save
// memory, we just keep in memory the necessary data for each Type.
// For more information about which fields are set for each type, please
// refer to the instantiation function of the respective informers.
type Info struct {
	// Informers need that internal object is an ObjectMeta instance
	metav1.ObjectMeta
	Type     string
	Owner    Owner
	HostName string
	HostIP   string
	ips      []string
}

var commonIndexers = map[string]cache.IndexFunc{
	IndexIP: func(obj interface{}) ([]string, error) {
		return obj.(*Info).ips, nil
	},
}

func (k *KubeData) GetInfo(ip string) (*Info, error) {
	if info, ok := k.fetchInformers(ip); ok {
		// Owner data might be discovered after the owned, so we fetch it
		// at the last moment
		if info.Owner.Name == "" {
			info.Owner = k.getOwner(info)
		}
		return info, nil
	}

	return nil, fmt.Errorf("informers can't find IP %s", ip)
}

func (k *KubeData) fetchInformers(ip string) (*Info, bool) {
	if info, ok := infoForIP(k.pods.GetIndexer(), ip); ok {
		// it might happen that the Host is discovered after the Pod
		if info.HostName == "" {
			info.HostName = k.getHostName(info.HostIP)
		}
		return info, true
	}
	if info, ok := infoForIP(k.nodes.GetIndexer(), ip); ok {
		return info, true
	}
	if info, ok := infoForIP(k.services.GetIndexer(), ip); ok {
		return info, true
	}
	return nil, false
}

func infoForIP(idx cache.Indexer, ip string) (*Info, bool) {
	objs, err := idx.ByIndex(IndexIP, ip)
	if err != nil {
		slog.Debug("error accessing index. Ignoring", "ip", ip, "error", err)
		return nil, false
	}
	if len(objs) == 0 {
		return nil, false
	}
	return objs[0].(*Info), true
}

func (k *KubeData) getOwner(info *Info) Owner {
	if len(info.OwnerReferences) != 0 {
		ownerReference := info.OwnerReferences[0]
		if ownerReference.Kind != "ReplicaSet" {
			return Owner{
				Name: ownerReference.Name,
				Type: ownerReference.Kind,
			}
		}

		item, ok, err := k.replicaSets.GetIndexer().GetByKey(info.Namespace + "/" + ownerReference.Name)
		if err != nil {
			slog.Debug("can't get ReplicaSet info from informer. Ignoring",
				"key", info.Namespace+"/"+ownerReference.Name, "error", err)
		} else if ok {
			rsInfo := item.(*metav1.ObjectMeta)
			if len(rsInfo.OwnerReferences) > 0 {
				return Owner{
					Name: rsInfo.OwnerReferences[0].Name,
					Type: rsInfo.OwnerReferences[0].Kind,
				}
			}
		}
	}
	// If no owner references found, return itself as owner
	return Owner{
		Name: info.Name,
		Type: info.Type,
	}
}

func (k *KubeData) getHostName(hostIP string) string {
	if hostIP != "" {
		if info, ok := infoForIP(k.nodes.GetIndexer(), hostIP); ok {
			return info.Name
		}
	}
	return ""
}

func (k *KubeData) initNodeInformer(informerFactory informers.SharedInformerFactory) error {
	nodes := informerFactory.Core().V1().Nodes().Informer()
	// Transform any *v1.Node instance into a *Info instance to save space
	// in the informer's cache
	if err := nodes.SetTransform(func(i interface{}) (interface{}, error) {
		node, ok := i.(*v1.Node)
		if !ok {
			return nil, fmt.Errorf("was expecting a Node. Got: %T", i)
		}
		ips := make([]string, 0, len(node.Status.Addresses))
		for _, address := range node.Status.Addresses {
			ip := net.ParseIP(address.Address)
			if ip != nil {
				ips = append(ips, ip.String())
			}
		}
		// CNI-dependent logic (must work regardless of whether the CNI is installed)
		ips = cni.AddOvnIPs(ips, node)

		return &Info{
			ObjectMeta: metav1.ObjectMeta{
				Name:      node.Name,
				Namespace: node.Namespace,
				Labels:    node.Labels,
			},
			ips:  ips,
			Type: typeNode,
		}, nil
	}); err != nil {
		return fmt.Errorf("can't set nodes transform: %w", err)
	}
	if err := nodes.AddIndexers(commonIndexers); err != nil {
		return fmt.Errorf("can't add %s indexer to Nodes informer: %w", IndexIP, err)
	}
	k.nodes = nodes
	return nil
}

func (k *KubeData) initPodInformer(informerFactory informers.SharedInformerFactory) error {
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
				Name:            pod.Name,
				Namespace:       pod.Namespace,
				Labels:          pod.Labels,
				OwnerReferences: pod.OwnerReferences,
			},
			Type:   typePod,
			HostIP: pod.Status.HostIP,
			ips:    ips,
		}, nil
	}); err != nil {
		return fmt.Errorf("can't set pods transform: %w", err)
	}
	if err := pods.AddIndexers(commonIndexers); err != nil {
		return fmt.Errorf("can't add %s indexer to Pods informer: %w", IndexIP, err)
	}

	k.pods = pods
	return nil
}

func (k *KubeData) initServiceInformer(informerFactory informers.SharedInformerFactory) error {
	services := informerFactory.Core().V1().Services().Informer()
	// Transform any *v1.Service instance into a *Info instance to save space
	// in the informer's cache
	if err := services.SetTransform(func(i interface{}) (interface{}, error) {
		svc, ok := i.(*v1.Service)
		if !ok {
			return nil, fmt.Errorf("was expecting a Service. Got: %T", i)
		}
		if svc.Spec.ClusterIP == v1.ClusterIPNone {
			k.log.Warn("Service doesn't have any ClusterIP. Beyla won't decorate their flows",
				"namespace", svc.Namespace, "name", svc.Name)
		}
		return &Info{
			ObjectMeta: metav1.ObjectMeta{
				Name:      svc.Name,
				Namespace: svc.Namespace,
				Labels:    svc.Labels,
			},
			Type: typeService,
			ips:  svc.Spec.ClusterIPs,
		}, nil
	}); err != nil {
		return fmt.Errorf("can't set services transform: %w", err)
	}
	if err := services.AddIndexers(commonIndexers); err != nil {
		return fmt.Errorf("can't add %s indexer to Pods informer: %w", IndexIP, err)
	}

	k.services = services
	return nil
}

func (k *KubeData) initReplicaSetInformer(informerFactory informers.SharedInformerFactory) error {
	k.replicaSets = informerFactory.Apps().V1().ReplicaSets().Informer()
	// To save space, instead of storing a complete *appvs1.Replicaset instance, the
	// informer's cache will store a *metav1.ObjectMeta with the minimal required fields
	if err := k.replicaSets.SetTransform(func(i interface{}) (interface{}, error) {
		rs, ok := i.(*appsv1.ReplicaSet)
		if !ok {
			return nil, fmt.Errorf("was expecting a ReplicaSet. Got: %T", i)
		}
		return &metav1.ObjectMeta{
			Name:            rs.Name,
			Namespace:       rs.Namespace,
			OwnerReferences: rs.OwnerReferences,
		}, nil
	}); err != nil {
		return fmt.Errorf("can't set ReplicaSets transform: %w", err)
	}
	return nil
}

func (k *KubeData) InitFromConfig(kubeConfigPath string) error {
	k.log = slog.With("component", "kubernetes.KubeData")
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

	err = k.initInformers(kubeClient)
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

func (k *KubeData) initInformers(client kubernetes.Interface) error {
	informerFactory := informers.NewSharedInformerFactory(client, syncTime)
	err := k.initNodeInformer(informerFactory)
	if err != nil {
		return err
	}
	err = k.initPodInformer(informerFactory)
	if err != nil {
		return err
	}
	err = k.initServiceInformer(informerFactory)
	if err != nil {
		return err
	}
	err = k.initReplicaSetInformer(informerFactory)
	if err != nil {
		return err
	}

	slog.Debug("starting kubernetes informers, waiting for syncronization")
	informerFactory.Start(k.stopChan)
	informerFactory.WaitForCacheSync(k.stopChan)
	slog.Debug("kubernetes informers started")

	return nil
}
