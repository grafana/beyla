package kube

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/grafana/beyla/pkg/internal/helpers/maps"
)

const (
	kubeConfigEnvVariable  = "KUBECONFIG"
	resyncTime             = 10 * time.Minute
	defaultSyncTimeout     = 10 * time.Minute
	IndexPodByContainerIDs = "idx_pod_by_container"
	IndexReplicaSetNames   = "idx_rs"
	IndexIP                = "idx_ip"
	typeNode               = "Node"
	typePod                = "Pod"
	typeService            = "Service"
)

func klog() *slog.Logger {
	return slog.With("component", "kube.Metadata")
}

// ContainerEventHandler listens for the deletion of containers, as triggered
// by a Pod deletion.
type ContainerEventHandler interface {
	OnDeletion(containerID []string)
}

// Metadata stores an in-memory copy of the different Kubernetes objects whose metadata is relevant to us.
type Metadata struct {
	log *slog.Logger
	// pods and replicaSets cache the different K8s types to custom, smaller object types
	pods        cache.SharedIndexInformer
	replicaSets cache.SharedIndexInformer
	nodesIP     cache.SharedIndexInformer
	servicesIP  cache.SharedIndexInformer

	containerEventHandlers []ContainerEventHandler

	disabledInformers maps.Bits
}

// PodInfo contains precollected metadata for Pods.
type PodInfo struct {
	// Informers need that internal object is an ObjectMeta instance
	metav1.ObjectMeta
	NodeName string

	Owner *Owner

	// StartTimeStr caches value of ObjectMeta.StartTimestamp.String()
	StartTimeStr string
	ContainerIDs []string
	IPInfo       IPInfo
}

// ServiceInfo contains precollected metadata for services.
type ServiceInfo struct {
	metav1.ObjectMeta
	IPInfo IPInfo
}

// ReplicaSetInfo contains precollected metadata for ReplicaSets
type ReplicaSetInfo struct {
	metav1.ObjectMeta
	Owner *Owner
}

// NodeInfo contains precollected metadata for nodes
type NodeInfo struct {
	metav1.ObjectMeta
	IPInfo IPInfo
}

func qName(namespace, name string) string {
	return namespace + "/" + name
}

var podIndexers = cache.Indexers{
	IndexPodByContainerIDs: func(obj interface{}) ([]string, error) {
		pi := obj.(*PodInfo)
		return pi.ContainerIDs, nil
	},
	IndexIP: func(obj interface{}) ([]string, error) {
		pi := obj.(*PodInfo)
		return pi.IPInfo.IPs, nil
	},
}

var serviceIndexers = cache.Indexers{
	IndexIP: func(obj interface{}) ([]string, error) {
		pi := obj.(*ServiceInfo)
		return pi.IPInfo.IPs, nil
	},
}

var nodeIndexers = cache.Indexers{
	IndexIP: func(obj interface{}) ([]string, error) {
		pi := obj.(*NodeInfo)
		return pi.IPInfo.IPs, nil
	},
}

// usually all the data required by the discovery and enrichement is inside
// te v1.Pod object. However, when the Pod object has a ReplicaSet as owner,
// if the ReplicaSet is owned by a Deployment, the reported Pod Owner should
// be the Deployment, as the Replicaset is just an intermediate entity
// used by the Deployment that it's actually defined by the user
var replicaSetIndexers = cache.Indexers{
	IndexReplicaSetNames: func(obj interface{}) ([]string, error) {
		rs := obj.(*ReplicaSetInfo)
		return []string{qName(rs.Namespace, rs.Name)}, nil
	},
}

// GetContainerPod fetches metadata from a Pod given the name of one of its containers
func (k *Metadata) GetContainerPod(containerID string) (*PodInfo, bool) {
	objs, err := k.pods.GetIndexer().ByIndex(IndexPodByContainerIDs, containerID)
	if err != nil {
		k.log.Debug("error accessing index by container ID. Ignoring", "error", err, "containerID", containerID)
		return nil, false
	}
	if len(objs) == 0 {
		return nil, false
	}
	return objs[0].(*PodInfo), true
}

func (k *Metadata) initPodInformer(informerFactory informers.SharedInformerFactory) error {
	pods := informerFactory.Core().V1().Pods().Informer()

	k.initContainerListeners(pods)

	// Transform any *v1.Pod instance into a *PodInfo instance to save space
	// in the informer's cache
	if err := pods.SetTransform(func(i interface{}) (interface{}, error) {
		pod, ok := i.(*v1.Pod)
		if !ok {
			// it's Ok. The K8s library just informed from an entity
			// that has been previously transformed/stored
			if pi, ok := i.(*PodInfo); ok {
				return pi, nil
			}
			return nil, fmt.Errorf("was expecting a Pod. Got: %T", i)
		}
		containerIDs := make([]string, 0,
			len(pod.Status.ContainerStatuses)+
				len(pod.Status.InitContainerStatuses)+
				len(pod.Status.EphemeralContainerStatuses))
		for i := range pod.Status.ContainerStatuses {
			containerIDs = append(containerIDs,
				rmContainerIDSchema(pod.Status.ContainerStatuses[i].ContainerID))
		}
		for i := range pod.Status.InitContainerStatuses {
			containerIDs = append(containerIDs,
				rmContainerIDSchema(pod.Status.InitContainerStatuses[i].ContainerID))
		}
		for i := range pod.Status.EphemeralContainerStatuses {
			containerIDs = append(containerIDs,
				rmContainerIDSchema(pod.Status.EphemeralContainerStatuses[i].ContainerID))
		}

		ips := make([]string, 0, len(pod.Status.PodIPs))
		for _, ip := range pod.Status.PodIPs {
			// ignoring host-networked Pod IPs
			if ip.IP != pod.Status.HostIP {
				ips = append(ips, ip.IP)
			}
		}

		owner := OwnerFrom(pod.OwnerReferences)
		startTime := pod.GetCreationTimestamp().String()
		if k.log.Enabled(context.TODO(), slog.LevelDebug) {
			k.log.Debug("inserting pod", "name", pod.Name, "namespace", pod.Namespace,
				"uid", pod.UID, "owner", owner,
				"node", pod.Spec.NodeName, "startTime", startTime,
				"containerIDs", containerIDs)
		}
		return &PodInfo{
			ObjectMeta: metav1.ObjectMeta{
				Name:            pod.Name,
				Namespace:       pod.Namespace,
				UID:             pod.UID,
				Labels:          pod.Labels,
				OwnerReferences: pod.OwnerReferences,
			},
			Owner:        owner,
			NodeName:     pod.Spec.NodeName,
			StartTimeStr: startTime,
			ContainerIDs: containerIDs,
			IPInfo: IPInfo{
				Kind:   typePod,
				HostIP: pod.Status.HostIP,
				IPs:    ips,
			},
		}, nil
	}); err != nil {
		return fmt.Errorf("can't set pods transform: %w", err)
	}
	if err := pods.AddIndexers(podIndexers); err != nil {
		return fmt.Errorf("can't add indexers to Pods informer: %w", err)
	}

	k.pods = pods
	return nil
}

// initContainerListeners listens for deletions of pods, to forward them to the ContainerEventHandler subscribers.
func (k *Metadata) initContainerListeners(pods cache.SharedIndexInformer) {
	if _, err := pods.AddEventHandler(cache.ResourceEventHandlerFuncs{
		DeleteFunc: func(obj interface{}) {
			pod := obj.(*PodInfo)
			k.log.Debug("deleting containers for pod", "pod", pod.Name, "containers", pod.ContainerIDs)
			for _, listener := range k.containerEventHandlers {
				listener.OnDeletion(pod.ContainerIDs)
			}
		},
	}); err != nil {
		k.log.Warn("can't attach container listener to the Kubernetes informer."+
			" Your kubernetes metadata might be outdated in the long term", "error", err)
	}
}

// rmContainerIDSchema extracts the hex ID of a container ID that is provided in the form:
// containerd://40c03570b6f4c30bc8d69923d37ee698f5cfcced92c7b7df1c47f6f7887378a9
func rmContainerIDSchema(containerID string) string {
	if parts := strings.Split(containerID, "://"); len(parts) > 1 {
		return parts[1]
	}
	return containerID
}

// GetReplicaSetInfo fetches metadata from a ReplicaSet given its name
func (k *Metadata) GetReplicaSetInfo(namespace, name string) (*ReplicaSetInfo, bool) {
	if k.disabledInformers.Has(InformerReplicaSet) {
		return nil, false
	}
	objs, err := k.replicaSets.GetIndexer().ByIndex(IndexReplicaSetNames, qName(namespace, name))
	if err != nil {
		klog().Debug("error accessing ReplicaSet index by name. Ignoring",
			"error", err, "name", name)
		return nil, false
	}
	if len(objs) == 0 {
		return nil, false
	}
	return objs[0].(*ReplicaSetInfo), true
}

func (k *Metadata) initReplicaSetInformer(informerFactory informers.SharedInformerFactory) error {
	if k.disabledInformers.Has(InformerReplicaSet) {
		return nil
	}
	log := klog().With("informer", "ReplicaSet")
	rss := informerFactory.Apps().V1().ReplicaSets().Informer()
	// Transform any *appsv1.Replicaset instance into a *ReplicaSetInfo instance to save space
	// in the informer's cache
	if err := rss.SetTransform(func(i interface{}) (interface{}, error) {
		rs, ok := i.(*appsv1.ReplicaSet)
		if !ok {
			// it's Ok. The K8s library just informed from an entity
			// that has been previously transformed/stored
			if pi, ok := i.(*ReplicaSetInfo); ok {
				return pi, nil
			}
			return nil, fmt.Errorf("was expecting a ReplicaSet. Got: %T", i)
		}
		owner := OwnerFrom(rs.OwnerReferences)
		if log.Enabled(context.TODO(), slog.LevelDebug) {
			log.Debug("inserting ReplicaSet", "name", rs.Name, "namespace", rs.Namespace,
				"owner", owner)
		}
		return &ReplicaSetInfo{
			ObjectMeta: metav1.ObjectMeta{
				Name:            rs.Name,
				Namespace:       rs.Namespace,
				OwnerReferences: rs.OwnerReferences,
			},
			Owner: owner,
		}, nil
	}); err != nil {
		return fmt.Errorf("can't set pods transform: %w", err)
	}
	if err := rss.AddIndexers(replicaSetIndexers); err != nil {
		return fmt.Errorf("can't add %s indexer to ReplicaSets informer: %w", IndexReplicaSetNames, err)
	}

	k.replicaSets = rss
	return nil
}

func (k *Metadata) InitFromClient(ctx context.Context, client kubernetes.Interface, timeout time.Duration) error {
	// Initialization variables
	k.log = klog()
	return k.initInformers(ctx, client, timeout)
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

func (k *Metadata) initInformers(ctx context.Context, client kubernetes.Interface, syncTimeout time.Duration) error {
	if syncTimeout <= 0 {
		syncTimeout = defaultSyncTimeout
	}
	informerFactory := informers.NewSharedInformerFactory(client, resyncTime)
	if err := k.initPodInformer(informerFactory); err != nil {
		return err
	}
	if err := k.initNodeIPInformer(informerFactory); err != nil {
		return err
	}
	if err := k.initServiceIPInformer(informerFactory); err != nil {
		return err
	}
	if err := k.initReplicaSetInformer(informerFactory); err != nil {
		return err
	}

	log := klog()
	log.Debug("starting kubernetes informers, waiting for syncronization")
	informerFactory.Start(ctx.Done())
	finishedCacheSync := make(chan struct{})
	go func() {
		informerFactory.WaitForCacheSync(ctx.Done())
		close(finishedCacheSync)
	}()
	select {
	case <-finishedCacheSync:
		log.Debug("kubernetes informers started")
		return nil
	case <-time.After(syncTimeout):
		return fmt.Errorf("kubernetes cache has not been synced after %s timeout", syncTimeout)
	}
}

// FetchPodOwnerInfo updates the pod owner with the Deployment information, if it exists.
// Pod Info might include a ReplicaSet as owner, and ReplicaSet info
// usually has a Deployment as owner reference, which is the one that we'd really like
// to report as owner.
func (k *Metadata) FetchPodOwnerInfo(pod *PodInfo) {
	if pod.Owner != nil && pod.Owner.LabelName == OwnerReplicaSet {
		if rsi, ok := k.GetReplicaSetInfo(pod.Namespace, pod.Owner.Name); ok {
			pod.Owner.Owner = rsi.Owner
		}
	}
}

func (k *Metadata) AddContainerEventHandler(eh ContainerEventHandler) {
	k.containerEventHandlers = append(k.containerEventHandlers, eh)
}

func (k *Metadata) AddPodEventHandler(h cache.ResourceEventHandler) error {
	_, err := k.pods.AddEventHandler(h)
	// passing a snapshot of the currently stored entities
	go func() {
		for _, pod := range k.pods.GetStore().List() {
			h.OnAdd(pod, true)
		}
	}()
	return err
}

func (k *Metadata) AddReplicaSetEventHandler(h cache.ResourceEventHandler) error {
	if k.disabledInformers.Has(InformerReplicaSet) {
		return nil
	}
	_, err := k.replicaSets.AddEventHandler(h)
	// passing a snapshot of the currently stored entities
	go func() {
		for _, pod := range k.replicaSets.GetStore().List() {
			h.OnAdd(pod, true)
		}
	}()
	return err
}

func (k *Metadata) AddNodeEventHandler(h cache.ResourceEventHandler) error {
	if k.disabledInformers.Has(InformerNode) {
		return nil
	}
	_, err := k.nodesIP.AddEventHandler(h)
	// passing a snapshot of the currently stored entities
	go func() {
		for _, node := range k.nodesIP.GetStore().List() {
			h.OnAdd(node, true)
		}
	}()
	return err
}

func (i *PodInfo) ServiceName() string {
	if i.Owner != nil {
		// we have two levels of ownership at most
		if i.Owner.Owner != nil {
			return i.Owner.Owner.Name
		}

		return i.Owner.Name
	}

	return i.Name
}
