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
)

const (
	kubeConfigEnvVariable  = "KUBECONFIG"
	syncTime               = 10 * time.Minute
	IndexPodByContainerIDs = "idx_pod_by_container"
	IndexReplicaSetNames   = "idx_rs"
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
	// pods and replicaSets cache the different K8s types to custom, smaller object types
	pods        cache.SharedIndexInformer
	replicaSets cache.SharedIndexInformer

	stopChan               chan struct{}
	containerEventHandlers []ContainerEventHandler
}

// PodInfo contains precollected metadata for Pods, Nodes and Services.
// Not all the fields are populated for all the above types. To save
// memory, we just keep in memory the necessary data for each Type.
// For more information about which fields are set for each type, please
// refer to the instantiation function of the respective informers.
type PodInfo struct {
	// Informers need that internal object is an ObjectMeta instance
	metav1.ObjectMeta
	NodeName string

	Owner *Owner

	// StartTimeStr caches value of ObjectMeta.StartTimestamp.String()
	StartTimeStr string
	ContainerIDs []string
}

type ReplicaSetInfo struct {
	metav1.ObjectMeta
	DeploymentName string
}

func qName(namespace, name string) string {
	return namespace + "/" + name
}

var podIndexer = cache.Indexers{
	IndexPodByContainerIDs: func(obj interface{}) ([]string, error) {
		pi := obj.(*PodInfo)
		return pi.ContainerIDs, nil
	},
}

// usually all the data required by the discovery and enrichement is inside
// te v1.Pod object. However, when the Pod object has a ReplicaSet as owner,
// if the ReplicaSet is owned by a Deployment, the reported Pod Owner should
// be the Deployment, as the Replicaset is just an intermediate entity
// used by the Deployment that it's actually defined by the user
var replicaSetIndexer = cache.Indexers{
	IndexReplicaSetNames: func(obj interface{}) ([]string, error) {
		rs := obj.(*ReplicaSetInfo)
		return []string{qName(rs.Namespace, rs.Name)}, nil
	},
}

// GetContainerPod fetches metadata from a Pod given the name of one of its containera
func (k *Metadata) GetContainerPod(containerID string) (*PodInfo, bool) {
	objs, err := k.pods.GetIndexer().ByIndex(IndexPodByContainerIDs, containerID)
	if err != nil {
		klog().Debug("error accessing index by container ID. Ignoring", "error", err, "containerID", containerID)
		return nil, false
	}
	if len(objs) == 0 {
		return nil, false
	}
	return objs[0].(*PodInfo), true
}

func (k *Metadata) initPodInformer(informerFactory informers.SharedInformerFactory) error {
	log := klog().With("informer", "Pod")
	pods := informerFactory.Core().V1().Pods().Informer()

	k.initContainerListeners(log, pods)

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

		owner := OwnerFromPodInfo(pod)
		startTime := pod.GetCreationTimestamp().String()
		if log.Enabled(context.TODO(), slog.LevelDebug) {
			log.Debug("inserting pod", "name", pod.Name, "namespace", pod.Namespace,
				"uid", pod.UID, "owner", owner,
				"node", pod.Spec.NodeName, "startTime", startTime,
				"containerIDs", containerIDs)
		}
		return &PodInfo{
			ObjectMeta: metav1.ObjectMeta{
				Name:      pod.Name,
				Namespace: pod.Namespace,
				UID:       pod.UID,
				Labels:    pod.Labels,
			},
			Owner:        owner,
			NodeName:     pod.Spec.NodeName,
			StartTimeStr: startTime,
			ContainerIDs: containerIDs,
		}, nil
	}); err != nil {
		return fmt.Errorf("can't set pods transform: %w", err)
	}
	if err := pods.AddIndexers(podIndexer); err != nil {
		return fmt.Errorf("can't add indexers to Pods informer: %w", err)
	}

	k.pods = pods
	return nil
}

// initContainerListeners listens for deletions of pods, to forward them to the ContainerEventHandler subscribers.
func (k *Metadata) initContainerListeners(log *slog.Logger, pods cache.SharedIndexInformer) {
	if _, err := pods.AddEventHandler(cache.ResourceEventHandlerFuncs{
		DeleteFunc: func(obj interface{}) {
			pod := obj.(*PodInfo)
			log.Debug("deleting containers for pod", "pod", pod.Name, "containers", pod.ContainerIDs)
			for _, listener := range k.containerEventHandlers {
				listener.OnDeletion(pod.ContainerIDs)
			}
		},
	}); err != nil {
		log.Warn("can't attach container listener to the Kubernetes informer."+
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
		var deployment string
		for i := range rs.OwnerReferences {
			or := &rs.OwnerReferences[i]
			if or.APIVersion == "apps/v1" && or.Kind == "Deployment" {
				deployment = or.Name
				break
			}
		}
		if log.Enabled(context.TODO(), slog.LevelDebug) {
			log.Debug("inserting ReplicaSet", "name", rs.Name, "namespace", rs.Namespace,
				"deployment", deployment)
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
	if err := rss.AddIndexers(replicaSetIndexer); err != nil {
		return fmt.Errorf("can't add %s indexer to ReplicaSets informer: %w", IndexReplicaSetNames, err)
	}

	k.replicaSets = rss
	return nil
}

func (k *Metadata) InitFromClient(client kubernetes.Interface, timeout time.Duration) error {
	// Initialization variables
	k.stopChan = make(chan struct{})

	return k.initInformers(client, timeout)
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

// FetchPodOwnerInfo updates the pod owner with the Deployment information, if it exists.
// Pod Info might include a ReplicaSet as owner, and ReplicaSet info
// usually has a Deployment as owner reference, which is the one that we'd really like
// to report as owner.
func (k *Metadata) FetchPodOwnerInfo(pod *PodInfo) {
	if pod.Owner != nil && pod.Owner.Type == OwnerReplicaSet {
		if rsi, ok := k.GetReplicaSetInfo(pod.Namespace, pod.Owner.Name); ok {
			pod.Owner.Owner = &Owner{Type: OwnerDeployment, Name: rsi.DeploymentName}
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
	_, err := k.replicaSets.AddEventHandler(h)
	// passing a snapshot of the currently stored entities
	go func() {
		for _, pod := range k.replicaSets.GetStore().List() {
			h.OnAdd(pod, true)
		}
	}()
	return err
}
