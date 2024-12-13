package meta

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/testing/protocmp"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/grafana/beyla/pkg/kubecache/informer"
	"github.com/grafana/beyla/pkg/kubecache/instrument"
	"github.com/grafana/beyla/pkg/kubecache/meta/cni"
)

const (
	kubeConfigEnvVariable = "KUBECONFIG"
	typeNode              = "Node"
	typePod               = "Pod"
	typeService           = "Service"
	defaultResyncTime     = 30 * time.Minute
	EnvServiceName        = "OTEL_SERVICE_NAME"
	EnvResourceAttrs      = "OTEL_RESOURCE_ATTRIBUTES"
	defaultSyncTimeout    = 60 * time.Second
)

var usefulEnvVars = map[string]struct{}{EnvServiceName: {}, EnvResourceAttrs: {}}

type informersConfig struct {
	kubeConfigPath  string
	resyncPeriod    time.Duration
	disableNodes    bool
	disableServices bool

	restrictNode string

	// waits for cache synchronization at start
	waitCacheSync    bool
	cacheSyncTimeout time.Duration

	kubeClient kubernetes.Interface
}

// global object used for comparing protobuf messages in the informers event handlers
var protoCmpTransform = protocmp.Transform()

type InformerOption func(*informersConfig)

func WithKubeConfigPath(path string) InformerOption {
	return func(c *informersConfig) {
		c.kubeConfigPath = path
	}
}

func WithResyncPeriod(period time.Duration) InformerOption {
	return func(c *informersConfig) {
		c.resyncPeriod = period
	}
}

func WithoutNodes() InformerOption {
	return func(c *informersConfig) {
		c.disableNodes = true
	}
}

func WithoutServices() InformerOption {
	return func(c *informersConfig) {
		c.disableServices = true
	}
}

func RestrictNode(nodeName string) InformerOption {
	return func(c *informersConfig) {
		c.restrictNode = nodeName
	}
}

func WithKubeClient(client kubernetes.Interface) InformerOption {
	return func(c *informersConfig) {
		c.kubeClient = client
	}
}

func WaitForCacheSync() InformerOption {
	return func(c *informersConfig) {
		c.waitCacheSync = true
	}
}

func WithCacheSyncTimeout(to time.Duration) InformerOption {
	return func(config *informersConfig) {
		config.cacheSyncTimeout = to
	}
}

func InitInformers(ctx context.Context, opts ...InformerOption) (*Informers, error) {
	config := initConfigOpts(opts)
	log := slog.With("component", "kube.Informers")
	svc := &Informers{
		log:          log,
		config:       config,
		BaseNotifier: NewBaseNotifier(log),
		waitForSync:  make(chan struct{}),
	}

	if config.kubeClient == nil {
		kubeCfg, err := loadKubeconfig(config.kubeConfigPath)
		if err != nil {
			return nil, fmt.Errorf("kubeconfig can't be loaded: %w", err)
		}
		config.kubeClient, err = kubernetes.NewForConfig(kubeCfg)
		if err != nil {
			return nil, fmt.Errorf("kubernetes client can't be initialized: %w", err)
		}
	}

	createdFactories, err := svc.initInformers(ctx, config)
	if err != nil {
		return nil, err
	}

	svc.log.Debug("starting kubernetes informers")
	allSynced := sync.WaitGroup{}
	allSynced.Add(len(createdFactories))
	for _, factory := range createdFactories {
		factory.Start(ctx.Done())
		go func() {
			factory.WaitForCacheSync(ctx.Done())
			allSynced.Done()
		}()
	}

	go func() {
		svc.log.Debug("waiting for informers' synchronization")
		allSynced.Wait()
		svc.log.Debug("informers synchronized")
		close(svc.waitForSync)
	}()
	if config.waitCacheSync {
		select {
		case <-svc.waitForSync:
			// continue
		case <-time.After(config.cacheSyncTimeout):
			svc.log.Warn("Kubernetes cache has not been synced after timeout."+
				" The Kubernetes attributes might be incomplete during an initial period."+
				" Consider increasing the BEYLA_KUBE_INFORMERS_SYNC_TIMEOUT value", "timeout", config.cacheSyncTimeout)
		}
	}
	svc.log.Debug("kubernetes informers started")

	return svc, nil

}

func (inf *Informers) initInformers(ctx context.Context, config *informersConfig) ([]informers.SharedInformerFactory, error) {
	var informerFactory informers.SharedInformerFactory
	if config.restrictNode == "" {
		informerFactory = informers.NewSharedInformerFactory(inf.config.kubeClient, inf.config.resyncPeriod)
	} else {
		informerFactory = informers.NewSharedInformerFactoryWithOptions(inf.config.kubeClient, inf.config.resyncPeriod,
			informers.WithTweakListOptions(func(options *metav1.ListOptions) {
				options.FieldSelector = fields.Set{"spec.nodeName": config.restrictNode}.String()
			}))
	}
	createdFactories := []informers.SharedInformerFactory{informerFactory}
	if err := inf.initPodInformer(ctx, informerFactory); err != nil {
		return nil, err
	}

	if !inf.config.disableNodes {
		nodeIFactory := informerFactory
		if config.restrictNode != "" {
			nodeIFactory = informers.NewSharedInformerFactoryWithOptions(inf.config.kubeClient, inf.config.resyncPeriod,
				informers.WithTweakListOptions(func(options *metav1.ListOptions) {
					options.FieldSelector = fields.Set{"metadata.name": config.restrictNode}.String()
				}))
			createdFactories = append(createdFactories, nodeIFactory)
		} // else: use default, unfiltered informerFactory instance
		if err := inf.initNodeIPInformer(ctx, nodeIFactory); err != nil {
			return nil, err
		}
	}
	if !inf.config.disableServices {
		svcIFactory := informerFactory
		if config.restrictNode != "" {
			// informerFactory will be initially set to a "spec.nodeName"-filtered instance, so we need
			// to create an unfiltered one for global services
			svcIFactory = informers.NewSharedInformerFactory(inf.config.kubeClient, inf.config.resyncPeriod)
			createdFactories = append(createdFactories, svcIFactory)
		}
		if err := inf.initServiceIPInformer(ctx, svcIFactory); err != nil {
			return nil, err
		}
	}
	return createdFactories, nil
}

func initConfigOpts(opts []InformerOption) *informersConfig {
	config := &informersConfig{}
	for _, opt := range opts {
		opt(config)
	}
	if config.cacheSyncTimeout == 0 {
		config.cacheSyncTimeout = defaultSyncTimeout
	}
	if config.resyncPeriod == 0 {
		config.resyncPeriod = defaultResyncTime
	}
	return config
}

func loadKubeconfig(kubeConfigPath string) (*rest.Config, error) {
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

// the transformed objects that are stored in the Informers' cache require to embed an ObjectMeta
// instances. Since the informer's cache is only used to list the stored objects, we just need
// something that is unique. We can get rid of many fields for memory saving in big clusters with
// millions of pods
func minimalIndex(om *metav1.ObjectMeta) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Name:      om.Name,
		Namespace: om.Namespace,
		UID:       om.UID,
	}
}

func (inf *Informers) initPodInformer(ctx context.Context, informerFactory informers.SharedInformerFactory) error {
	pods := informerFactory.Core().V1().Pods().Informer()

	// Transform any *v1.Pod instance into a *PodInfo instance to save space
	// in the informer's cache
	if err := pods.SetTransform(func(i interface{}) (interface{}, error) {
		pod, ok := i.(*v1.Pod)
		if !ok {
			// it's Ok. The K8s library just informed from an entity
			// that has been previously transformed/stored/deleted
			if pi, ok := i.(*indexableEntity); ok {
				return pi, nil
			}
			// let's forward the stale object to the event handler
			if obj, stale := i.(cache.DeletedFinalStateUnknown); stale {
				return obj, nil
			}
			return nil, fmt.Errorf("was expecting a *v1.Pod. Got: %T", i)
		}
		return inf.podToIndexableEntity(pod)
	}); err != nil {
		return fmt.Errorf("can't set pods transform: %w", err)
	}

	_, err := pods.AddEventHandler(inf.ipInfoEventHandler(ctx))
	if err != nil {
		return fmt.Errorf("can't register Pod event handler in the K8s informer: %w", err)
	}

	inf.log.Debug("registered Pod event handler in the K8s informer")

	inf.pods = pods
	return nil
}

func (inf *Informers) podToIndexableEntity(pod *v1.Pod) (interface{}, error) {
	containers := make([]*informer.ContainerInfo, 0,
		len(pod.Status.ContainerStatuses)+
			len(pod.Status.InitContainerStatuses)+
			len(pod.Status.EphemeralContainerStatuses))
	for i := range pod.Status.ContainerStatuses {
		cs := &pod.Status.ContainerStatuses[i]
		envs := envsFromContainerSpec(cs.Name, pod.Spec.Containers)
		containers = append(containers,
			&informer.ContainerInfo{
				Name: cs.Name,
				Id:   rmContainerIDSchema(cs.ContainerID),
				Env:  envToMap(inf.config.kubeClient, pod.ObjectMeta, envs),
			},
		)
	}
	for i := range pod.Status.InitContainerStatuses {
		ics := &pod.Status.InitContainerStatuses[i]
		envs := envsFromContainerSpec(ics.Name, pod.Spec.InitContainers)
		containers = append(containers,
			&informer.ContainerInfo{
				Name: ics.Name,
				Id:   rmContainerIDSchema(ics.ContainerID),
				Env:  envToMap(inf.config.kubeClient, pod.ObjectMeta, envs),
			},
		)
	}
	for i := range pod.Status.EphemeralContainerStatuses {
		ecs := &pod.Status.EphemeralContainerStatuses[i]
		var envs []v1.EnvVar
		for i := range pod.Spec.EphemeralContainers {
			c := &pod.Spec.EphemeralContainers[i]
			if c.Name == ecs.Name {
				envs = c.Env
				break
			}
		}
		containers = append(containers,
			&informer.ContainerInfo{
				Name: ecs.Name,
				Id:   rmContainerIDSchema(ecs.ContainerID),
				Env:  envToMap(inf.config.kubeClient, pod.ObjectMeta, envs),
			},
		)
	}

	ips := make([]string, 0, len(pod.Status.PodIPs))
	for _, ip := range pod.Status.PodIPs {
		// ignoring host-networked Pod IPs
		// TODO: check towards all the Status.HostIPs slice
		if ip.IP != pod.Status.HostIP {
			ips = append(ips, ip.IP)
		}
	}

	startTime := pod.GetCreationTimestamp().String()
	return &indexableEntity{
		ObjectMeta: minimalIndex(&pod.ObjectMeta),
		EncodedMeta: &informer.ObjectMeta{
			Name:      pod.Name,
			Namespace: pod.Namespace,
			Labels:    pod.Labels,
			Ips:       ips,
			Kind:      typePod,
			Pod: &informer.PodInfo{
				Uid:          string(pod.UID),
				NodeName:     pod.Spec.NodeName,
				StartTimeStr: startTime,
				Containers:   containers,
				Owners:       ownersFrom(&pod.ObjectMeta),
				HostIp:       pod.Status.HostIP,
			},
		},
	}, nil
}

func envToMap(kc kubernetes.Interface, objMeta metav1.ObjectMeta, containerEnv []v1.EnvVar) map[string]string {
	envMap := map[string]string{}
	for _, envV := range containerEnv {
		if _, ok := usefulEnvVars[envV.Name]; ok {
			if envV.Value != "" {
				envMap[envV.Name] = envV.Value
			} else if envV.ValueFrom != nil {
				if v, err := GetEnvVarRefValue(kc, objMeta.Namespace, envV.ValueFrom, objMeta); err == nil {
					if v != "" {
						envMap[envV.Name] = v
					}
				}
			}
		}
	}

	return envMap
}

func envsFromContainerSpec(containerName string, containers []v1.Container) []v1.EnvVar {
	var envs []v1.EnvVar
	for i := range containers {
		c := &containers[i]
		if c.Name == containerName {
			envs = c.Env
			break
		}
	}
	return envs
}

// rmContainerIDSchema extracts the hex ID of a container ID that is provided in the form:
// containerd://40c03570b6f4c30bc8d69923d37ee698f5cfcced92c7b7df1c47f6f7887378a9
func rmContainerIDSchema(containerID string) string {
	if parts := strings.SplitN(containerID, "://", 2); len(parts) > 1 {
		return parts[1]
	}
	return containerID
}

func (inf *Informers) initNodeIPInformer(ctx context.Context, informerFactory informers.SharedInformerFactory) error {
	nodes := informerFactory.Core().V1().Nodes().Informer()
	// Transform any *v1.Node instance into an *indexableEntity instance to save space
	// in the informer's cache
	if err := nodes.SetTransform(func(i interface{}) (interface{}, error) {
		node, ok := i.(*v1.Node)
		// todo: move to generic function
		if !ok {
			// it's Ok. The K8s library just informed from an entity
			// that has been previously transformed/stored
			if pi, ok := i.(*indexableEntity); ok {
				return pi, nil
			}
			// let's forward the stale object to the event handler
			if obj, stale := i.(cache.DeletedFinalStateUnknown); stale {
				return obj, nil
			}
			return nil, fmt.Errorf("was expecting a *v1.Node. Got: %T", i)
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

		return &indexableEntity{
			ObjectMeta: minimalIndex(&node.ObjectMeta),
			EncodedMeta: &informer.ObjectMeta{
				Name:      node.Name,
				Namespace: node.Namespace,
				Labels:    node.Labels,
				Ips:       ips,
				Kind:      typeNode,
			},
		}, nil
	}); err != nil {
		return fmt.Errorf("can't set nodes transform: %w", err)
	}

	if _, err := nodes.AddEventHandler(inf.ipInfoEventHandler(ctx)); err != nil {
		return fmt.Errorf("can't register Node event handler in the K8s informer: %w", err)
	}
	inf.log.Debug("registered Node event handler in the K8s informer")

	inf.nodes = nodes
	return nil
}

func (inf *Informers) initServiceIPInformer(ctx context.Context, informerFactory informers.SharedInformerFactory) error {
	services := informerFactory.Core().V1().Services().Informer()
	// Transform any *v1.Service instance into a *indexableEntity instance to save space
	// in the informer's cache
	if err := services.SetTransform(func(i interface{}) (interface{}, error) {
		svc, ok := i.(*v1.Service)
		if !ok {
			// it's Ok. The K8s library just informed from an entity
			// that has been previously transformed/stored
			if pi, ok := i.(*indexableEntity); ok {
				return pi, nil
			}
			// let's forward the stale object to the event handler
			if obj, stale := i.(cache.DeletedFinalStateUnknown); stale {
				return obj, nil
			}
			return nil, fmt.Errorf("was expecting a *v1.Service. Got: %T", i)
		}
		var ips []string
		if svc.Spec.ClusterIP != v1.ClusterIPNone {
			ips = svc.Spec.ClusterIPs
		}
		return &indexableEntity{
			ObjectMeta: minimalIndex(&svc.ObjectMeta),
			EncodedMeta: &informer.ObjectMeta{
				Name:      svc.Name,
				Namespace: svc.Namespace,
				Labels:    svc.Labels,
				Ips:       ips,
				Kind:      typeService,
			},
		}, nil
	}); err != nil {
		return fmt.Errorf("can't set services transform: %w", err)
	}

	if _, err := services.AddEventHandler(inf.ipInfoEventHandler(ctx)); err != nil {
		return fmt.Errorf("can't register Service event handler in the K8s informer: %w", err)
	}
	inf.log.Debug("registered Service event handler in the K8s informer")

	inf.services = services
	return nil
}

func headlessService(om *informer.ObjectMeta) bool {
	return len(om.Ips) == 0 && om.Kind == "Service"
}

func (inf *Informers) ipInfoEventHandler(ctx context.Context) *cache.ResourceEventHandlerFuncs {
	metrics := instrument.FromContext(ctx)
	log := inf.log.With("func", "ipInfoEventHandler")
	return &cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			metrics.InformerNew()
			em := obj.(*indexableEntity).EncodedMeta
			log.Debug("AddFunc", "kind", em.Kind, "name", em.Name, "ips", em.Ips)
			// ignore headless services from being added
			if headlessService(obj.(*indexableEntity).EncodedMeta) {
				return
			}
			inf.Notify(&informer.Event{
				Type:     informer.EventType_CREATED,
				Resource: em,
			})
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			metrics.InformerUpdate()
			newEM := newObj.(*indexableEntity).EncodedMeta
			oldEM := oldObj.(*indexableEntity).EncodedMeta
			// ignore headless services from being added
			if headlessService(newEM) && headlessService(oldEM) {
				return
			}
			if cmp.Equal(oldEM, newEM, protoCmpTransform) {
				return
			}
			log.Debug("UpdateFunc", "kind", newEM.Kind, "name", newEM.Name,
				"ips", newEM.Ips, "oldIps", oldEM.Ips)
			inf.Notify(&informer.Event{
				Type:     informer.EventType_UPDATED,
				Resource: newObj.(*indexableEntity).EncodedMeta,
			})
		},
		DeleteFunc: func(obj interface{}) {
			// this type is received when an object was deleted but the watch deletion event was missed
			// while disconnected from the API server. In this case we don't know the final "resting"
			// state of the object, so there's a chance the included `Obj` is stale.
			// We delete it anyway despite some data could be kept in the cache if the last snapshot we have
			// don't contain all the IPs associated to that object
			if stale, ok := obj.(cache.DeletedFinalStateUnknown); ok {
				inf.log.Debug("stale object received in the informer. Deleting", "key", stale.Key)
				if obj, ok = stale.Obj.(*indexableEntity); !ok {
					inf.log.Warn("can't cast stale object to *indexableEntity",
						"obj", stale.Obj, "type", fmt.Sprintf("%T", stale.Obj))
					return
				}
			}
			em := obj.(*indexableEntity).EncodedMeta
			log.Debug("DeleteFunc", "kind", em.Kind, "name", em.Name, "ips", em.Ips)

			metrics.InformerDelete()
			inf.Notify(&informer.Event{
				Type:     informer.EventType_DELETED,
				Resource: obj.(*indexableEntity).EncodedMeta,
			})
		},
	}
}
