package kube

import (
	"fmt"
	"net"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"

	"github.com/grafana/beyla/pkg/internal/kube/cni"
)

// IPInfo contains precollected metadata for Pods, Nodes and Services.
// Not all the fields are populated for all the above types. To save
// memory, we just keep in memory the necessary data for each Type.
// For more information about which fields are set for each type, please
// refer to the instantiation function of the respective informers.
type IPInfo struct {
	// Informers need that internal object is an ObjectMeta instance
	metav1.ObjectMeta
	Type     string
	Owner    Owner
	HostName string
	HostIP   string
	ips      []string
}

func (k *Metadata) initPodIPInformer(informerFactory informers.SharedInformerFactory) error {
	pods := informerFactory.Core().V1().Pods().Informer()
	// Transform any *v1.Pod instance into a *IPInfo instance to save space
	// in the informer's cache
	if err := pods.SetTransform(func(i interface{}) (interface{}, error) {
		pod, ok := i.(*corev1.Pod)
		if !ok {
			// it's Ok. The K8s library just informed from an entity
			// that has been previously transformed/stored
			if pi, ok := i.(*IPInfo); ok {
				return pi, nil
			}
			return nil, fmt.Errorf("was expecting a Pod. Got: %T", i)
		}
		ips := make([]string, 0, len(pod.Status.PodIPs))
		for _, ip := range pod.Status.PodIPs {
			// ignoring host-networked Pod IPs
			if ip.IP != pod.Status.HostIP {
				ips = append(ips, ip.IP)
			}
		}
		return &IPInfo{
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
	if err := pods.AddIndexers(ipIndexer); err != nil {
		return fmt.Errorf("can't add %s indexer to Pods informer: %w", IndexIP, err)
	}

	k.podsIP = pods
	return nil
}

func (k *Metadata) initServiceIPInformer(informerFactory informers.SharedInformerFactory) error {
	services := informerFactory.Core().V1().Services().Informer()
	// Transform any *v1.Service instance into a *IPInfo instance to save space
	// in the informer's cache
	if err := services.SetTransform(func(i interface{}) (interface{}, error) {
		svc, ok := i.(*corev1.Service)
		if !ok {
			// it's Ok. The K8s library just informed from an entity
			// that has been previously transformed/stored
			if pi, ok := i.(*IPInfo); ok {
				return pi, nil
			}
			return nil, fmt.Errorf("was expecting a Service. Got: %T", i)
		}
		if svc.Spec.ClusterIP == corev1.ClusterIPNone {
			k.log.Warn("Service doesn't have any ClusterIP. Beyla won't decorate their flows",
				"namespace", svc.Namespace, "name", svc.Name)
		}
		return &IPInfo{
			ObjectMeta: metav1.ObjectMeta{
				Name:      svc.Name,
				Namespace: svc.Namespace,
				Labels:    svc.Labels,
			},
			Type: typeService,
			ips:  svc.Spec.ClusterIPs,
		}, nil
	}); err != nil {
		return fmt.Errorf("can't set servicesIP transform: %w", err)
	}
	if err := services.AddIndexers(ipIndexer); err != nil {
		return fmt.Errorf("can't add %s indexer to Pods informer: %w", IndexIP, err)
	}

	k.servicesIP = services
	return nil
}

func (k *Metadata) initNodeIPInformer(informerFactory informers.SharedInformerFactory) error {
	nodes := informerFactory.Core().V1().Nodes().Informer()
	// Transform any *v1.Node instance into a *IPInfo instance to save space
	// in the informer's cache
	if err := nodes.SetTransform(func(i interface{}) (interface{}, error) {
		node, ok := i.(*corev1.Node)
		if !ok {
			// it's Ok. The K8s library just informed from an entity
			// that has been previously transformed/stored
			if pi, ok := i.(*IPInfo); ok {
				return pi, nil
			}
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

		return &IPInfo{
			ObjectMeta: metav1.ObjectMeta{
				Name:      node.Name,
				Namespace: node.Namespace,
				Labels:    node.Labels,
			},
			ips:  ips,
			Type: typeNode,
		}, nil
	}); err != nil {
		return fmt.Errorf("can't set nodesIP transform: %w", err)
	}
	if err := nodes.AddIndexers(ipIndexer); err != nil {
		return fmt.Errorf("can't add %s indexer to Nodes informer: %w", IndexIP, err)
	}
	k.nodesIP = nodes
	return nil
}

func (k *Metadata) GetInfo(ip string) (*IPInfo, bool) {
	if info, ok := k.fetchInformers(ip); ok {
		// Owner data might be discovered after the owned, so we fetch it
		// at the last moment
		if info.Owner.Name == "" {
			info.Owner = k.getOwner(info)
		}
		return info, true
	}

	return nil, false
}

func (k *Metadata) fetchInformers(ip string) (*IPInfo, bool) {
	if info, ok := k.infoForIP(k.podsIP.GetIndexer(), ip); ok {
		// it might happen that the Host is discovered after the Pod
		if info.HostName == "" {
			info.HostName = k.getHostName(info.HostIP)
		}
		return info, true
	}
	if info, ok := k.infoForIP(k.nodesIP.GetIndexer(), ip); ok {
		return info, true
	}
	if info, ok := k.infoForIP(k.servicesIP.GetIndexer(), ip); ok {
		return info, true
	}
	return nil, false
}

func (k *Metadata) infoForIP(idx cache.Indexer, ip string) (*IPInfo, bool) {
	objs, err := idx.ByIndex(IndexIP, ip)
	if err != nil {
		k.log.Debug("error accessing index. Ignoring", "ip", ip, "error", err)
		return nil, false
	}
	if len(objs) == 0 {
		return nil, false
	}
	return objs[0].(*IPInfo), true
}

func (k *Metadata) getOwner(info *IPInfo) Owner {
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
			k.log.Debug("can't get ReplicaSet info from informer. Ignoring",
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

func (k *Metadata) getHostName(hostIP string) string {
	if hostIP != "" {
		if info, ok := k.infoForIP(k.nodesIP.GetIndexer(), hostIP); ok {
			return info.Name
		}
	}
	return ""
}
