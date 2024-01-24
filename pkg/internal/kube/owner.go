package kube

import (
	"strings"

	v1 "k8s.io/api/core/v1"
)

const (
	NamespaceName   = "k8s.namespace.name"
	PodName         = "k8s.pod.name"
	DeploymentName  = "k8s.deployment.name"
	ReplicaSetName  = "k8s.replicaset.name"
	DaemonSetName   = "k8s.daemonset.name"
	StatefulSetName = "k8s.statefulset.name"
	NodeName        = "k8s.node.name"
	PodUID          = "k8s.pod.uid"
	PodStartTime    = "k8s.pod.start_time"
)

type OwnerType int

const (
	OwnerUnknown = OwnerType(iota)
	OwnerReplicaSet
	OwnerDeployment
	OwnerStatefulSet
	OwnerDaemonSet
)

func (o OwnerType) LabelName() string {
	switch o {
	case OwnerReplicaSet:
		return ReplicaSetName
	case OwnerDeployment:
		return DeploymentName
	case OwnerStatefulSet:
		return StatefulSetName
	case OwnerDaemonSet:
		return DaemonSetName
	default:
		return "k8s.unknown.owner"
	}
}

type Owner struct {
	Type OwnerType
	Name string
	// Owner of the owner. For example, a ReplicaSet might be owned by a Deployment
	Owner *Owner
}

// OwnerFromPodInfo returns the pod Owner reference. It might be
// null if the Pod does not have any owner
func OwnerFromPodInfo(pod *v1.Pod) *Owner {
	for i := range pod.OwnerReferences {
		or := &pod.OwnerReferences[i]
		if or.APIVersion != "apps/v1" {
			continue
		}
		switch or.Kind {
		case "ReplicaSet":
			return &Owner{Type: OwnerReplicaSet, Name: or.Name}
		case "Deployment":
			return &Owner{Type: OwnerDeployment, Name: or.Name}
		case "StatefulSet":
			return &Owner{Type: OwnerStatefulSet, Name: or.Name}
		case "DaemonSet":
			return &Owner{Type: OwnerDaemonSet, Name: or.Name}
		}
	}
	return nil
}

func (o *Owner) String() string {
	sb := strings.Builder{}
	o.string(&sb)
	return sb.String()
}

func (o *Owner) string(sb *strings.Builder) {
	if o.Owner != nil {
		o.Owner.string(sb)
		sb.WriteString("->")
	}
	sb.WriteString(o.Type.LabelName())
	sb.WriteByte(':')
	sb.WriteString(o.Name)
}
