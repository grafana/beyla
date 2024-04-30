package kube

import (
	"strings"

	v1 "k8s.io/api/core/v1"

	"github.com/grafana/beyla/pkg/internal/export/metric/attr"
)

type OwnerType int

const (
	OwnerUnknown = OwnerType(iota)
	OwnerReplicaSet
	OwnerDeployment
	OwnerStatefulSet
	OwnerDaemonSet
)

func (o OwnerType) LabelName() attr.Name {
	switch o {
	case OwnerReplicaSet:
		return attr.K8sReplicaSetName
	case OwnerDeployment:
		return attr.K8sDeploymentName
	case OwnerStatefulSet:
		return attr.K8sStatefulSetName
	case OwnerDaemonSet:
		return attr.K8sDaemonSetName
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
	sb.WriteString(string(o.Type.LabelName()))
	sb.WriteByte(':')
	sb.WriteString(o.Name)
}
