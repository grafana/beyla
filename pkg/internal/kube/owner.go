package kube

import (
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	attr "github.com/grafana/beyla/pkg/internal/export/attributes/names"
)

type OwnerLabel attr.Name

const (
	OwnerReplicaSet  = OwnerLabel(attr.K8sReplicaSetName)
	OwnerDeployment  = OwnerLabel(attr.K8sDeploymentName)
	OwnerStatefulSet = OwnerLabel(attr.K8sStatefulSetName)
	OwnerDaemonSet   = OwnerLabel(attr.K8sDaemonSetName)
	OwnerUnknown     = OwnerLabel(attr.K8sUnknownOwnerName)
)

type Owner struct {
	Kind      string
	LabelName OwnerLabel
	Name      string
	// Owner of the owner. For example, a ReplicaSet might be owned by a Deployment
	Owner *Owner
}

// OwnerFrom returns the most plausible Owner reference. It might be
// null if the entity does not have any owner
func OwnerFrom(orefs []metav1.OwnerReference) *Owner {
	// fallback will store any found owner that is not part of the bundled
	// K8s owner types (e.g. argocd rollouts).
	// It will be returned if any of the standard K8s owners are found
	var fallback *Owner
	for i := range orefs {
		or := &orefs[i]
		if or.APIVersion != "apps/v1" {
			fallback = unrecognizedOwner(or)
			continue
		}
		switch or.Kind {
		case "ReplicaSet":
			return &Owner{LabelName: OwnerReplicaSet, Name: or.Name, Kind: or.Kind}
		case "Deployment":
			return &Owner{LabelName: OwnerDeployment, Name: or.Name, Kind: or.Kind}
		case "StatefulSet":
			return &Owner{LabelName: OwnerStatefulSet, Name: or.Name, Kind: or.Kind}
		case "DaemonSet":
			return &Owner{LabelName: OwnerDaemonSet, Name: or.Name, Kind: or.Kind}
		default:
			fallback = unrecognizedOwner(or)
		}
	}
	return fallback
}

func unrecognizedOwner(or *metav1.OwnerReference) *Owner {
	return &Owner{
		LabelName: OwnerLabel(attr.K8sUnknownOwnerName),
		Name:      or.Name,
	}
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
	sb.WriteString(string(o.LabelName))
	sb.WriteByte(':')
	sb.WriteString(o.Name)
}
