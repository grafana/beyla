package meta

import (
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/grafana/beyla-k8s-cache/pkg/informer"
)

type indexableEntity struct {
	metav1.ObjectMeta
	Pod        *informer.PodInfo
	IPInfo     *informer.IPInfo
}

// ownerFrom returns the most plausible Owner reference. It might be
// null if the entity does not have any owner
func ownerFrom(meta *metav1.ObjectMeta) (kind, name string) {
	if len(meta.OwnerReferences) == 0 {
		// If no owner references found, return itself as owner
		return "Pod", meta.Name
	}

	for i := range meta.OwnerReferences {
		or := &meta.OwnerReferences[i]
		if or.APIVersion != "apps/v1" {
			// as fallback, we store any found owner that is not part of the bundled
			// K8s owner types (e.g. argocd rollouts).
			// It will be returned if no standard K8s owners are found
			kind, name = or.Kind, or.Name
			continue
		}
		return topOwner(or.Kind, or.Name)
	}
	return kind, name
}

// topOwner returns the top Owner in the owner chain.
// For example, if the owner is a ReplicaSet, it will return the Deployment name.
func topOwner(kind, name string) (string, string) {
	// we have two levels of ownership at most, and
	// we heuristically extract the Deployment name from the replicaset name
	if kind == "ReplicaSet" {
		if idx := strings.IndexByte(name, '-'); idx > 0 {
			return "Deployment", name[:idx]
		}
	}
	return kind, name
}
