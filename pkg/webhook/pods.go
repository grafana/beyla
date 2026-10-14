package webhook

import (
	"strings"

	appsv1 "k8s.io/api/apps/v1"

	"go.opentelemetry.io/obi/pkg/appolly/services"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
	"go.opentelemetry.io/obi/pkg/transform"

	"github.com/grafana/beyla/v3/pkg/webhook/configmap"
)

func topOwner(owners []*informer.Owner) *informer.Owner {
	if len(owners) == 0 {
		return nil
	}
	return owners[len(owners)-1]
}

func deploymentNameFromReplicaSet(replicaSetName string, labels map[string]string) string {
	podTemplateHash := labels[appsv1.DefaultDeploymentUniqueLabelKey]
	suffix := "-" + podTemplateHash
	if podTemplateHash != "" && strings.HasSuffix(replicaSetName, suffix) {
		return strings.TrimSuffix(replicaSetName, suffix)
	}
	return replicaSetName
}

// Adds the kubernetes metadata to the matched local process
func addMetadata(pp *ProcessInfo, info *informer.ObjectMeta) *ProcessInfo {
	ownerName := info.Name
	if info.Pod != nil {
		if topOwner := topOwner(info.Pod.Owners); topOwner != nil {
			ownerName = topOwner.Name
		}
	}

	ret := pp

	ret.metadata = map[string]string{
		services.AttrNamespace: info.Namespace,
		services.AttrPodName:   info.Name,
		services.AttrOwnerName: ownerName,
	}
	ret.podLabels = info.Labels
	ret.podAnnotations = info.Annotations

	// Always include the pod itself as the first chain entry so pods are
	// selectable by name via ownerKind: Pod, ownerName: <glob>.
	ret.ownerChain = append(ret.ownerChain, configmap.Owner{Name: info.Name, Kind: "Pod"})
	// add any other owner name (they might be several, e.g. replicaset and deployment)
	for _, owner := range info.Pod.Owners {
		ret.metadata[transform.OwnerLabelName(owner.Kind).Prom()] = owner.Name
		ret.ownerChain = append(ret.ownerChain, configmap.Owner{Name: owner.Name, Kind: owner.Kind})
	}
	return ret
}

func deploymentFromProcess(a *ProcessInfo, stateHash string) *configmap.EligibleDeployment {
	namespace := a.metadata[services.AttrNamespace]
	deployment := a.metadata[attr.K8sDeploymentName.Prom()]

	language := languageLabel(a.kind)

	return &configmap.EligibleDeployment{
		Namespace: namespace,
		Kind:      "Deployment",
		Name:      deployment,
		Language:  language,
		Hash:      stateHash,
	}
}

func deploymentKeyFromProcess(a *ProcessInfo) string {
	namespace := a.metadata[services.AttrNamespace]
	deployment := a.metadata[attr.K8sDeploymentName.Prom()]

	return mutationKey(namespace, deployment)
}
