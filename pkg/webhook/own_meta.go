package webhook

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/meta"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
)

func log() *slog.Logger {
	return slog.With("component", "webhook.own_meta")
}

type OwnMeta struct {
	NodeName    string
	ContainerID string
	Namespace   string
	PodName     string
}

func LoadOwnMeta(ctx context.Context, ctxInfo *global.ContextInfo) (om OwnMeta, err error) {
	if om.ContainerID, err = ownContainerID(); err != nil {
		return OwnMeta{}, fmt.Errorf("could not get container ID: %w", err)
	}
	if om.Namespace, err = ownNamespace(); err != nil {
		return OwnMeta{}, fmt.Errorf("could not get namespace: %w", err)
	}
	kubeClient, err := ctxInfo.K8sInformer.KubeClient()
	if err != nil {
		return OwnMeta{}, fmt.Errorf("could not get kube client: %w", err)
	}
	if foundPod, err := ownNodePod(ctx, kubeClient, ctxInfo.NodeMeta, om.Namespace, om.ContainerID); err != nil {
		return OwnMeta{}, fmt.Errorf("could not get pod information: %w", err)
	} else {
		om.PodName = foundPod.Name
		om.NodeName = foundPod.Spec.NodeName
		if envNode := os.Getenv("NODE_NAME"); envNode != "" && om.NodeName != "" {
			log().Warn("the provided NODE_NAME env var does not match the actual Beyla Pod Node Name."+
				" This might have incur in unexpected behavior. Using fetched node name",
				"provided", envNode, "fetched", om.NodeName)
		}
	}
	return om, nil
}

func ownContainerID() (string, error) {
	info, err := containerInfoFunc(uint32(os.Getpid()))
	if err != nil {
		return "", err
	}
	if info.ContainerID == "" {
		return "", fmt.Errorf("container ID is empty")
	}
	log().Debug("own container ID", "containerID", info.ContainerID)
	return info.ContainerID, nil
}

// Reads the namespace name like k8s client-go does it
func ownNamespace() (string, error) {
	data, err := os.ReadFile(saNamespacePath)
	if err != nil {
		return "", fmt.Errorf("read SA namespace: %w", err)
	}
	ns := strings.TrimSpace(string(data))
	if ns == "" {
		return "", fmt.Errorf("SA namespace file is empty")
	}
	log().Debug("own namespace", "namespace", ns)
	return ns, nil
}

func ownNodePod(ctx context.Context, kubeClient kubernetes.Interface, nodeMeta meta.NodeMeta, ns, containerID string) (foundPod *corev1.Pod, err error) {
	candidateNodeNames := []string{
		fields.OneTermEqualSelector("spec.nodeName", ownNodeName()).String(),
	}
	for _, e := range nodeMeta.Metadata {
		if e.Key == attr.Name(semconv.HostNameKey) {
			candidateNodeNames = append(candidateNodeNames,
				fields.OneTermEqualSelector("spec.nodeName", e.Value).String())
			break
		}
	}
	candidateNodeNames = append(candidateNodeNames,
		fields.OneTermEqualSelector("spec.nodeName", nodeMeta.HostID).String(),
		// at this point, someone override the node name with some exotic value: eventually we search in all the nodes
		// of the cluster. This can be time-consuming
		"",
	)
	nlog := log()
	for _, nodeSelector := range candidateNodeNames {
		nlog.Debug("looking for own Pod", "nodeSelector", nodeSelector)
		foundPod, err := podInNode(ctx, kubeClient, ns, containerID, nodeSelector)
		if err != nil {
			return nil, err
		}
		if foundPod != nil {
			return foundPod, nil
		}
	}
	return nil, fmt.Errorf("could not find own pod in the cluster. Namespace %s. ContainerID %s", ns, containerID)
}

func podInNode(ctx context.Context, kubeClient kubernetes.Interface, ns, containerID, nodeSelector string) (foundPod *corev1.Pod, err error) {
	pods, err := kubeClient.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
		FieldSelector: nodeSelector,
	})
	if err != nil {
		return nil, fmt.Errorf("list pods in namespace %s on node %s: %w", ns, nodeSelector, err)
	}
	for i := range pods.Items {
		if podHasContainerID(&pods.Items[i], containerID) {
			return &pods.Items[i], nil
		}
	}
	return nil, nil
}

func podHasContainerID(pod *corev1.Pod, containerID string) bool {
	for i := range pod.Status.ContainerStatuses {
		if containerIDMatches(pod.Status.ContainerStatuses[i].ContainerID, containerID) {
			return true
		}
	}
	return false
}

func containerIDMatches(statusContainerID, ownContainerID string) bool {
	statusContainerID = trimContainerIDScheme(statusContainerID)
	ownContainerID = trimContainerIDScheme(ownContainerID)
	if statusContainerID == "" || ownContainerID == "" {
		return false
	}
	return statusContainerID == ownContainerID
}

func trimContainerIDScheme(containerID string) string {
	if _, id, ok := strings.Cut(containerID, "://"); ok {
		return id
	}
	return containerID
}
