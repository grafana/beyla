package webhook

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"go.opentelemetry.io/obi/pkg/pipe/global"
)

func log() *slog.Logger {
	return slog.With("component", "webhook.own_meta")
}

func OwnPod(ctx context.Context, ctxInfo *global.ContextInfo) (*corev1.Pod, error) {
	containerID, err := ownContainerID()
	if err != nil {
		return nil, fmt.Errorf("could not get container ID: %w", err)
	}
	namespace, err := ownNamespace()
	if err != nil {
		return nil, fmt.Errorf("could not get namespace: %w", err)
	}
	kubeClient, err := ctxInfo.K8sInformer.KubeClient()
	if err != nil {
		return nil, fmt.Errorf("could not get kube client: %w", err)
	}
	if foundPod, err := ownNodePod(ctx, kubeClient, namespace, containerID); err != nil {
		return nil, fmt.Errorf("could not get pod information: %w", err)
	} else {
		return foundPod, nil
	}
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

func ownNodePod(ctx context.Context, kubeClient kubernetes.Interface, ns, containerID string) (*corev1.Pod, error) {
	// We already uniquely identify ourselves by (namespace, containerID). The node name is derived
	// from the found Pod, so there's no need to guess it up-front to build a spec.nodeName field
	// selector. Listing all the Pods of our own namespace is a cheap, one-shot startup call that works
	// regardless of how the node was named.
	log().Debug("looking for own Pod", "namespace", ns, "containerID", containerID)
	pods, err := kubeClient.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list pods in namespace %s: %w", ns, err)
	}
	for i := range pods.Items {
		if podHasContainerID(&pods.Items[i], containerID) {
			return &pods.Items[i], nil
		}
	}
	return nil, fmt.Errorf("could not find own pod in the cluster. Namespace %s. ContainerID %s", ns, containerID)
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
