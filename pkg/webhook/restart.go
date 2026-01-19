package webhook

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// RestartDeployment triggers a rollout restart of a deployment by patching its pod template annotations
func RestartDeployment(ctx context.Context, namespace, deploymentName string) error {
	// Create in-cluster config
	config, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("failed to get in-cluster config: %w", err)
	}

	// Create clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create clientset: %w", err)
	}

	// Patch the deployment to trigger restart
	// Using a Beyla-specific annotation that should be configured to be ignored by ArgoCD
	// Add to ArgoCD config: ignoreDifferences for /spec/template/metadata/annotations/beyla.grafana.com~1restartedAt
	patch := []byte(fmt.Sprintf(`{
		"spec": {
			"template": {
				"metadata": {
					"annotations": {
						"beyla.grafana.com/restartedAt": "%s"
					}
				}
			}
		}
	}`, time.Now().Format(time.RFC3339)))

	_, err = clientset.AppsV1().Deployments(namespace).Patch(
		ctx,
		deploymentName,
		types.StrategicMergePatchType,
		patch,
		metav1.PatchOptions{},
	)
	if err != nil {
		return fmt.Errorf("failed to patch deployment %s/%s: %w", namespace, deploymentName, err)
	}

	return nil
}

// RestartDeploymentByDeletingPods triggers a rolling restart by deleting pods one at a time (ArgoCD-friendly, no drift)
// Waits for each new pod to be ready before deleting the next, respecting PodDisruptionBudgets
func RestartDeploymentByDeletingPods(ctx context.Context, namespace, deploymentName string) error {
	config, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("failed to get in-cluster config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create clientset: %w", err)
	}

	// Get the deployment to find its label selector
	deployment, err := clientset.AppsV1().Deployments(namespace).Get(ctx, deploymentName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get deployment: %w", err)
	}

	// Convert label selector to string
	selector := metav1.FormatLabelSelector(deployment.Spec.Selector)

	// List all pods for this deployment
	pods, err := clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: selector,
	})
	if err != nil {
		return fmt.Errorf("failed to list pods: %w", err)
	}

	// Delete pods one at a time to simulate rolling update behavior
	for _, pod := range pods.Items {
		// Delete the pod
		err = clientset.CoreV1().Pods(namespace).Delete(ctx, pod.Name, metav1.DeleteOptions{})
		if err != nil {
			return fmt.Errorf("failed to delete pod %s: %w", pod.Name, err)
		}

		// Wait for a new pod to be ready before continuing
		// This ensures rolling update behavior with zero downtime
		err = waitForDeploymentReady(ctx, clientset, namespace, deploymentName, 2*time.Minute)
		if err != nil {
			return fmt.Errorf("deployment did not become ready after deleting pod %s: %w", pod.Name, err)
		}
	}

	return nil
}

// waitForDeploymentReady waits until the deployment has all desired replicas ready
func waitForDeploymentReady(ctx context.Context, clientset *kubernetes.Clientset, namespace, name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		deployment, err := clientset.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}

		// Check if deployment is ready (all replicas available and up-to-date)
		if deployment.Status.Replicas == deployment.Status.ReadyReplicas &&
			deployment.Status.Replicas == deployment.Status.UpdatedReplicas &&
			deployment.Status.UnavailableReplicas == 0 {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
			// Poll every 2 seconds
		}
	}

	return fmt.Errorf("timeout waiting for deployment %s/%s to be ready", namespace, name)
}

// RestartDeploymentsWithAnnotation triggers a rollout restart for all deployments with a specific annotation
// Example: RestartDeploymentsWithAnnotation(ctx, "default", "beyla.grafana.com/auto-instrument", "enabled")
func RestartDeploymentsWithAnnotation(ctx context.Context, namespace, annotationKey, annotationValue string) error {
	config, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("failed to get in-cluster config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create clientset: %w", err)
	}

	// List all deployments in namespace (can't filter by annotation in API)
	deployments, err := clientset.AppsV1().Deployments(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list deployments: %w", err)
	}

	// Filter by annotation and restart
	for _, deployment := range deployments.Items {
		if val, ok := deployment.Annotations[annotationKey]; ok && val == annotationValue {
			if err := RestartDeployment(ctx, namespace, deployment.Name); err != nil {
				return fmt.Errorf("failed to restart deployment %s: %w", deployment.Name, err)
			}
		}
	}

	return nil
}

// RestartAllDeploymentsInNamespace triggers a rollout restart for all deployments in a namespace
func RestartAllDeploymentsInNamespace(ctx context.Context, namespace string) error {
	config, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("failed to get in-cluster config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create clientset: %w", err)
	}

	deployments, err := clientset.AppsV1().Deployments(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list deployments: %w", err)
	}

	for _, deployment := range deployments.Items {
		if err := RestartDeployment(ctx, namespace, deployment.Name); err != nil {
			return fmt.Errorf("failed to restart deployment %s: %w", deployment.Name, err)
		}
	}

	return nil
}
