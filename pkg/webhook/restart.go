package webhook

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

// restartDeployment triggers a rollout restart of a deployment by patching its pod template annotations
func restartDeployment(ctx context.Context, kubeClient kubernetes.Interface, namespace, deploymentName string) error {
	logger := slog.Default().With("component", "webhook-restart")

	logger.Info("looking to restart",
		"deployment", deploymentName,
		"namespace", namespace)

	// First, verify the deployment exists
	deployment, err := kubeClient.AppsV1().Deployments(namespace).Get(ctx, deploymentName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get deployment %s/%s: %w", namespace, deploymentName, err)
	}

	logger.Info("found deployment to restart",
		"deployment", deploymentName,
		"namespace", namespace,
		"replicas", *deployment.Spec.Replicas,
		"currentAnnotations", deployment.Spec.Template.Annotations)

	// Patch the deployment to trigger restart
	// Using a Beyla-specific annotation that should be configured to be ignored by ArgoCD
	// Add to ArgoCD config: ignoreDifferences for /spec/template/metadata/annotations/beyla.grafana.com/restartedAt
	restartTime := time.Now().Format(time.RFC3339)
	patch := fmt.Sprintf(`{"spec":{"template":{"metadata":{"annotations":{"beyla.grafana.com/restartedAt":"%s"}}}}}`, restartTime)

	logger.Info("patching deployment", "patch", patch)

	result, err := kubeClient.AppsV1().Deployments(namespace).Patch(
		ctx,
		deploymentName,
		types.MergePatchType,
		[]byte(patch),
		metav1.PatchOptions{},
	)
	if err != nil {
		return fmt.Errorf("failed to patch deployment %s/%s: %w", namespace, deploymentName, err)
	}

	logger.Info("deployment patched successfully",
		"deployment", deploymentName,
		"namespace", namespace,
		"newAnnotations", result.Spec.Template.Annotations,
		"observedGeneration", result.Status.ObservedGeneration)

	return nil
}
