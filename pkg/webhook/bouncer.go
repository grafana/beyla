package webhook

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/obi/pkg/pipe/global"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

type PodBouncer struct {
	logger             *slog.Logger
	kubeClient         kubernetes.Interface
	bouncedDeployments map[string]any
}

// Creates a new K8S pod bouncer that will annotate deployments to force them to restart
func NewPodBouncer(ctxInfo *global.ContextInfo) (*PodBouncer, error) {
	kubeClient, err := ctxInfo.K8sInformer.KubeClient()
	if err != nil {
		return nil, fmt.Errorf("can't get kubernetes client: %w", err)
	}

	return &PodBouncer{
		kubeClient:         kubeClient,
		logger:             slog.Default().With("component", "webhook.bouncer"),
		bouncedDeployments: map[string]any{},
	}, nil
}

func mutationKey(namespace, deploymentName string) string {
	return namespace + ":" + deploymentName
}

// Ensures that we have sufficient information to perform the restart
func (b *PodBouncer) CanBeBounced(namespace, deploymentName string) bool {
	return namespace != "" && deploymentName != ""
}

// Prevents double restarts for pods that belong to the same deployment, since
// we mark the deployment, all pods in that deployment will be restarted
func (b *PodBouncer) AlreadyBounced(namespace, deploymentName string) bool {
	_, ok := b.bouncedDeployments[mutationKey(namespace, deploymentName)]
	return ok
}

// RestartDeployment triggers a rollout restart of a deployment by patching its pod template annotations
func (b *PodBouncer) RestartDeployment(ctx context.Context, namespace, deploymentName string) error {
	if !b.CanBeBounced(namespace, deploymentName) {
		return fmt.Errorf("pod missing namespace: %s or deployment name: %s", namespace, deploymentName)
	}

	// We set the mark as bounced immediately even if we fail, so we don't reattempt and fail non-stop
	// if there's a reason for this to not work.
	b.bouncedDeployments[mutationKey(namespace, deploymentName)] = true

	b.logger.Debug("looking to restart",
		"deployment", deploymentName,
		"namespace", namespace)

	// First, verify the deployment exists
	deployment, err := b.kubeClient.AppsV1().Deployments(namespace).Get(ctx, deploymentName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get deployment %s/%s: %w", namespace, deploymentName, err)
	}

	b.logger.Debug("found deployment to restart",
		"deployment", deploymentName,
		"namespace", namespace,
		"replicas", *deployment.Spec.Replicas,
		"currentAnnotations", deployment.Spec.Template.Annotations)

	// Patch the deployment to trigger restart
	// Using a Beyla-specific annotation that should be configured to be ignored by ArgoCD and other CI/CD systems
	// Add to ArgoCD config: ignoreDifferences for /spec/template/metadata/annotations/beyla.grafana.com/restartedAt
	// If not configured to skip, pods might get bounced twice
	restartTime := time.Now().Format(time.RFC3339)
	patch := fmt.Sprintf(`{"spec":{"template":{"metadata":{"annotations":{"beyla.grafana.com/restartedAt":"%s"}}}}}`, restartTime)

	b.logger.Debug("patching deployment", "patch", patch)

	result, err := b.kubeClient.AppsV1().Deployments(namespace).Patch(
		ctx,
		deploymentName,
		types.MergePatchType,
		[]byte(patch),
		metav1.PatchOptions{},
	)
	if err != nil {
		return fmt.Errorf("failed to patch deployment %s/%s: %w", namespace, deploymentName, err)
	}

	b.logger.Info("deployment patched successfully for SDK instrumentation",
		"deployment", deploymentName,
		"namespace", namespace,
		"newAnnotations", result.Spec.Template.Annotations,
		"observedGeneration", result.Status.ObservedGeneration)

	return nil
}
