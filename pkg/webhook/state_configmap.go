package webhook

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/grafana/beyla/v3/pkg/beyla"
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/pipe/global"
)

const (
	stateConfigMapNameSuffix  = "-injector-state"
	stateConfigMapKeyCriteria = "selectors.yaml"
	stateConfigMapKeyEligible = "eligible_deployments.yaml"

	daemonSetOwnerKind       = "DaemonSet"
	daemonSetOwnerAPIVersion = "apps/v1"

	saNamespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

// EligibleDeployment is a workload that matches the SDK injection criteria and
// would be (or has been) bounced by the bouncer.
type EligibleDeployment struct {
	Namespace  string `yaml:"namespace"`
	Kind       string `yaml:"kind,omitempty"`
	Deployment string `yaml:"deployment"`
	Language   string `yaml:"language,omitempty"`
}

// StateConfigMapWriter creates/updates a per-node ConfigMap holding the SDK
// injection criteria and the deployments matched for restart. The ConfigMap is
// owned by the Beyla DaemonSet so it is garbage-collected when Beyla is
// uninstalled from the cluster.
type StateConfigMapWriter struct {
	logger       *slog.Logger
	kubeClient   kubernetes.Interface
	nodeName     string
	name         string
	ownNamespace string
}

// NewStateConfigMapWriter resolves the Beyla pod identity from the downward
// API (POD_NAME, POD_NAMESPACE). It returns an error if either is unset, in
// which case the caller should disable state ConfigMap writing.
func NewStateConfigMapWriter(cfg *beyla.Config, ctxInfo *global.ContextInfo, nodeName string) (*StateConfigMapWriter, error) {
	logger := slog.Default().With("component", "webhook.StateConfigMapWriter")

	fullHostName, err := os.Hostname()
	if err != nil {
		fullHostName = uuid.New().String()
		logger.Warn("cannot determine Beyla instance hostname", "error", err, "uuid", fullHostName)
	}

	if nodeName == "" {
		return nil, fmt.Errorf("node name unavailable; cannot derive ConfigMap name")
	}
	kubeClient, err := ctxInfo.K8sInformer.KubeClient()
	if err != nil {
		return nil, fmt.Errorf("can't get kubernetes client: %w", err)
	}

	myNamespace, err := ownNamespace()
	if err != nil {
		return nil, fmt.Errorf("cannot find out the current namespace", "error", err)
	}

	return &StateConfigMapWriter{
		logger:       logger,
		kubeClient:   kubeClient,
		nodeName:     nodeName,
		name:         fullHostName,
		ownNamespace: myNamespace,
	}, nil
}

// Write upserts the ConfigMap. The instrumentation criteria comes from the
// Beyla configuration verbatim; eligible is the locally-matched set of
// deployments collected during the initial sync.
func (w *StateConfigMapWriter) Write(
	ctx context.Context,
	criteria services.GlobDefinitionCriteria,
	eligible []*EligibleDeployment,
) error {
	owner, err := w.findDaemonSetOwner(ctx)
	if err != nil {
		return err
	}
	if owner == nil {
		return fmt.Errorf("no DaemonSet owner found for pod %s/%s", w.ownNamespace, w.name)
	}

	sortEligible(eligible)

	criteriaYAML, err := yaml.Marshal(criteria)
	if err != nil {
		return fmt.Errorf("marshal criteria: %w", err)
	}
	eligibleYAML, err := yaml.Marshal(eligible)
	if err != nil {
		return fmt.Errorf("marshal eligible deployments: %w", err)
	}

	name := stateConfigMapName(owner.Name, w.nodeName)

	desired := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       w.ownNamespace,
			OwnerReferences: []metav1.OwnerReference{*owner},
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "beyla",
				"app.kubernetes.io/component":  "injector-state",
				"beyla.grafana.com/node":       sanitizeDNS1123(w.nodeName),
			},
		},
		Data: map[string]string{
			stateConfigMapKeyCriteria: string(criteriaYAML),
			stateConfigMapKeyEligible: string(eligibleYAML),
		},
	}

	cms := w.kubeClient.CoreV1().ConfigMaps(w.ownNamespace)
	existing, err := cms.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("get ConfigMap %s/%s: %w", w.ownNamespace, name, err)
		}
		if _, err := cms.Create(ctx, desired, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("create ConfigMap %s/%s: %w", w.ownNamespace, name, err)
		}
		w.logger.Info("created injector state ConfigMap",
			"name", name, "namespace", w.ownNamespace, "eligible", len(eligible))
		return nil
	}

	desired.ResourceVersion = existing.ResourceVersion
	if _, err := cms.Update(ctx, desired, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("update ConfigMap %s/%s: %w", w.ownNamespace, name, err)
	}
	w.logger.Info("updated injector state ConfigMap",
		"name", name, "namespace", w.ownNamespace, "eligible", len(eligible))
	return nil
}

// findDaemonSetOwner fetches this pod and returns an OwnerReference pointing at
// the parent DaemonSet, or nil if the pod has no DaemonSet owner.
func (w *StateConfigMapWriter) findDaemonSetOwner(ctx context.Context) (*metav1.OwnerReference, error) {
	pod, err := w.kubeClient.CoreV1().Pods(w.ownNamespace).Get(ctx, w.name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get own pod %s/%s: %w", w.ownNamespace, w.name, err)
	}
	for i := range pod.OwnerReferences {
		ref := &pod.OwnerReferences[i]
		if ref.Kind != daemonSetOwnerKind {
			continue
		}
		controller := true
		blockOwnerDeletion := false
		return &metav1.OwnerReference{
			APIVersion:         daemonSetOwnerAPIVersion,
			Kind:               daemonSetOwnerKind,
			Name:               ref.Name,
			UID:                ref.UID,
			Controller:         &controller,
			BlockOwnerDeletion: &blockOwnerDeletion,
		}, nil
	}
	return nil, nil
}

func sortEligible(eligible []*EligibleDeployment) {
	sort.Slice(eligible, func(i, j int) bool {
		if eligible[i].Namespace != eligible[j].Namespace {
			return eligible[i].Namespace < eligible[j].Namespace
		}
		return eligible[i].Deployment < eligible[j].Deployment
	})
}

func stateConfigMapName(daemonSetName, nodeName string) string {
	return daemonSetName + stateConfigMapNameSuffix + "-" + sanitizeDNS1123(nodeName)
}

var dns1123InvalidRE = regexp.MustCompile(`[^a-z0-9-]+`)

// sanitizeDNS1123 lowercases and substitutes invalid runes so the result is a
// valid DNS-1123 label fragment. Long node names are truncated so the final
// ConfigMap name fits within the 253-char DNS-1123 subdomain limit with margin.
func sanitizeDNS1123(s string) string {
	if s == "" {
		return "unknown"
	}
	s = strings.ToLower(s)
	s = dns1123InvalidRE.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if s == "" {
		return "unknown"
	}
	const maxLen = 63
	if len(s) > maxLen {
		s = strings.TrimRight(s[:maxLen], "-")
	}
	return s
}

func ownNamespace() (string, error) {
	data, err := os.ReadFile(saNamespacePath)
	if err != nil {
		return "", fmt.Errorf("read SA namespace: %w", err)
	}
	ns := strings.TrimSpace(string(data))
	if ns == "" {
		return "", fmt.Errorf("SA namespace file is empty")
	}
	return ns, nil
}
