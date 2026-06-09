package webhook

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"

	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/pipe/global"

	"github.com/grafana/beyla/v3/pkg/beyla"
	servicesextra "github.com/grafana/beyla/v3/pkg/services"
	"github.com/grafana/beyla/v3/pkg/webhook/configmap"
)

const (
	stateConfigMapNameSuffix = "-injector-state"

	daemonSetOwnerKind       = "DaemonSet"
	daemonSetOwnerAPIVersion = "apps/v1"

	// ownPodLookupTimeout bounds how long Init waits for the kubelet to publish
	// this pod's container status before giving up. The container ID we match on
	// is written to status.containerStatuses asynchronously after the container
	// starts, so a freshly-started Beyla (the container's own entrypoint) can
	// race ahead of it; polling lets the status converge instead of crashing.
	ownPodLookupTimeout      = 90 * time.Second
	ownPodLookupPollInterval = time.Second
)

// overridable for testing
var saNamespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

// StateConfigMapWriter creates/updates a per-node ConfigMap holding the SDK
// injection criteria and the deployments matched for restart. The ConfigMap is
// owned by the Beyla DaemonSet so it is garbage-collected when Beyla is
// uninstalled from the cluster.
type StateConfigMapWriter struct {
	logger       *slog.Logger
	kubeClient   kubernetes.Interface
	nodeName     string
	ownContainer string
	ownNamespace string
	owner        *metav1.OwnerReference
}

func NewStateConfigMapWriter(ctxInfo *global.ContextInfo, nodeName string) (*StateConfigMapWriter, error) {
	logger := slog.Default().With("component", "webhook.StateConfigMapWriter")

	ownContainer, err := ownContainerID()
	if err != nil {
		return nil, fmt.Errorf("cannot find own container ID: %w", err)
	}

	if nodeName == "" {
		return nil, fmt.Errorf("node name unavailable; cannot derive ConfigMap name")
	}
	kubeClient, err := ctxInfo.K8sInformer.KubeClient()
	if err != nil {
		return nil, fmt.Errorf("can't get kubernetes client: %w", err)
	}

	podNamespace, err := ownNamespace()
	if err != nil {
		return nil, fmt.Errorf("cannot find out the current namespace: %w", err)
	}

	logger.Debug("own namespace", "namespace", podNamespace)

	return &StateConfigMapWriter{
		logger:       logger,
		kubeClient:   kubeClient,
		nodeName:     nodeName,
		ownContainer: ownContainer,
		ownNamespace: podNamespace,
	}, nil
}

func (w *StateConfigMapWriter) Init(ctx context.Context) error {
	// The kubelet publishes status.containerStatuses[].containerID (the field
	// findOwnPod matches on) asynchronously, just after starting the container.
	// Beyla is that container's entrypoint, so on a cold/slow node it routinely
	// reaches this code before the status is populated and the lookup misses.
	// Poll until it converges rather than failing the whole process on first try.
	var owner *metav1.OwnerReference
	var findErr error
	pollErr := wait.PollUntilContextTimeout(ctx, ownPodLookupPollInterval, ownPodLookupTimeout, true,
		func(ctx context.Context) (bool, error) {
			o, err := w.findDaemonSetOwner(ctx)
			if err != nil {
				findErr = err
				w.logger.Debug("own pod not visible yet (kubelet may not have published the container status); retrying",
					"error", err)
				return false, nil
			}
			owner = o
			return true, nil
		})
	if pollErr != nil {
		if findErr != nil {
			return fmt.Errorf("error finding daemonset (gave up after %s): %w", ownPodLookupTimeout, findErr)
		}
		return fmt.Errorf("error finding daemonset: %w", pollErr)
	}
	if owner == nil {
		return fmt.Errorf("no DaemonSet owner found for own pod in namespace %s on node %s", w.ownNamespace, w.nodeName)
	}

	w.owner = owner

	return nil
}

// Write upserts the ConfigMap. The instrumentation criteria comes from the
// Beyla configuration verbatim; eligible is the locally-matched set of
// deployments collected during the initial sync.
func (w *StateConfigMapWriter) Write(
	ctx context.Context,
	config *configmap.InjectConfig,
	eligible []*configmap.EligibleDeployment,
) error {
	configYAML, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("marshal criteria: %w", err)
	}
	eligibleYAML, err := yaml.Marshal(eligible)
	if err != nil {
		return fmt.Errorf("marshal eligible deployments: %w", err)
	}

	name := stateConfigMapName(w.owner.Name, w.nodeName)

	desired := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       w.ownNamespace,
			OwnerReferences: []metav1.OwnerReference{*w.owner},
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "beyla",
				"app.kubernetes.io/component":  "injector-state",
				configmap.SelectorAnnotation:   sanitizeDNS1123(w.nodeName),
			},
			// Annotation (presence-only) is what the external injection
			// controller watches; without it the controller ignores the CM.
			Annotations: map[string]string{
				configmap.SelectorAnnotation: w.nodeName,
			},
		},
		Data: map[string]string{
			configmap.KeyInstrumentation:    string(configYAML),
			configmap.KeyEligibleForRestart: string(eligibleYAML),
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
		w.logger.Debug("created injector state ConfigMap",
			"name", name, "namespace", w.ownNamespace, "eligible", len(eligible))
		return nil
	}

	desired.ResourceVersion = existing.ResourceVersion
	if _, err := cms.Update(ctx, desired, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("update ConfigMap %s/%s: %w", w.ownNamespace, name, err)
	}
	w.logger.Debug("updated injector state ConfigMap",
		"name", name, "namespace", w.ownNamespace, "eligible", len(eligible))
	return nil
}

// findDaemonSetOwner fetches this pod and returns an OwnerReference pointing at
// the parent DaemonSet, or nil if the pod has no DaemonSet owner.
func (w *StateConfigMapWriter) findDaemonSetOwner(ctx context.Context) (*metav1.OwnerReference, error) {
	pod, err := w.findOwnPod(ctx)
	if err != nil {
		return nil, err
	}
	w.logger.Debug("finding own pod", "pod", pod)
	for i := range pod.OwnerReferences {
		ref := &pod.OwnerReferences[i]
		if ref.Kind != daemonSetOwnerKind {
			continue
		}
		controller := true
		blockOwnerDeletion := false
		w.logger.Debug("found owning Daemonset", "owner", ref.Name)
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

func (w *StateConfigMapWriter) findOwnPod(ctx context.Context) (*corev1.Pod, error) {
	pods, err := w.kubeClient.CoreV1().Pods(w.ownNamespace).List(ctx, metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("spec.nodeName", w.nodeName).String(),
	})
	if err != nil {
		return nil, fmt.Errorf("list pods in namespace %s on node %s: %w", w.ownNamespace, w.nodeName, err)
	}
	for i := range pods.Items {
		if podHasContainerID(&pods.Items[i], w.ownContainer) {
			return &pods.Items[i], nil
		}
	}
	return nil, fmt.Errorf("own pod not found in namespace %s on node %s for container ID %s",
		w.ownNamespace, w.nodeName, w.ownContainer)
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

// buildInjectConfig constructs an InjectConfig from the Beyla injector configuration.
// Each selector becomes one Rule whose Config.Env carries all SDK configuration as
// env vars, derived from Beyla as the single source of truth.
func buildInjectConfig(cfg *beyla.Config, endpoint, protocol string) configmap.InjectConfig {
	var env configmap.EnvVars

	// OTLP destination
	env = append(env, corev1.EnvVar{Name: "OTEL_EXPORTER_OTLP_ENDPOINT", Value: endpoint})
	env = append(env, corev1.EnvVar{Name: "OTEL_EXPORTER_OTLP_PROTOCOL", Value: protocol})

	// Signal exporters
	env = append(env,
		corev1.EnvVar{Name: "OTEL_TRACES_EXPORTER", Value: otlpOrNone(cfg.Injector.ExportedSignals.TracesEnabled())},
		corev1.EnvVar{Name: "OTEL_METRICS_EXPORTER", Value: otlpOrNone(cfg.Injector.ExportedSignals.MetricsEnabled())},
		corev1.EnvVar{Name: "OTEL_LOGS_EXPORTER", Value: otlpOrNone(cfg.Injector.ExportedSignals.LogsEnabled())},
	)

	// Propagators
	if len(cfg.Injector.Propagators) > 0 {
		env = append(env, corev1.EnvVar{Name: "OTEL_PROPAGATORS", Value: strings.Join(cfg.Injector.Propagators, ",")})
	}

	// Sampler
	if cfg.Injector.DefaultSampler != nil {
		if cfg.Injector.DefaultSampler.Name != "" {
			env = append(env, corev1.EnvVar{Name: "OTEL_TRACES_SAMPLER", Value: string(cfg.Injector.DefaultSampler.Name)})
		}
		if cfg.Injector.DefaultSampler.Arg != "" {
			env = append(env, corev1.EnvVar{Name: "OTEL_TRACES_SAMPLER_ARG", Value: cfg.Injector.DefaultSampler.Arg})
		}
	}

	// Static resource attributes
	if len(cfg.Injector.Resources.Attributes) > 0 {
		keys := make([]string, 0, len(cfg.Injector.Resources.Attributes))
		for k := range cfg.Injector.Resources.Attributes {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		attrs := make([]string, 0, len(keys))
		for _, k := range keys {
			attrs = append(attrs, fmt.Sprintf("%s=%s", k, cfg.Injector.Resources.Attributes[k]))
		}
		env = append(env, corev1.EnvVar{Name: "OTEL_INJECTOR_RESOURCE_ATTRIBUTES", Value: strings.Join(attrs, ",")})
	}

	// nil (not an empty slice) when there are no selectors, so the marshalled
	// config omits rules entirely rather than emitting an empty list.
	var rules []configmap.Rule
	// Exclusions are emitted first as skip rules. Rules are evaluated in order
	// (first match wins), so a skip rule ahead of the install rules carves the
	// excluded workloads out — e.g. "instrument all except serviceA". Skip rules
	// carry no env; the injector only needs to know not to instrument.
	for _, glob := range cfg.Injector.ExcludeInstrument {
		sel := selectorFromGlob(&glob)
		if sel == nil {
			continue
		}
		rules = append(rules, configmap.Rule{
			Selector: *sel,
			Config:   configmap.RuleConfig{Mode: configmap.ModeSkip},
		})
	}
	for _, glob := range cfg.Injector.Instrument {
		sel := selectorFromGlob(&glob)
		if sel == nil {
			continue
		}
		rules = append(rules, configmap.Rule{
			Selector: *sel,
			Config:   configmap.RuleConfig{Env: env},
		})
	}

	return configmap.InjectConfig{
		ImageVersion: cfg.Injector.ImageVersion,
		Rules:        rules,
		BPFConfig: configmap.BPFConfig{
			SpanMetrics: cfg.AsOBI().SpanMetricsEnabledForTraces(),
			Rules:       rulesFromDiscoveryInstrument(&cfg.Discovery),
		},
	}
}

func ruleFromDefinition(a *services.GlobAttributes, mode configmap.Mode) *configmap.Rule {
	sel := selectorFromGlob(a)

	if sel == nil || sel.IsEmpty() {
		return nil
	}

	return &configmap.Rule{
		Selector: *sel,
		Config:   configmap.RuleConfig{Mode: mode},
	}
}

func rulesFromDiscoveryInstrument(d *servicesextra.BeylaDiscoveryConfig) []configmap.Rule {
	var rules []configmap.Rule

	exc := make(services.GlobDefinitionCriteria, 0, len(d.DefaultExcludeInstrument)+len(d.ExcludeInstrument))
	exc = append(exc, d.DefaultExcludeInstrument...)
	exc = append(exc, d.ExcludeInstrument...)

	for i := range exc {
		if rule := ruleFromDefinition(&exc[i], configmap.ModeSkip); rule != nil {
			rules = append(rules, *rule)
		}
	}

	for i := range d.Instrument {
		if rule := ruleFromDefinition(&d.Instrument[i], configmap.ModeInstall); rule != nil {
			rules = append(rules, *rule)
		}
	}

	return rules
}

func otlpOrNone(enabled bool) string {
	if enabled {
		return "otlp"
	}
	return "none"
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

func ownContainerID() (string, error) {
	info, err := containerInfoFunc(uint32(os.Getpid()))
	if err != nil {
		return "", err
	}
	if info.ContainerID == "" {
		return "", fmt.Errorf("container ID is empty")
	}
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
	return ns, nil
}
