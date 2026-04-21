package webhook

import (
	"context"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"go.opentelemetry.io/obi/pkg/appolly/services"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"

	"github.com/grafana/beyla/v3/pkg/beyla"
)

// Status represents the injection state of a pod.
type Status string

const (
	StatusInstrumented   Status = "instrumented"
	StatusPendingRestart Status = "pending_restart"
	StatusSkipped        Status = "skipped"
	StatusUnmatched      Status = "unmatched"
)

// Skip reasons for StatusSkipped pods.
const (
	SkipReasonConflict            = "conflict"
	SkipReasonAlreadyInstrumented = "already_instrumented"
	SkipReasonUnsupportedLanguage = "unsupported_language"
	SkipReasonMissingSDKVersion   = "missing_sdk_version"

	// skipReasonAnnotation is set on pods by the bouncer when a skip reason can't
	// be determined from the pod spec alone (e.g. unsupported language from process scan).
	skipReasonAnnotation = "beyla.grafana.com/skip-reason"
)

// systemNamespaces are excluded from the "unmatched" emission even when
// the injector is configured with a wildcard namespace selector.
var systemNamespaces = map[string]bool{
	"kube-system":     true,
	"kube-node-lease": true,
	"kube-public":     true,
}

// PodClassification is the per-pod output of classify.
type PodClassification struct {
	Namespace    string
	WorkloadKind string
	WorkloadName string
	NodeName     string
	Status       Status
	SkipReason   string
}

// classify returns a PodClassification for pod, or nil if the pod is outside
// the scope of the injector configuration (and should be ignored entirely).
// It is a pure function: no global state, no I/O.
// scope should be pre-computed by scopedNamespaces(cfg) once per batch of pods.
func classify(pod *corev1.Pod, matcher *PodMatcher, scope nsScope) *PodClassification {
	ns := pod.Namespace
	if !inScope(ns, scope) {
		return nil
	}

	info := processMetadata(&pod.ObjectMeta)
	_, matched := matcher.MatchProcessInfo(info)

	status, skipReason := classifyStatus(pod, matched)

	kind, name := resolveWorkload(pod)
	return &PodClassification{
		Namespace:    ns,
		WorkloadKind: kind,
		WorkloadName: name,
		NodeName:     pod.Spec.NodeName,
		Status:       status,
		SkipReason:   skipReason,
	}
}

// classifyStatus determines the status and skip reason for a pod given whether it
// matched a selector. For unmatched pods it always returns StatusUnmatched.
func classifyStatus(pod *corev1.Pod, matched bool) (Status, string) {
	if !matched {
		return StatusUnmatched, ""
	}

	// Has our LD_PRELOAD → instrumented by us.
	for i := range pod.Spec.Containers {
		for _, env := range pod.Spec.Containers[i].Env {
			if env.Name == envVarLdPreloadName && env.Value == envVarLdPreloadValue {
				return StatusInstrumented, ""
			}
		}
	}

	// Has a different LD_PRELOAD → we cannot inject without overwriting it.
	for i := range pod.Spec.Containers {
		for _, env := range pod.Spec.Containers[i].Env {
			if env.Name == envVarLdPreloadName && env.Value != "" {
				return StatusSkipped, SkipReasonConflict
			}
		}
	}

	// Has an instrumentation config env var or our label → already instrumented by another tool.
	if podAlreadyInstrumentedByOther(pod) {
		return StatusSkipped, SkipReasonAlreadyInstrumented
	}

	// Has a skip-reason annotation set by the bouncer (e.g. unsupported language).
	if reason, ok := pod.Annotations[skipReasonAnnotation]; ok && reason != "" {
		return StatusSkipped, reason
	}

	// Matches a selector but we haven't mutated it yet — waiting for a pod bounce.
	return StatusPendingRestart, ""
}

// podAlreadyInstrumentedByOther returns true when a pod shows signs of instrumentation
// by another tool (the operator's config file env var, or our label from a previous
// webhook invocation that didn't set LD_PRELOAD for some reason).
func podAlreadyInstrumentedByOther(pod *corev1.Pod) bool {
	for i := range pod.Spec.Containers {
		for _, env := range pod.Spec.Containers[i].Env {
			if env.Name == envOtelInjectorConfigFileName {
				return true
			}
		}
	}
	if val, ok := pod.Labels[instrumentedLabel]; ok && val != "" {
		return true
	}
	return false
}

// nsScope is the pre-computed namespace scope derived from the injector config.
// It is calculated once per Collect() call and passed into classify to avoid
// re-scanning the full config for every pod.
type nsScope struct {
	clusterWide bool
	globs       []*services.GlobAttr
}

// scopedNamespaces analyses the injector configuration and returns an nsScope.
//
//   - If any selector has no k8s_namespace constraint, the scope is cluster-wide
//     (all non-system namespaces are considered in-scope).
//   - Otherwise, the scope is the union of each selector's k8s_namespace glob matchers.
//
// The returned nsScope is a pure function of cfg and can be computed once per
// scrape rather than once per pod.
func scopedNamespaces(cfg *beyla.Config) nsScope {
	for i := range cfg.Injector.Instrument {
		if _, hasNs := cfg.Injector.Instrument[i].Metadata[services.AttrNamespace]; !hasNs {
			return nsScope{clusterWide: true}
		}
	}
	globs := make([]*services.GlobAttr, 0, len(cfg.Injector.Instrument))
	for i := range cfg.Injector.Instrument {
		if g, ok := cfg.Injector.Instrument[i].Metadata[services.AttrNamespace]; ok {
			globs = append(globs, g)
		}
	}
	return nsScope{globs: globs}
}

// isInScope returns true if namespace falls within the watched scope.
// System namespaces are always excluded regardless of config.
func isInScope(namespace string, cfg *beyla.Config) bool {
	return inScope(namespace, scopedNamespaces(cfg))
}

// inScope is the inner check used by both isInScope and Collect (which pre-computes
// the nsScope once).
func inScope(namespace string, scope nsScope) bool {
	if systemNamespaces[namespace] {
		return false
	}
	if scope.clusterWide {
		return true
	}
	for _, g := range scope.globs {
		if g.MatchString(namespace) {
			return true
		}
	}
	return false
}

// resolveWorkload returns the top-level workload kind and name for a pod by walking
// its ownerReferences. For ReplicaSet-owned pods it heuristically extracts the
// Deployment name (strips the last hyphen-suffix), which matches the approach used by
// the OBI informer's own ownersFrom function. Falls back to ("Pod", pod.Name) for
// standalone pods with no owner references.
func resolveWorkload(pod *corev1.Pod) (kind, name string) {
	owners := ownersFrom(&pod.ObjectMeta)
	if top := topOwner(owners); top != nil {
		return top.Kind, top.Name
	}
	return "Pod", pod.Name
}

// labelTuple is the unique key for aggregating pod counts in Collect.
type labelTuple struct {
	namespace    string
	workloadKind string
	workloadName string
	nodeName     string
	status       string
	skipReason   string
}

// podLister lists pods on a given node. Abstracted so the StateCollector can be tested
// without a live Kubernetes cluster.
type podLister interface {
	listPodsOnNode(ctx context.Context, nodeName string) ([]corev1.Pod, error)
}

// k8sPodLister implements podLister using a Kubernetes client.
type k8sPodLister struct{ client kubernetes.Interface }

func (l *k8sPodLister) listPodsOnNode(ctx context.Context, nodeName string) ([]corev1.Pod, error) {
	list, err := l.client.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + nodeName,
	})
	if err != nil {
		return nil, err
	}
	return list.Items, nil
}

// StateCollector is a prometheus.Collector that emits one gauge sample per unique
// (namespace, workload_kind, workload_name, node_name, status, skip_reason) tuple,
// representing the current injection state of pods on this node.
//
// Beyla is a DaemonSet, so each instance emits only the pods scheduled to its own
// node. The Hub queries should sum across nodes:
//
//	sum by (k8s_namespace_name, k8s_workload_kind, k8s_workload_name, status) (beyla_injection_pods)
type StateCollector struct {
	lister  podLister
	matcher *PodMatcher
	cfg     *beyla.Config
	ownNode string
	desc    *prometheus.Desc
}

var stateCollectorLabels = []string{
	"k8s_namespace_name",
	"k8s_workload_kind",
	"k8s_workload_name",
	"k8s_node_name",
	"status",
	"skip_reason",
}

// NewStateCollector creates a StateCollector. ownNode should come from the NODE_NAME
// env var (set via downward API in the DaemonSet manifest); OwnNodeName() is a
// convenience helper for that.
func NewStateCollector(client kubernetes.Interface, matcher *PodMatcher, cfg *beyla.Config, ownNode string) *StateCollector {
	return &StateCollector{
		lister:  &k8sPodLister{client: client},
		matcher: matcher,
		cfg:     cfg,
		ownNode: ownNode,
		desc: prometheus.NewDesc(
			attr.VendorPrefix+"_injection_pods",
			"Current number of pods in each SDK injection state, as seen from this Beyla node.",
			stateCollectorLabels,
			nil,
		),
	}
}

// OwnNodeName returns the name of the node this Beyla instance is running on.
// It reads NODE_NAME (set via the downward API in the DaemonSet manifest) and
// falls back to os.Hostname().
func OwnNodeName() string {
	if name := os.Getenv("NODE_NAME"); name != "" {
		return name
	}
	if h, err := os.Hostname(); err == nil {
		return h
	}
	return ""
}

func (c *StateCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.desc
}

// Collect lists all pods on this node, classifies each one, aggregates by label
// tuple, and emits one GaugeValue per tuple. It uses a short timeout so a slow
// API server cannot stall a Prometheus scrape indefinitely.
func (c *StateCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pods, err := c.lister.listPodsOnNode(ctx, c.ownNode)
	if err != nil {
		return
	}

	scope := scopedNamespaces(c.cfg)
	counts := map[labelTuple]int{}
	for i := range pods {
		pc := classify(&pods[i], c.matcher, scope)
		if pc == nil {
			continue
		}
		lt := labelTuple{
			namespace:    pc.Namespace,
			workloadKind: pc.WorkloadKind,
			workloadName: pc.WorkloadName,
			nodeName:     pc.NodeName,
			status:       string(pc.Status),
			skipReason:   pc.SkipReason,
		}
		counts[lt]++
	}

	for lt, count := range counts {
		ch <- prometheus.MustNewConstMetric(
			c.desc,
			prometheus.GaugeValue,
			float64(count),
			lt.namespace,
			lt.workloadKind,
			lt.workloadName,
			lt.nodeName,
			lt.status,
			lt.skipReason,
		)
	}
}
