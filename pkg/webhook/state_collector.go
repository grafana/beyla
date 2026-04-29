package webhook

import (
	"context"
	"log/slog"
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
// the scope of the injector configuration.
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

func classifyStatus(pod *corev1.Pod, matched bool) (Status, string) {
	if !matched {
		return StatusUnmatched, ""
	}

	// Mirror mutatePod: check alreadyInstrumentedByOther before inspecting LD_PRELOAD.
	if alreadyInstrumentedByOther(&pod.Spec, &pod.ObjectMeta) {
		return StatusSkipped, SkipReasonAlreadyInstrumented
	}

	// our LD_PRELOAD -> instrumented, any other non-empty value -> conflict.
	seenConflict := false
	for i := range pod.Spec.Containers {
		for _, env := range pod.Spec.Containers[i].Env {
			if env.Name == envVarLdPreloadName {
				if env.Value == envVarLdPreloadValue {
					return StatusInstrumented, ""
				}
				if env.Value != "" {
					seenConflict = true
				}
			}
		}
	}
	if seenConflict {
		return StatusSkipped, SkipReasonConflict
	}

	return StatusPendingRestart, ""
}

// alreadyInstrumentedByOther returns true when a pod shows signs of instrumentation
// by another tool: the operator's config file env var, or our label from a previous
// webhook invocation.
func alreadyInstrumentedByOther(spec *corev1.PodSpec, meta *metav1.ObjectMeta) bool {
	for i := range spec.Containers {
		for _, env := range spec.Containers[i].Env {
			if env.Name == envOtelInjectorConfigFileName {
				return true
			}
		}
	}
	if val, ok := meta.Labels[instrumentedLabel]; ok && val != "" {
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
// its ownerReferences. Falls back to ("Pod", pod.Name) for standalone pods.
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
type StateCollector struct {
	logger  *slog.Logger
	lister  podLister
	matcher *PodMatcher
	cfg     *beyla.Config
	ownNode string
	desc    *prometheus.Desc
}

// NewStateCollector creates a StateCollector. ownNode should come from the NODE_NAME
// env var (set via downward API in the DaemonSet manifest); OwnNodeName() is a
// convenience helper for that.
func NewStateCollector(client kubernetes.Interface, matcher *PodMatcher, cfg *beyla.Config, ownNode string) *StateCollector {
	return &StateCollector{
		logger:  slog.With("component", "webhook.StateCollector"),
		lister:  &k8sPodLister{client: client},
		matcher: matcher,
		cfg:     cfg,
		ownNode: ownNode,
		desc: prometheus.NewDesc(
			attr.VendorPrefix+"_injection_pods",
			"Current number of pods in each SDK injection state, as seen from this Beyla node.",
			[]string{"k8s_namespace_name", "k8s_workload_kind", "k8s_workload_name", "k8s_node_name", "status", "skip_reason"},
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
// tuple, and emits one GaugeValue per tuple.
func (c *StateCollector) Collect(ch chan<- prometheus.Metric) {
	if c.ownNode == "" {
		c.logger.Warn("skipping pod state collection: node name is empty")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pods, err := c.lister.listPodsOnNode(ctx, c.ownNode)
	if err != nil {
		c.logger.Error("failed to list pods", "node", c.ownNode, "error", err)
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
