package webhook

import (
	"log/slog"
	"os"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.opentelemetry.io/obi/pkg/appolly/services"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
	"go.opentelemetry.io/obi/pkg/transform"

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

// PodClassification is the per-pod output of classify and classifyFromInformer.
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
// Retained for test coverage of the underlying classification helpers.
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
type nsScope struct {
	clusterWide bool
	globs       []*services.GlobAttr
}

// scopedNamespaces analyses the injector configuration and returns an nsScope.
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

// PodStateCache is an event-driven cache of pod injection states. It implements
// meta.Observer to receive pod events from the kube informer store and
// prometheus.Collector to expose the aggregated state as a gauge metric.
// This replaces the per-scrape Kubernetes API call used by the old StateCollector.
type PodStateCache struct {
	mu      sync.RWMutex
	pods    map[string]*PodClassification // keyed by pod UID
	synced  bool                          // true after first SYNC_FINISHED
	matcher *PodMatcher
	cfg     *beyla.Config
	ownNode string
	desc    *prometheus.Desc
	logger  *slog.Logger
}

// NewPodStateCache creates a PodStateCache. ownNode should come from OwnNodeName().
func NewPodStateCache(matcher *PodMatcher, cfg *beyla.Config, ownNode string) *PodStateCache {
	return &PodStateCache{
		logger:  slog.With("component", "webhook.PodStateCache"),
		pods:    map[string]*PodClassification{},
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

// ID implements meta.Observer.
func (c *PodStateCache) ID() string { return "webhook-pod-state-cache" }

// markSynced marks the cache as ready to serve metrics. It is called by
// subscribeStateCache after store.Subscribe returns, at which point all
// existing pods have been delivered synchronously as CREATED events.
// SYNC_FINISHED from the informer is not forwarded to late subscribers by the
// store, so we set the flag explicitly here instead.
func (c *PodStateCache) markSynced() {
	c.mu.Lock()
	c.synced = true
	c.mu.Unlock()
}

// On implements meta.Observer. It updates the in-memory pod state cache from
// informer events.
func (c *PodStateCache) On(event *informer.Event) error {
	if event.Type == informer.EventType_SYNC_FINISHED {
		c.mu.Lock()
		c.synced = true
		c.mu.Unlock()
		return nil
	}

	if event.Resource == nil || event.GetResource().GetPod() == nil {
		return nil
	}

	pod := event.GetResource()
	uid := pod.Pod.Uid

	switch event.Type {
	case informer.EventType_CREATED, informer.EventType_UPDATED:
		if c.ownNode == "" || pod.Pod.NodeName != c.ownNode {
			return nil
		}
		pc := classifyFromInformer(pod, c.matcher, scopedNamespaces(c.cfg), c.cfg.Injector.PackageVersion())
		c.mu.Lock()
		if pc == nil {
			delete(c.pods, uid)
		} else {
			c.pods[uid] = pc
		}
		c.mu.Unlock()
	case informer.EventType_DELETED:
		c.mu.Lock()
		delete(c.pods, uid)
		c.mu.Unlock()
	}
	return nil
}

func (c *PodStateCache) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.desc
}

// Collect emits one GaugeValue per unique (namespace, workload_kind, workload_name,
// node_name, status, skip_reason) tuple. It returns nothing until the initial
// informer sync completes to avoid emitting misleading zeros at startup.
func (c *PodStateCache) Collect(ch chan<- prometheus.Metric) {
	if c.ownNode == "" {
		c.logger.Warn("skipping pod state collection: node name is empty")
		return
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.synced {
		return
	}

	counts := map[labelTuple]int{}
	for _, pc := range c.pods {
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

// classifyFromInformer classifies a pod from informer metadata, returning nil if
// the pod is outside the configured namespace scope.
func classifyFromInformer(pod *informer.ObjectMeta, matcher *PodMatcher, scope nsScope, currentVersion string) *PodClassification {
	ns := pod.Namespace
	if !inScope(ns, scope) {
		return nil
	}

	info := processMetadataFromInformer(pod)
	_, matched := matcher.MatchProcessInfo(info)

	status, skipReason := classifyStatusFromInformer(pod, matched, currentVersion)

	kind, name := resolveWorkloadFromInformer(pod)

	nodeName := ""
	if pod.Pod != nil {
		nodeName = pod.Pod.NodeName
	}

	return &PodClassification{
		Namespace:    ns,
		WorkloadKind: kind,
		WorkloadName: name,
		NodeName:     nodeName,
		Status:       status,
		SkipReason:   skipReason,
	}
}

// classifyStatusFromInformer derives pod injection status from informer metadata.
// Limitation: StatusSkipped/conflict (LD_PRELOAD set to a foreign value) is not
// detectable from informer data because LD_PRELOAD is filtered by OBI's usefulEnvVars.
// Conflict pods appear as pending_restart.
func classifyStatusFromInformer(pod *informer.ObjectMeta, matched bool, currentVersion string) (Status, string) {
	if !matched {
		return StatusUnmatched, ""
	}
	if ver, ok := pod.Labels[instrumentedLabel]; ok && ver != "" {
		if ver == currentVersion {
			return StatusInstrumented, ""
		}
		// Label present but version differs — pod will be re-instrumented after restart.
		return StatusPendingRestart, ""
	}
	return StatusPendingRestart, ""
}

// processMetadataFromInformer builds a *ProcessInfo for MatchProcessInfo() from
// informer metadata. Mirrors processMetadata() in mutator.go but works directly
// with *informer.ObjectMeta (owners are already []*informer.Owner).
func processMetadataFromInformer(pod *informer.ObjectMeta) *ProcessInfo {
	ownerName := pod.Name
	var owners []*informer.Owner
	if pod.Pod != nil {
		owners = pod.Pod.Owners
	}
	if top := topOwner(owners); top != nil {
		ownerName = top.Name
	}

	ret := ProcessInfo{}
	ret.metadata = map[string]string{
		services.AttrNamespace: pod.Namespace,
		services.AttrPodName:   pod.Name,
		services.AttrOwnerName: ownerName,
	}
	ret.podLabels = pod.Labels
	ret.podAnnotations = pod.Annotations

	for _, owner := range owners {
		ret.metadata[transform.OwnerLabelName(owner.Kind).Prom()] = owner.Name
	}
	return &ret
}

// resolveWorkloadFromInformer returns the top-level workload kind and name using
// the owner chain already present in the informer ObjectMeta.
func resolveWorkloadFromInformer(pod *informer.ObjectMeta) (kind, name string) {
	if pod.Pod != nil {
		if top := topOwner(pod.Pod.Owners); top != nil {
			return top.Kind, top.Name
		}
	}
	return "Pod", pod.Name
}
