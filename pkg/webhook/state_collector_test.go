package webhook

import (
	"log/slog"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"

	"github.com/grafana/beyla/v3/pkg/beyla"
	"github.com/grafana/beyla/v3/pkg/webhook/configmap"
)

// nsMatcher builds a PodMatcher that matches pods in the given namespace.
func nsMatcher(ns string) *PodMatcher {
	return &PodMatcher{
		logger: slog.Default(),
		instrument: configmap.WebhookInstrument{
			{Namespaces: []services.GlobAttr{services.NewGlob(ns)}},
		},
	}
}

// nsLabelMatcher builds a PodMatcher that matches pods in the given namespace
// AND carrying the given pod label key=value.
func nsLabelMatcher(ns, labelKey, labelValue string) *PodMatcher {
	return &PodMatcher{
		logger: slog.Default(),
		instrument: configmap.WebhookInstrument{
			{
				Namespaces: []services.GlobAttr{services.NewGlob(ns)},
				PodLabels:  map[string]services.GlobAttr{labelKey: services.NewGlob(labelValue)},
			},
		},
	}
}

// nsCfg builds a beyla.Config whose Injector.Instrument restricts to ns.
func nsCfg(ns string) *beyla.Config {
	return &beyla.Config{
		Injector: beyla.SDKInject{
			Instrument: configmap.WebhookInstrument{
				{Namespaces: []services.GlobAttr{services.NewGlob(ns)}},
			},
		},
	}
}

// wildcardCfg returns a config with a selector that has no namespace constraint.
func wildcardCfg() *beyla.Config {
	return &beyla.Config{
		Injector: beyla.SDKInject{
			// An empty Selector is a wildcard — matches any pod.
			Instrument: configmap.WebhookInstrument{
				{},
			},
		},
	}
}

// pod builds a minimal corev1.Pod for testing.
func pod(namespace, name string, opts ...func(*corev1.Pod)) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app"}},
		},
	}
	for _, o := range opts {
		o(p)
	}
	return p
}

func withEnv(key, value string) func(*corev1.Pod) {
	return func(p *corev1.Pod) {
		p.Spec.Containers[0].Env = append(p.Spec.Containers[0].Env, corev1.EnvVar{Name: key, Value: value})
	}
}

func withLabel(key, value string) func(*corev1.Pod) {
	return func(p *corev1.Pod) {
		if p.Labels == nil {
			p.Labels = map[string]string{}
		}
		p.Labels[key] = value
	}
}

func withNodeName(node string) func(*corev1.Pod) {
	return func(p *corev1.Pod) { p.Spec.NodeName = node }
}

func withOwner(kind, name, apiVersion string) func(*corev1.Pod) {
	return func(p *corev1.Pod) {
		p.OwnerReferences = append(p.OwnerReferences, metav1.OwnerReference{
			Kind:       kind,
			Name:       name,
			APIVersion: apiVersion,
		})
	}
}

func TestClassify(t *testing.T) {
	const prodNS = "prod"

	tests := []struct {
		name       string
		pod        *corev1.Pod
		matcher    *PodMatcher
		cfg        *beyla.Config
		wantNil    bool
		wantStatus Status
		wantSkip   string
		wantNode   string
	}{
		{
			name:       "instrumented_basic",
			pod:        pod(prodNS, "my-pod", withEnv(envVarLdPreloadName, envVarLdPreloadValue)),
			matcher:    nsMatcher(prodNS),
			cfg:        nsCfg(prodNS),
			wantStatus: StatusInstrumented,
		},
		{
			name:       "pending_restart_basic",
			pod:        pod(prodNS, "my-pod"),
			matcher:    nsMatcher(prodNS),
			cfg:        nsCfg(prodNS),
			wantStatus: StatusPendingRestart,
		},
		{
			name:       "skipped_conflict",
			pod:        pod(prodNS, "my-pod", withEnv(envVarLdPreloadName, "/some/other/lib.so")),
			matcher:    nsMatcher(prodNS),
			cfg:        nsCfg(prodNS),
			wantStatus: StatusSkipped,
			wantSkip:   SkipReasonConflict,
		},
		{
			name:       "skipped_already_instrumented_label",
			pod:        pod(prodNS, "my-pod", withLabel(instrumentedLabel, "v1.2.3")),
			matcher:    nsMatcher(prodNS),
			cfg:        nsCfg(prodNS),
			wantStatus: StatusSkipped,
			wantSkip:   SkipReasonAlreadyInstrumented,
		},
		{
			name:       "skipped_already_instrumented_env",
			pod:        pod(prodNS, "my-pod", withEnv(envOtelInjectorConfigFileName, envOtelInjectorConfigFileValue)),
			matcher:    nsMatcher(prodNS),
			cfg:        nsCfg(prodNS),
			wantStatus: StatusSkipped,
			wantSkip:   SkipReasonAlreadyInstrumented,
		},
		{
			name:       "unmatched_in_scope",
			pod:        pod(prodNS, "other-app"),
			matcher:    nsLabelMatcher(prodNS, "app", "specific-app"),
			cfg:        nsCfg(prodNS),
			wantStatus: StatusUnmatched,
		},
		{
			name:    "out_of_scope_different_namespace",
			pod:     pod("staging", "my-pod"),
			matcher: nsMatcher(prodNS),
			cfg:     nsCfg(prodNS),
			wantNil: true,
		},
		{
			name:    "out_of_scope_system_namespace",
			pod:     pod("kube-system", "my-pod"),
			matcher: &PodMatcher{logger: slog.Default(), instrument: configmap.WebhookInstrument{{}}},
			cfg:     wildcardCfg(),
			wantNil: true,
		},
		{
			name:    "out_of_scope_no_selectors",
			pod:     pod(prodNS, "my-pod"),
			matcher: &PodMatcher{logger: slog.Default()},
			cfg:     &beyla.Config{},
			wantNil: true,
		},
		{
			name:       "node_name_propagated",
			pod:        pod(prodNS, "my-pod", withEnv(envVarLdPreloadName, envVarLdPreloadValue), withNodeName("node-1")),
			matcher:    nsMatcher(prodNS),
			cfg:        nsCfg(prodNS),
			wantStatus: StatusInstrumented,
			wantNode:   "node-1",
		},
		{
			// A pod carrying Beyla's instrumented label AND a foreign LD_PRELOAD must be
			// reported as already_instrumented (not conflict) — alreadyInstrumentedByOther
			// takes priority, mirroring the check order in mutatePod.
			name:       "skipped_already_instrumented_label_beats_conflict",
			pod:        pod(prodNS, "my-pod", withLabel(instrumentedLabel, "v1.2.3"), withEnv(envVarLdPreloadName, "/foreign/lib.so")),
			matcher:    nsMatcher(prodNS),
			cfg:        nsCfg(prodNS),
			wantStatus: StatusSkipped,
			wantSkip:   SkipReasonAlreadyInstrumented,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classify(tt.pod, tt.matcher, scopedNamespaces(tt.cfg))
			if tt.wantNil {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, tt.wantStatus, got.Status, "status")
			assert.Equal(t, tt.wantSkip, got.SkipReason, "skip_reason")
			assert.Equal(t, tt.pod.Namespace, got.Namespace, "namespace")
			if tt.wantNode != "" {
				assert.Equal(t, tt.wantNode, got.NodeName, "node_name")
			}
		})
	}
}

func TestClassifyWorkloadResolution(t *testing.T) {
	const ns = "prod"

	tests := []struct {
		name         string
		pod          *corev1.Pod
		wantKind     string
		wantWorkName string
	}{
		{
			name:         "owner_deployment",
			pod:          pod(ns, "my-pod-abc-xyz", withOwner("ReplicaSet", "my-deploy-abc", "apps/v1")),
			wantKind:     "Deployment",
			wantWorkName: "my-deploy",
		},
		{
			name:         "owner_statefulset",
			pod:          pod(ns, "my-pod-0", withOwner("StatefulSet", "my-ss", "apps/v1")),
			wantKind:     "StatefulSet",
			wantWorkName: "my-ss",
		},
		{
			name:         "owner_daemonset",
			pod:          pod(ns, "my-pod-xyz", withOwner("DaemonSet", "my-ds", "apps/v1")),
			wantKind:     "DaemonSet",
			wantWorkName: "my-ds",
		},
		{
			// ownersFrom heuristically strips the last hyphen-suffix from a Job name to derive
			// a CronJob parent name, so a job name without a hyphen stays as Kind=Job.
			name:         "owner_job_standalone",
			pod:          pod(ns, "myjob-xyz", withOwner("Job", "myjob", "batch/v1")),
			wantKind:     "Job",
			wantWorkName: "myjob",
		},
		{
			// A hyphenated job name triggers the CronJob heuristic in ownersFrom.
			name:         "owner_cronjob_heuristic",
			pod:          pod(ns, "my-cron-12345-xyz", withOwner("Job", "my-cron-12345", "batch/v1")),
			wantKind:     "CronJob",
			wantWorkName: "my-cron",
		},
		{
			name:         "owner_standalone",
			pod:          pod(ns, "standalone-pod"),
			wantKind:     "Pod",
			wantWorkName: "standalone-pod",
		},
	}

	cfg := nsCfg(ns)
	matcher := nsMatcher(ns)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classify(tt.pod, matcher, scopedNamespaces(cfg))
			require.NotNil(t, got)
			assert.Equal(t, tt.wantKind, got.WorkloadKind, "workload_kind")
			assert.Equal(t, tt.wantWorkName, got.WorkloadName, "workload_name")
		})
	}
}

// TestIsInScope covers namespace scope detection.
func TestIsInScope(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		cfg       *beyla.Config
		want      bool
	}{
		{
			name:      "in_scope_explicit_namespace",
			namespace: "prod",
			cfg:       nsCfg("prod"),
			want:      true,
		},
		{
			name:      "in_scope_glob_namespace",
			namespace: "production",
			cfg:       nsCfg("prod*"),
			want:      true,
		},
		{
			name:      "out_of_scope_different_namespace",
			namespace: "staging",
			cfg:       nsCfg("prod"),
			want:      false,
		},
		{
			name:      "in_scope_wildcard_selector",
			namespace: "any-namespace",
			cfg:       wildcardCfg(),
			want:      true,
		},
		{
			name:      "out_of_scope_system_namespace",
			namespace: "kube-system",
			cfg:       wildcardCfg(),
			want:      false,
		},
		{
			name:      "out_of_scope_kube_node_lease",
			namespace: "kube-node-lease",
			cfg:       wildcardCfg(),
			want:      false,
		},
		{
			name:      "out_of_scope_kube_public",
			namespace: "kube-public",
			cfg:       wildcardCfg(),
			want:      false,
		},
		{
			name:      "out_of_scope_no_selectors",
			namespace: "prod",
			cfg:       &beyla.Config{},
			want:      false,
		},
		{
			name:      "in_scope_multi_selector_second_matches",
			namespace: "staging",
			cfg: &beyla.Config{
				Injector: beyla.SDKInject{
					Instrument: configmap.WebhookInstrument{
						{Namespaces: []services.GlobAttr{services.NewGlob("prod")}},
						{Namespaces: []services.GlobAttr{services.NewGlob("staging")}},
					},
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inScope(tt.namespace, scopedNamespaces(tt.cfg))
			assert.Equal(t, tt.want, got)
		})
	}
}

// collectMetrics gathers metrics from any prometheus.Collector and returns them
// as a map from label-set string to gauge value.
func collectMetrics(t *testing.T, c prometheus.Collector) map[string]float64 {
	t.Helper()
	reg := prometheus.NewRegistry()
	require.NoError(t, reg.Register(c))

	mfs, err := reg.Gather()
	require.NoError(t, err)

	out := map[string]float64{}
	for _, mf := range mfs {
		for _, m := range mf.GetMetric() {
			key := labelSetKey(m.GetLabel())
			out[key] = m.GetGauge().GetValue()
		}
	}
	return out
}

func labelSetKey(labels []*dto.LabelPair) string {
	var s string
	for _, lp := range labels {
		s += lp.GetName() + "=" + lp.GetValue() + ","
	}
	return s
}

// ---------------------------------------------------------------------------
// Informer-based classification tests
// ---------------------------------------------------------------------------

// informerPod builds a minimal *informer.ObjectMeta for testing.
func informerPod(namespace, name, uid, node string, opts ...func(*informer.ObjectMeta)) *informer.ObjectMeta {
	p := &informer.ObjectMeta{
		Name:      name,
		Namespace: namespace,
		Pod: &informer.PodInfo{
			Uid:      uid,
			NodeName: node,
		},
	}
	for _, o := range opts {
		o(p)
	}
	return p
}

func withInformerLabel(key, value string) func(*informer.ObjectMeta) {
	return func(p *informer.ObjectMeta) {
		if p.Labels == nil {
			p.Labels = map[string]string{}
		}
		p.Labels[key] = value
	}
}

// withInformerOwners sets the full owner chain on the informer pod, as the OBI
// informer would produce it (e.g. [ReplicaSet, Deployment] after the heuristic).
func withInformerOwners(owners []*informer.Owner) func(*informer.ObjectMeta) {
	return func(p *informer.ObjectMeta) {
		p.Pod.Owners = owners
	}
}

func createdEvent(pod *informer.ObjectMeta) *informer.Event {
	return &informer.Event{Type: informer.EventType_CREATED, Resource: pod}
}

func updatedEvent(pod *informer.ObjectMeta) *informer.Event {
	return &informer.Event{Type: informer.EventType_UPDATED, Resource: pod}
}

func deletedEvent(pod *informer.ObjectMeta) *informer.Event {
	return &informer.Event{Type: informer.EventType_DELETED, Resource: pod}
}

func syncFinishedEvent() *informer.Event {
	return &informer.Event{Type: informer.EventType_SYNC_FINISHED}
}

func TestProcessMetadataFromInformer(t *testing.T) {
	tests := []struct {
		name           string
		pod            *informer.ObjectMeta
		wantNamespace  string
		wantOwnerChain []configmap.Owner
	}{
		{
			name:           "no owners — chain is empty",
			pod:            informerPod("prod", "my-pod", "uid-1", "node-1"),
			wantNamespace:  "prod",
			wantOwnerChain: nil,
		},
		{
			name: "single deployment owner",
			pod: informerPod("prod", "my-pod", "uid-2", "node-1",
				withInformerOwners([]*informer.Owner{
					{Kind: "Deployment", Name: "my-app"},
				}),
			),
			wantNamespace:  "prod",
			wantOwnerChain: []configmap.Owner{{Name: "my-app", Kind: "Deployment"}},
		},
		{
			// The OBI informer resolves [ReplicaSet, Deployment] before handing it to us;
			// processMetadataFromInformer must pass both into ownerChain so that
			// OwnerName/OwnerKind selectors can match either link.
			name: "replicaset and deployment chain",
			pod: informerPod("prod", "my-pod", "uid-3", "node-1",
				withInformerOwners([]*informer.Owner{
					{Kind: "ReplicaSet", Name: "my-app-abc"},
					{Kind: "Deployment", Name: "my-app"},
				}),
			),
			wantNamespace: "prod",
			wantOwnerChain: []configmap.Owner{
				{Name: "my-app-abc", Kind: "ReplicaSet"},
				{Name: "my-app", Kind: "Deployment"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := processMetadataFromInformer(tt.pod)
			assert.Equal(t, tt.wantNamespace, info.metadata[services.AttrNamespace])
			assert.Equal(t, tt.wantOwnerChain, info.ownerChain)
		})
	}
}

func TestClassifyFromInformer(t *testing.T) {
	const (
		ns      = "prod"
		node    = "node-1"
		version = "v1.2.3"
	)

	cfg := nsCfg(ns)
	matcher := nsMatcher(ns)
	scope := scopedNamespaces(cfg)

	tests := []struct {
		name       string
		pod        *informer.ObjectMeta
		wantNil    bool
		wantStatus Status
		wantSkip   string
		wantKind   string
		wantWork   string
	}{
		{
			name:       "matched_no_label_pending_restart",
			pod:        informerPod(ns, "my-pod", "uid-1", node),
			wantStatus: StatusPendingRestart,
		},
		{
			name:       "matched_current_version_label_instrumented",
			pod:        informerPod(ns, "my-pod", "uid-2", node, withInformerLabel(instrumentedLabel, version)),
			wantStatus: StatusInstrumented,
		},
		{
			name:       "matched_stale_version_label_pending_restart",
			pod:        informerPod(ns, "my-pod", "uid-3", node, withInformerLabel(instrumentedLabel, "v0.9.0")),
			wantStatus: StatusPendingRestart,
		},
		{
			name:    "out_of_scope_system_namespace",
			pod:     informerPod("kube-system", "system-pod", "uid-5", node),
			wantNil: true,
		},
		{
			name:    "out_of_scope_other_namespace",
			pod:     informerPod("other-ns", "my-pod", "uid-6", node),
			wantNil: true,
		},
		{
			// Deployment owner: OBI produces [ReplicaSet, Deployment] after the heuristic.
			name: "workload_deployment",
			pod: informerPod(ns, "my-pod-abc-xyz", "uid-7", node,
				withInformerOwners([]*informer.Owner{
					{Kind: "ReplicaSet", Name: "my-deploy-abc"},
					{Kind: "Deployment", Name: "my-deploy"},
				}),
			),
			wantStatus: StatusPendingRestart,
			wantKind:   "Deployment",
			wantWork:   "my-deploy",
		},
		{
			name:       "workload_standalone_pod",
			pod:        informerPod(ns, "standalone", "uid-8", node),
			wantStatus: StatusPendingRestart,
			wantKind:   "Pod",
			wantWork:   "standalone",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyFromInformer(tt.pod, matcher, scope, version)
			if tt.wantNil {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, tt.wantStatus, got.Status, "status")
			assert.Equal(t, tt.wantSkip, got.SkipReason, "skip_reason")
			if tt.wantKind != "" {
				assert.Equal(t, tt.wantKind, got.WorkloadKind, "workload_kind")
				assert.Equal(t, tt.wantWork, got.WorkloadName, "workload_name")
			}
		})
	}

	t.Run("unmatched_in_scope", func(t *testing.T) {
		m := nsLabelMatcher(ns, "app", "specific-app")
		got := classifyFromInformer(informerPod(ns, "other-app", "uid-u", node), m, scope, version)
		require.NotNil(t, got)
		assert.Equal(t, StatusUnmatched, got.Status)
	})
}

func TestPodStateCache_On(t *testing.T) {
	const (
		ns   = "prod"
		node = "node-1"
	)

	cfg := &beyla.Config{
		Injector: beyla.SDKInject{
			ImageVersion: "v1.2.3",
			Instrument: configmap.WebhookInstrument{
				{Namespaces: []services.GlobAttr{services.NewGlob(ns)}},
			},
		},
	}
	version := cfg.Injector.PackageVersion()
	matcher := nsMatcher(ns)

	t.Run("created_event_populates_cache", func(t *testing.T) {
		cache := NewPodStateCache(matcher, cfg, node)
		require.NoError(t, cache.On(createdEvent(informerPod(ns, "pod-a", "uid-a", node))))

		cache.mu.RLock()
		defer cache.mu.RUnlock()
		require.Contains(t, cache.pods, "uid-a")
		assert.Equal(t, StatusPendingRestart, cache.pods["uid-a"].Status)
	})

	t.Run("created_other_node_ignored", func(t *testing.T) {
		cache := NewPodStateCache(matcher, cfg, node)
		require.NoError(t, cache.On(createdEvent(informerPod(ns, "pod-b", "uid-b", "node-2"))))

		cache.mu.RLock()
		defer cache.mu.RUnlock()
		assert.NotContains(t, cache.pods, "uid-b")
	})

	t.Run("updated_event_overwrites_entry", func(t *testing.T) {
		cache := NewPodStateCache(matcher, cfg, node)
		require.NoError(t, cache.On(createdEvent(informerPod(ns, "pod-c", "uid-c", node))))
		// Update with the instrumented label — status should change.
		require.NoError(t, cache.On(updatedEvent(
			informerPod(ns, "pod-c", "uid-c", node, withInformerLabel(instrumentedLabel, version)),
		)))

		cache.mu.RLock()
		defer cache.mu.RUnlock()
		require.Contains(t, cache.pods, "uid-c")
		assert.Equal(t, StatusInstrumented, cache.pods["uid-c"].Status)
	})

	t.Run("deleted_event_removes_entry", func(t *testing.T) {
		cache := NewPodStateCache(matcher, cfg, node)
		require.NoError(t, cache.On(createdEvent(informerPod(ns, "pod-d", "uid-d", node))))
		require.NoError(t, cache.On(deletedEvent(informerPod(ns, "pod-d", "uid-d", node))))

		cache.mu.RLock()
		defer cache.mu.RUnlock()
		assert.NotContains(t, cache.pods, "uid-d")
	})

	t.Run("non_pod_event_ignored", func(t *testing.T) {
		cache := NewPodStateCache(matcher, cfg, node)
		// Event with no Pod field on the resource.
		nonPod := &informer.Event{
			Type:     informer.EventType_CREATED,
			Resource: &informer.ObjectMeta{Name: "some-service", Namespace: ns},
		}
		require.NoError(t, cache.On(nonPod))

		cache.mu.RLock()
		defer cache.mu.RUnlock()
		assert.Empty(t, cache.pods)
	})

	t.Run("sync_finished_sets_synced", func(t *testing.T) {
		cache := NewPodStateCache(matcher, cfg, node)
		assert.False(t, cache.synced)
		require.NoError(t, cache.On(syncFinishedEvent()))
		assert.True(t, cache.synced)
	})
}

func TestPodStateCache_Collect(t *testing.T) {
	const (
		ns   = "prod"
		node = "node-1"
	)

	cfg := &beyla.Config{
		Injector: beyla.SDKInject{
			ImageVersion: "v1.2.3",
			Instrument: configmap.WebhookInstrument{
				{Namespaces: []services.GlobAttr{services.NewGlob(ns)}},
			},
		},
	}
	version := cfg.Injector.PackageVersion()
	matcher := nsMatcher(ns)

	t.Run("no_metrics_before_sync", func(t *testing.T) {
		cache := NewPodStateCache(matcher, cfg, node)
		require.NoError(t, cache.On(createdEvent(informerPod(ns, "pod-a", "uid-a", node))))
		// markSynced not yet called — Collect must emit nothing.
		metrics := collectMetrics(t, cache)
		assert.Empty(t, metrics)
	})

	t.Run("emits_metrics_after_sync", func(t *testing.T) {
		cache := NewPodStateCache(matcher, cfg, node)
		require.NoError(t, cache.On(createdEvent(informerPod(ns, "pod-a", "uid-a", node))))
		// markSynced mirrors what subscribeStateCache() does after Subscribe returns.
		cache.markSynced()

		metrics := collectMetrics(t, cache)
		require.Len(t, metrics, 1)
		for key, val := range metrics {
			assert.Contains(t, key, "status=pending_restart,")
			assert.Equal(t, float64(1), val)
		}
	})

	t.Run("aggregates_same_label_tuple", func(t *testing.T) {
		cache := NewPodStateCache(matcher, cfg, node)
		owner := withInformerOwners([]*informer.Owner{
			{Kind: "ReplicaSet", Name: "my-deploy-abc"},
			{Kind: "Deployment", Name: "my-deploy"},
		})
		require.NoError(t, cache.On(createdEvent(informerPod(ns, "pod-1", "uid-1", node, owner))))
		require.NoError(t, cache.On(createdEvent(informerPod(ns, "pod-2", "uid-2", node, owner))))
		require.NoError(t, cache.On(createdEvent(informerPod(ns, "pod-3", "uid-3", node, owner))))
		cache.markSynced()

		metrics := collectMetrics(t, cache)
		require.Len(t, metrics, 1)
		for _, val := range metrics {
			assert.Equal(t, float64(3), val)
		}
	})

	t.Run("different_statuses_emit_separate_samples", func(t *testing.T) {
		cache := NewPodStateCache(matcher, cfg, node)
		require.NoError(t, cache.On(createdEvent(informerPod(ns, "pending", "uid-p", node))))
		require.NoError(t, cache.On(createdEvent(
			informerPod(ns, "instrumented", "uid-i", node, withInformerLabel(instrumentedLabel, version)),
		)))
		cache.markSynced()

		metrics := collectMetrics(t, cache)
		assert.Len(t, metrics, 2)
	})

	t.Run("out_of_scope_pods_not_emitted", func(t *testing.T) {
		cache := NewPodStateCache(matcher, cfg, node)
		require.NoError(t, cache.On(createdEvent(informerPod("kube-system", "sys", "uid-s", node))))
		require.NoError(t, cache.On(createdEvent(informerPod("other-ns", "foreign", "uid-f", node))))
		cache.markSynced()

		metrics := collectMetrics(t, cache)
		assert.Empty(t, metrics)
	})

	t.Run("empty_node_name_emits_nothing", func(t *testing.T) {
		cache := NewPodStateCache(matcher, cfg, "")
		cache.markSynced()

		metrics := collectMetrics(t, cache)
		assert.Empty(t, metrics, "Collect with empty node name must emit no metrics")
	})
}
