package webhook

import (
	"context"
	"log/slog"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.opentelemetry.io/obi/pkg/appolly/services"

	"github.com/grafana/beyla/v3/pkg/beyla"
)

// nsMatcher builds a PodMatcher that matches pods in the given namespace.
func nsMatcher(ns string) *PodMatcher {
	return &PodMatcher{
		logger: slog.Default(),
		selectors: []services.Selector{
			&services.GlobAttributes{
				Metadata: services.MetadataGlobMap{
					services.AttrNamespace: strToGlob(ns),
				},
			},
		},
	}
}

// nsLabelMatcher builds a PodMatcher that matches pods in the given namespace
// AND carrying the given pod label key=value.
func nsLabelMatcher(ns, labelKey, labelValue string) *PodMatcher {
	return &PodMatcher{
		logger: slog.Default(),
		selectors: []services.Selector{
			&services.GlobAttributes{
				Metadata: services.MetadataGlobMap{
					services.AttrNamespace: strToGlob(ns),
				},
				PodLabels: map[string]*services.GlobAttr{
					labelKey: strToGlob(labelValue),
				},
			},
		},
	}
}

// nsCfg builds a beyla.Config whose Injector.Instrument restricts to ns.
func nsCfg(ns string) *beyla.Config {
	return &beyla.Config{
		Injector: beyla.SDKInject{
			Instrument: services.GlobDefinitionCriteria{
				{
					Metadata: services.MetadataGlobMap{
						services.AttrNamespace: strToGlob(ns),
					},
				},
			},
		},
	}
}

// wildcardCfg returns a config with a selector that has no namespace constraint.
func wildcardCfg() *beyla.Config {
	return &beyla.Config{
		Injector: beyla.SDKInject{
			// A selector with no k8s_namespace key matches any namespace.
			Instrument: services.GlobDefinitionCriteria{
				{
					Metadata: services.MetadataGlobMap{},
				},
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

func withAnnotation(key, value string) func(*corev1.Pod) {
	return func(p *corev1.Pod) {
		if p.Annotations == nil {
			p.Annotations = map[string]string{}
		}
		p.Annotations[key] = value
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

// TestClassify covers every status/skip-reason combination from the plan.
func TestClassify(t *testing.T) {
	const prodNS = "prod"

	tests := []struct {
		name         string
		pod          *corev1.Pod
		matcher      *PodMatcher
		cfg          *beyla.Config
		wantNil      bool
		wantStatus   Status
		wantSkip     string
		wantWorkKind string
		wantWorkName string
		wantNode     string
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
			name: "skipped_unsupported_language",
			pod: pod(prodNS, "my-pod",
				withAnnotation(skipReasonAnnotation, SkipReasonUnsupportedLanguage)),
			matcher:    nsMatcher(prodNS),
			cfg:        nsCfg(prodNS),
			wantStatus: StatusSkipped,
			wantSkip:   SkipReasonUnsupportedLanguage,
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
			matcher: wildcardMatcher(),
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
			name:         "node_name_propagated",
			pod:          pod(prodNS, "my-pod", withEnv(envVarLdPreloadName, envVarLdPreloadValue), withNodeName("node-1")),
			matcher:      nsMatcher(prodNS),
			cfg:          nsCfg(prodNS),
			wantStatus:   StatusInstrumented,
			wantNode:     "node-1",
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

// wildcardMatcher returns a PodMatcher with no namespace constraint.
func wildcardMatcher() *PodMatcher {
	return &PodMatcher{
		logger: slog.Default(),
		selectors: []services.Selector{
			&services.GlobAttributes{
				Metadata: services.MetadataGlobMap{},
			},
		},
	}
}

// TestClassifyWorkloadResolution covers owner-reference walking.
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
			name:      "out_of_scope_kube_system",
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
					Instrument: services.GlobDefinitionCriteria{
						{Metadata: services.MetadataGlobMap{services.AttrNamespace: strToGlob("prod")}},
						{Metadata: services.MetadataGlobMap{services.AttrNamespace: strToGlob("staging")}},
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

// fakePodLister satisfies podLister for tests.
type fakePodLister struct{ pods []corev1.Pod }

func (f *fakePodLister) listPodsOnNode(_ context.Context, _ string) ([]corev1.Pod, error) {
	return f.pods, nil
}

// collectMetrics runs the StateCollector and returns the collected samples as a map
// from label-set string to gauge value, for easy assertion.
func collectMetrics(t *testing.T, sc *StateCollector) map[string]float64 {
	t.Helper()
	reg := prometheus.NewRegistry()
	require.NoError(t, reg.Register(sc))

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

func newTestStateCollector(lister podLister, matcher *PodMatcher, cfg *beyla.Config, node string) *StateCollector {
	sc := NewStateCollector(nil, matcher, cfg, node)
	sc.lister = lister // override with test lister
	return sc
}

func TestStateCollector_Collect(t *testing.T) {
	const (
		node  = "node-1"
		ns    = "prod"
		appNS = "prod"
	)

	cfg := nsCfg(ns)
	matcher := nsMatcher(ns)

	t.Run("instrumented_pod_counted", func(t *testing.T) {
		pods := []corev1.Pod{
			*pod(appNS, "app-1",
				withEnv(envVarLdPreloadName, envVarLdPreloadValue),
				withNodeName(node),
				withOwner("ReplicaSet", "my-deploy-abc", "apps/v1"),
			),
		}
		sc := newTestStateCollector(&fakePodLister{pods: pods}, matcher, cfg, node)
		metrics := collectMetrics(t, sc)

		assert.Len(t, metrics, 1)
		for key, val := range metrics {
			assert.Contains(t, key, "status=instrumented,")
			assert.Contains(t, key, "k8s_workload_kind=Deployment,")
			assert.Contains(t, key, "k8s_workload_name=my-deploy,")
			assert.Equal(t, float64(1), val)
		}
	})

	t.Run("aggregates_multiple_pods_same_workload", func(t *testing.T) {
		// All pods owned by the same ReplicaSet → same Deployment label → one sample with count=3.
		pods := []corev1.Pod{
			*pod(appNS, "app-abc-1", withEnv(envVarLdPreloadName, envVarLdPreloadValue), withNodeName(node), withOwner("ReplicaSet", "app-abc", "apps/v1")),
			*pod(appNS, "app-abc-2", withEnv(envVarLdPreloadName, envVarLdPreloadValue), withNodeName(node), withOwner("ReplicaSet", "app-abc", "apps/v1")),
			*pod(appNS, "app-abc-3", withEnv(envVarLdPreloadName, envVarLdPreloadValue), withNodeName(node), withOwner("ReplicaSet", "app-abc", "apps/v1")),
		}
		sc := newTestStateCollector(&fakePodLister{pods: pods}, matcher, cfg, node)
		metrics := collectMetrics(t, sc)

		require.Len(t, metrics, 1)
		for _, val := range metrics {
			assert.Equal(t, float64(3), val)
		}
	})

	t.Run("different_statuses_emit_separate_samples", func(t *testing.T) {
		pods := []corev1.Pod{
			*pod(appNS, "instrumented", withEnv(envVarLdPreloadName, envVarLdPreloadValue), withNodeName(node)),
			*pod(appNS, "pending", withNodeName(node)),
			*pod(appNS, "conflict", withEnv(envVarLdPreloadName, "/other/lib.so"), withNodeName(node)),
		}
		sc := newTestStateCollector(&fakePodLister{pods: pods}, matcher, cfg, node)
		metrics := collectMetrics(t, sc)

		assert.Len(t, metrics, 3)
	})

	t.Run("out_of_scope_pods_not_emitted", func(t *testing.T) {
		pods := []corev1.Pod{
			*pod("kube-system", "system-pod", withNodeName(node)),
			*pod("other-ns", "foreign-pod", withNodeName(node)),
		}
		sc := newTestStateCollector(&fakePodLister{pods: pods}, matcher, cfg, node)
		metrics := collectMetrics(t, sc)

		assert.Empty(t, metrics)
	})

	t.Run("skipped_conflict_has_skip_reason_label", func(t *testing.T) {
		pods := []corev1.Pod{
			*pod(appNS, "conflict-pod", withEnv(envVarLdPreloadName, "/other.so"), withNodeName(node)),
		}
		sc := newTestStateCollector(&fakePodLister{pods: pods}, matcher, cfg, node)
		metrics := collectMetrics(t, sc)

		require.Len(t, metrics, 1)
		for key := range metrics {
			assert.Contains(t, key, "status=skipped,")
			assert.Contains(t, key, "skip_reason=conflict,")
		}
	})
}

// TestScopedNamespaces covers the three cases from the plan:
// explicit namespaces, wildcard selector, and a combination.
func TestScopedNamespaces(t *testing.T) {
	t.Run("explicit_namespaces_not_cluster_wide", func(t *testing.T) {
		cfg := &beyla.Config{
			Injector: beyla.SDKInject{
				Instrument: services.GlobDefinitionCriteria{
					{Metadata: services.MetadataGlobMap{services.AttrNamespace: strToGlob("production")}},
					{Metadata: services.MetadataGlobMap{services.AttrNamespace: strToGlob("staging")}},
				},
			},
		}
		scope := scopedNamespaces(cfg)
		assert.False(t, scope.clusterWide)
		assert.Len(t, scope.globs, 2)
		// correct globs are stored
		assert.True(t, scope.globs[0].MatchString("production"))
		assert.False(t, scope.globs[0].MatchString("staging"))
		assert.True(t, scope.globs[1].MatchString("staging"))
	})

	t.Run("no_namespace_constraint_is_cluster_wide", func(t *testing.T) {
		scope := scopedNamespaces(wildcardCfg())
		assert.True(t, scope.clusterWide)
		assert.Nil(t, scope.globs)
	})

	t.Run("glob_namespace_pattern_not_cluster_wide", func(t *testing.T) {
		cfg := nsCfg("prod*")
		scope := scopedNamespaces(cfg)
		assert.False(t, scope.clusterWide)
		assert.Len(t, scope.globs, 1)
		assert.True(t, scope.globs[0].MatchString("production"))
		assert.True(t, scope.globs[0].MatchString("prod-east"))
		assert.False(t, scope.globs[0].MatchString("staging"))
	})

	t.Run("combination_with_cluster_wide_selector_is_cluster_wide", func(t *testing.T) {
		cfg := &beyla.Config{
			Injector: beyla.SDKInject{
				Instrument: services.GlobDefinitionCriteria{
					// explicit namespace
					{Metadata: services.MetadataGlobMap{services.AttrNamespace: strToGlob("production")}},
					// no namespace constraint → cluster-wide
					{Metadata: services.MetadataGlobMap{}},
				},
			},
		}
		scope := scopedNamespaces(cfg)
		assert.True(t, scope.clusterWide)
	})

	t.Run("empty_config_not_cluster_wide", func(t *testing.T) {
		scope := scopedNamespaces(&beyla.Config{})
		assert.False(t, scope.clusterWide)
		assert.Empty(t, scope.globs)
	})
}

// TestInScope verifies inScope works correctly with a pre-computed nsScope.
func TestInScope(t *testing.T) {
	t.Run("cluster_wide_includes_any_non_system_ns", func(t *testing.T) {
		scope := nsScope{clusterWide: true}
		assert.True(t, inScope("prod", scope))
		assert.True(t, inScope("any-namespace", scope))
		assert.False(t, inScope("kube-system", scope))
		assert.False(t, inScope("kube-node-lease", scope))
		assert.False(t, inScope("kube-public", scope))
	})

	t.Run("explicit_globs_match_correctly", func(t *testing.T) {
		prod := strToGlob("production")
		scope := nsScope{globs: []*services.GlobAttr{prod}}
		assert.True(t, inScope("production", scope))
		assert.False(t, inScope("staging", scope))
		assert.False(t, inScope("kube-system", scope))
	})

	t.Run("no_globs_and_not_cluster_wide_matches_nothing", func(t *testing.T) {
		scope := nsScope{}
		assert.False(t, inScope("production", scope))
		assert.False(t, inScope("anything", scope))
	})
}
