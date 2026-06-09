package webhook

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/appolly/services"

	"github.com/grafana/beyla/v3/pkg/beyla"
	"github.com/grafana/beyla/v3/pkg/webhook/configmap"
)

func TestPodMatcher_HasSelectionCriteria(t *testing.T) {
	assert.False(t, (&PodMatcher{}).HasSelectionCriteria())
	assert.True(t, (&PodMatcher{instrument: configmap.WebhookInstrument{{}}}).HasSelectionCriteria())
}

func TestPodMatcher_MatchProcessInfo(t *testing.T) {
	tests := []struct {
		name       string
		instrument configmap.WebhookInstrument
		process    *ProcessInfo
		want       bool
		wantSel    *configmap.K8sSelector // non-nil: assert the exact selector returned
	}{
		{
			name:       "no instrument — no match",
			instrument: configmap.WebhookInstrument{{}},
			process:    &ProcessInfo{metadata: map[string]string{"k8s_namespace": "prod"}},
			want:       false,
		},
		{
			name:       "nil process — no match",
			instrument: configmap.WebhookInstrument{{}},
			process:    nil,
			want:       false,
		},
		{
			name:       "no instrument — no match",
			instrument: configmap.WebhookInstrument{},
			process:    &ProcessInfo{metadata: map[string]string{"k8s_namespace": "prod"}},
			want:       false,
		},
		{
			// Verifies metadata["k8s_namespace"] is wired to MatchInput.Namespace.
			name: "namespace from metadata",
			instrument: configmap.WebhookInstrument{{
				Namespaces: []services.GlobAttr{services.NewGlob("prod")},
			}},
			process: &ProcessInfo{metadata: map[string]string{"k8s_namespace": "prod"}},
			want:    true,
		},
		{
			// Verifies podLabels are wired to MatchInput.Labels.
			name: "labels from podLabels",
			instrument: configmap.WebhookInstrument{{
				PodLabels: map[string]services.GlobAttr{"app": services.NewGlob("my-app")},
			}},
			process: &ProcessInfo{podLabels: map[string]string{"app": "my-app"}},
			want:    true,
		},
		{
			// Verifies podAnnotations are wired to MatchInput.Annotations.
			name: "annotations from podAnnotations",
			instrument: configmap.WebhookInstrument{{
				PodAnnotations: map[string]services.GlobAttr{"ver": services.NewGlob("v1")},
			}},
			process: &ProcessInfo{podAnnotations: map[string]string{"ver": "v1"}},
			want:    true,
		},
		{
			// Verifies ownerChain is wired to MatchInput.OwnerChain.
			name: "ownerChain from processInfo",
			instrument: configmap.WebhookInstrument{{
				OwnerNames: []services.GlobAttr{services.NewGlob("my-app")},
			}},
			process: &ProcessInfo{
				ownerChain: []configmap.Owner{{Name: "my-app", Kind: "Deployment"}},
			},
			want: true,
		},
		{
			// Verifies first-match semantics: second selector matches and is returned.
			name: "first matching selector wins",
			instrument: configmap.WebhookInstrument{
				{Namespaces: []services.GlobAttr{services.NewGlob("staging")}},
				{Namespaces: []services.GlobAttr{services.NewGlob("prod")}},
			},
			process: &ProcessInfo{metadata: map[string]string{"k8s_namespace": "prod"}},
			want:    true,
			wantSel: &configmap.K8sSelector{Namespaces: []services.GlobAttr{services.NewGlob("prod")}},
		},

		// Negative wiring: each field must propagate mismatches correctly.
		{
			name: "namespace mismatch — no match",
			instrument: configmap.WebhookInstrument{{
				Namespaces: []services.GlobAttr{services.NewGlob("prod")},
			}},
			process: &ProcessInfo{metadata: map[string]string{"k8s_namespace": "staging"}},
			want:    false,
		},
		{
			name: "labels mismatch — no match",
			instrument: configmap.WebhookInstrument{{
				PodLabels: map[string]services.GlobAttr{"app": services.NewGlob("my-app")},
			}},
			process: &ProcessInfo{podLabels: map[string]string{"app": "other-app"}},
			want:    false,
		},
		{
			name: "annotations mismatch — no match",
			instrument: configmap.WebhookInstrument{{
				PodAnnotations: map[string]services.GlobAttr{"ver": services.NewGlob("v1")},
			}},
			process: &ProcessInfo{podAnnotations: map[string]string{"ver": "v2"}},
			want:    false,
		},
		{
			name: "ownerChain mismatch — no match",
			instrument: configmap.WebhookInstrument{{
				OwnerNames: []services.GlobAttr{services.NewGlob("my-app")},
			}},
			process: &ProcessInfo{
				ownerChain: []configmap.Owner{{Name: "other-app", Kind: "Deployment"}},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := &PodMatcher{
				instrument: tt.instrument,
				logger:     slog.With("component", "webhook.Matcher"),
			}
			sel, matched := matcher.MatchProcessInfo(tt.process)
			assert.Equal(t, tt.want, matched)
			if tt.wantSel != nil {
				assert.Equal(t, *tt.wantSel, sel)
			}
		})
	}
}

func TestPodMatcher_MatchProcessInfo_Exclusion(t *testing.T) {
	instrument := configmap.WebhookInstrument{{
		Namespaces: []services.GlobAttr{services.NewGlob("demo")},
	}}
	exclude := configmap.WebhookInstrument{{
		Namespaces: []services.GlobAttr{services.NewGlob("demo")},
		OwnerNames: []services.GlobAttr{services.NewGlob("skip-me")},
	}}

	excludeReplicaSet := configmap.WebhookInstrument{{
		Namespaces: []services.GlobAttr{services.NewGlob("demo")},
		OwnerNames: []services.GlobAttr{services.NewGlob("skip-me")},
		OwnerKinds: []string{"ReplicaSet"},
	}}

	tests := []struct {
		name       string
		instrument configmap.WebhookInstrument
		exclude    configmap.WebhookInstrument
		process    *ProcessInfo
		want       bool
	}{
		{
			name:       "exclusion is filtered out because skip-me is a Deployment and not a ReplicaSet",
			instrument: instrument,
			exclude:    excludeReplicaSet,
			process: &ProcessInfo{
				metadata:   map[string]string{"k8s_namespace": "demo"},
				ownerChain: []configmap.Owner{{Name: "skip-me", Kind: "Deployment"}},
			},
			want: true,
		},
		{
			name:       "exclusion wins over a matching instrument selector",
			instrument: instrument,
			exclude:    exclude,
			process: &ProcessInfo{
				metadata:   map[string]string{"k8s_namespace": "demo"},
				ownerChain: []configmap.Owner{{Name: "skip-me", Kind: "Deployment"}},
			},
			want: false,
		},
		{
			name:       "non-excluded pod in the same namespace is still instrumented",
			instrument: instrument,
			exclude:    exclude,
			process: &ProcessInfo{
				metadata:   map[string]string{"k8s_namespace": "demo"},
				ownerChain: []configmap.Owner{{Name: "keep-me", Kind: "Deployment"}},
			},
			want: true,
		},
		{
			name:       "exclude selector that does not match leaves the instrument match intact",
			instrument: instrument,
			exclude: configmap.WebhookInstrument{{
				Namespaces: []services.GlobAttr{services.NewGlob("other")},
			}},
			process: &ProcessInfo{metadata: map[string]string{"k8s_namespace": "demo"}},
			want:    true,
		},
		{
			name:       "exclude only, no instrument, no match",
			instrument: configmap.WebhookInstrument{},
			exclude:    exclude,
			process: &ProcessInfo{
				metadata:   map[string]string{"k8s_namespace": "demo"},
				ownerChain: []configmap.Owner{{Name: "skip-me", Kind: "Deployment"}},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := &PodMatcher{
				instrument: tt.instrument,
				exclude:    tt.exclude,
				logger:     slog.With("component", "webhook.Matcher"),
			}
			_, matched := matcher.MatchProcessInfo(tt.process)
			assert.Equal(t, tt.want, matched)
		})
	}
}

func TestNewPodMatcher(t *testing.T) {
	t.Run("empty config", func(t *testing.T) {
		matcher := NewPodMatcher(&beyla.Config{})
		assert.NotNil(t, matcher)
		assert.False(t, matcher.HasSelectionCriteria())
	})

	t.Run("with instrument criteria", func(t *testing.T) {
		prod := services.NewGlob("prod*")
		cfg := &beyla.Config{
			Injector: beyla.SDKInject{
				Instrument: services.GlobDefinitionCriteria{{Metadata: services.MetadataGlobMap{"k8_namespace": &prod}}},
			},
		}
		matcher := NewPodMatcher(cfg)
		assert.NotNil(t, matcher)
		assert.True(t, matcher.HasSelectionCriteria())
	})

	t.Run("wires exclude_instrument and exclusion wins", func(t *testing.T) {
		demo := services.NewGlob("demo")
		skipMe := services.NewGlob("skip-me")

		cfg := &beyla.Config{
			Injector: beyla.SDKInject{
				Instrument:        services.GlobDefinitionCriteria{{Metadata: services.MetadataGlobMap{"k8_namespace": &demo}}},
				ExcludeInstrument: services.GlobDefinitionCriteria{{Metadata: services.MetadataGlobMap{"k8_namespace": &demo, "k8s_owner_name": &skipMe}}},
			},
		}
		matcher := NewPodMatcher(cfg)
		_, matched := matcher.MatchProcessInfo(&ProcessInfo{
			metadata:   map[string]string{"k8s_namespace": "demo"},
			ownerChain: []configmap.Owner{{Name: "skip-me", Kind: "Deployment"}},
		})
		assert.False(t, matched, "skip-me should be excluded")
		_, matched = matcher.MatchProcessInfo(&ProcessInfo{
			metadata:   map[string]string{"k8s_namespace": "demo"},
			ownerChain: []configmap.Owner{{Name: "keep-me", Kind: "Deployment"}},
		})
		assert.True(t, matched, "keep-me should be instrumented")
	})
}
