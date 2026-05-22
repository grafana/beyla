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
	}{
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
				OwnerName: services.NewGlob("my-app"),
			}},
			process: &ProcessInfo{
				ownerChain: []configmap.Owner{{Name: "my-app", Kind: "Deployment"}},
			},
			want: true,
		},
		{
			// Verifies first-match semantics across multiple selectors.
			name: "first matching selector wins",
			instrument: configmap.WebhookInstrument{
				{Namespaces: []services.GlobAttr{services.NewGlob("staging")}},
				{Namespaces: []services.GlobAttr{services.NewGlob("prod")}},
			},
			process: &ProcessInfo{metadata: map[string]string{"k8s_namespace": "prod"}},
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := &PodMatcher{
				instrument: tt.instrument,
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
		cfg := &beyla.Config{
			Injector: beyla.SDKInject{
				Instrument: configmap.WebhookInstrument{{
					Namespaces: []services.GlobAttr{services.NewGlob("prod*")},
				}},
			},
		}
		matcher := NewPodMatcher(cfg)
		assert.NotNil(t, matcher)
		assert.True(t, matcher.HasSelectionCriteria())
	})
}

func strToGlob(s string) *services.GlobAttr {
	v := services.NewGlob(s)
	return &v
}
