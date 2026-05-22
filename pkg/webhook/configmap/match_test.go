package configmap

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/appolly/services"
)

func TestSelector_Match(t *testing.T) {
	tests := []struct {
		name     string
		selector Selector
		input    MatchInput
		want     bool
	}{
		{
			name:     "empty selector matches everything",
			selector: Selector{},
			input:    MatchInput{Namespace: "prod", Labels: map[string]string{"app": "foo"}},
			want:     true,
		},

		// Namespace matching
		{
			name:     "namespace match",
			selector: Selector{Namespaces: []services.GlobAttr{services.NewGlob("prod")}},
			input:    MatchInput{Namespace: "prod"},
			want:     true,
		},
		{
			name:     "namespace no match",
			selector: Selector{Namespaces: []services.GlobAttr{services.NewGlob("prod")}},
			input:    MatchInput{Namespace: "staging"},
			want:     false,
		},
		{
			name:     "namespace glob pattern",
			selector: Selector{Namespaces: []services.GlobAttr{services.NewGlob("prod*")}},
			input:    MatchInput{Namespace: "production"},
			want:     true,
		},
		{
			name: "namespace OR semantics — second matches",
			selector: Selector{Namespaces: []services.GlobAttr{
				services.NewGlob("staging"),
				services.NewGlob("prod*"),
			}},
			input: MatchInput{Namespace: "production"},
			want:  true,
		},
		{
			name: "namespace OR semantics — none match",
			selector: Selector{Namespaces: []services.GlobAttr{
				services.NewGlob("staging"),
				services.NewGlob("dev"),
			}},
			input: MatchInput{Namespace: "production"},
			want:  false,
		},

		// OwnerName matching
		{
			name:     "ownerName matches direct owner",
			selector: Selector{OwnerName: services.NewGlob("my-app")},
			input:    MatchInput{OwnerChain: []Owner{{Name: "my-app", Kind: "DaemonSet"}}},
			want:     true,
		},
		{
			name:     "ownerName matches deployment via chain",
			selector: Selector{OwnerName: services.NewGlob("my-app")},
			input: MatchInput{OwnerChain: []Owner{
				{Name: "my-app-7d9f8b", Kind: "ReplicaSet"},
				{Name: "my-app", Kind: "Deployment"},
			}},
			want: true,
		},
		{
			name:     "ownerName no match",
			selector: Selector{OwnerName: services.NewGlob("my-app")},
			input: MatchInput{OwnerChain: []Owner{
				{Name: "other-app", Kind: "Deployment"},
			}},
			want: false,
		},
		{
			name:     "ownerName set but empty chain",
			selector: Selector{OwnerName: services.NewGlob("my-app")},
			input:    MatchInput{OwnerChain: nil},
			want:     false,
		},
		{
			name:     "ownerName glob pattern",
			selector: Selector{OwnerName: services.NewGlob("my-*")},
			input:    MatchInput{OwnerChain: []Owner{{Name: "my-app", Kind: "Deployment"}}},
			want:     true,
		},

		// OwnerKind matching
		{
			name:     "ownerKind match",
			selector: Selector{OwnerKind: "Deployment"},
			input:    MatchInput{OwnerChain: []Owner{{Name: "any", Kind: "Deployment"}}},
			want:     true,
		},
		{
			name:     "ownerKind no match",
			selector: Selector{OwnerKind: "Deployment"},
			input:    MatchInput{OwnerChain: []Owner{{Name: "any", Kind: "DaemonSet"}}},
			want:     false,
		},

		// OwnerName + OwnerKind AND semantics
		{
			name: "ownerName and ownerKind both must match same link",
			selector: Selector{
				OwnerName: services.NewGlob("my-app"),
				OwnerKind: "Deployment",
			},
			input: MatchInput{OwnerChain: []Owner{
				{Name: "my-app-7d9f8b", Kind: "ReplicaSet"},
				{Name: "my-app", Kind: "Deployment"},
			}},
			want: true,
		},
		{
			name: "ownerName matches but ownerKind does not on same link",
			selector: Selector{
				OwnerName: services.NewGlob("my-app"),
				OwnerKind: "StatefulSet",
			},
			input: MatchInput{OwnerChain: []Owner{
				{Name: "my-app", Kind: "Deployment"},
			}},
			want: false,
		},

		// PodLabels matching
		{
			name:     "label match",
			selector: Selector{PodLabels: map[string]services.GlobAttr{"app": services.NewGlob("my-app")}},
			input:    MatchInput{Labels: map[string]string{"app": "my-app"}},
			want:     true,
		},
		{
			name:     "label no match",
			selector: Selector{PodLabels: map[string]services.GlobAttr{"app": services.NewGlob("my-app")}},
			input:    MatchInput{Labels: map[string]string{"app": "other"}},
			want:     false,
		},
		{
			name:     "label key missing",
			selector: Selector{PodLabels: map[string]services.GlobAttr{"app": services.NewGlob("my-app")}},
			input:    MatchInput{Labels: map[string]string{"env": "prod"}},
			want:     false,
		},
		{
			name: "multiple labels AND semantics — all match",
			selector: Selector{PodLabels: map[string]services.GlobAttr{
				"app": services.NewGlob("my-app"),
				"env": services.NewGlob("prod"),
			}},
			input: MatchInput{Labels: map[string]string{"app": "my-app", "env": "prod"}},
			want:  true,
		},
		{
			name: "multiple labels AND semantics — one missing",
			selector: Selector{PodLabels: map[string]services.GlobAttr{
				"app": services.NewGlob("my-app"),
				"env": services.NewGlob("prod"),
			}},
			input: MatchInput{Labels: map[string]string{"app": "my-app"}},
			want:  false,
		},

		// PodAnnotations matching
		{
			name:     "annotation match",
			selector: Selector{PodAnnotations: map[string]services.GlobAttr{"version": services.NewGlob("v1.*")}},
			input:    MatchInput{Annotations: map[string]string{"version": "v1.2"}},
			want:     true,
		},
		{
			name:     "annotation no match",
			selector: Selector{PodAnnotations: map[string]services.GlobAttr{"version": services.NewGlob("v1.*")}},
			input:    MatchInput{Annotations: map[string]string{"version": "v2.0"}},
			want:     false,
		},

		// Combined criteria
		{
			name: "namespace and labels — both match",
			selector: Selector{
				Namespaces: []services.GlobAttr{services.NewGlob("prod")},
				PodLabels:  map[string]services.GlobAttr{"app": services.NewGlob("my-app")},
			},
			input: MatchInput{
				Namespace: "prod",
				Labels:    map[string]string{"app": "my-app"},
			},
			want: true,
		},
		{
			name: "namespace and labels — namespace fails",
			selector: Selector{
				Namespaces: []services.GlobAttr{services.NewGlob("prod")},
				PodLabels:  map[string]services.GlobAttr{"app": services.NewGlob("my-app")},
			},
			input: MatchInput{
				Namespace: "staging",
				Labels:    map[string]string{"app": "my-app"},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.selector.Match(tt.input))
		})
	}
}
