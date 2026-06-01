package configmap

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/appolly/services"
)

func TestK8sSelector_Match(t *testing.T) {
	tests := []struct {
		name     string
		selector K8sSelector
		input    MatchInput
		want     bool
	}{
		{
			name:     "empty selector matches everything",
			selector: K8sSelector{},
			input:    MatchInput{Namespace: "prod", Labels: map[string]string{"app": "foo"}},
			want:     true,
		},

		// Namespace matching
		{
			name:     "namespace match",
			selector: K8sSelector{Namespaces: []services.GlobAttr{services.NewGlob("prod")}},
			input:    MatchInput{Namespace: "prod"},
			want:     true,
		},
		{
			name:     "namespace no match",
			selector: K8sSelector{Namespaces: []services.GlobAttr{services.NewGlob("prod")}},
			input:    MatchInput{Namespace: "staging"},
			want:     false,
		},
		{
			name:     "namespace glob pattern",
			selector: K8sSelector{Namespaces: []services.GlobAttr{services.NewGlob("prod*")}},
			input:    MatchInput{Namespace: "production"},
			want:     true,
		},
		{
			name: "namespace OR semantics — second matches",
			selector: K8sSelector{Namespaces: []services.GlobAttr{
				services.NewGlob("staging"),
				services.NewGlob("prod*"),
			}},
			input: MatchInput{Namespace: "production"},
			want:  true,
		},
		{
			name: "namespace OR semantics — none match",
			selector: K8sSelector{Namespaces: []services.GlobAttr{
				services.NewGlob("staging"),
				services.NewGlob("dev"),
			}},
			input: MatchInput{Namespace: "production"},
			want:  false,
		},

		// OwnerNames matching
		{
			name:     "ownerNames matches direct owner",
			selector: K8sSelector{OwnerNames: []services.GlobAttr{services.NewGlob("my-app")}},
			input:    MatchInput{OwnerChain: []Owner{{Name: "my-app", Kind: "DaemonSet"}}},
			want:     true,
		},
		{
			name:     "ownerNames matches deployment via chain",
			selector: K8sSelector{OwnerNames: []services.GlobAttr{services.NewGlob("my-app")}},
			input: MatchInput{OwnerChain: []Owner{
				{Name: "my-app-7d9f8b", Kind: "ReplicaSet"},
				{Name: "my-app", Kind: "Deployment"},
			}},
			want: true,
		},
		{
			name:     "ownerNames no match",
			selector: K8sSelector{OwnerNames: []services.GlobAttr{services.NewGlob("my-app")}},
			input: MatchInput{OwnerChain: []Owner{
				{Name: "other-app", Kind: "Deployment"},
			}},
			want: false,
		},
		{
			name:     "ownerNames set but empty chain",
			selector: K8sSelector{OwnerNames: []services.GlobAttr{services.NewGlob("my-app")}},
			input:    MatchInput{OwnerChain: nil},
			want:     false,
		},
		{
			name:     "ownerNames glob pattern",
			selector: K8sSelector{OwnerNames: []services.GlobAttr{services.NewGlob("my-*")}},
			input:    MatchInput{OwnerChain: []Owner{{Name: "my-app", Kind: "Deployment"}}},
			want:     true,
		},
		{
			name: "ownerNames OR — second glob matches a chain link",
			selector: K8sSelector{OwnerNames: []services.GlobAttr{
				services.NewGlob("nope"),
				services.NewGlob("my-app"),
			}},
			input: MatchInput{OwnerChain: []Owner{{Name: "my-app", Kind: "Deployment"}}},
			want:  true,
		},
		{
			name: "ownerNames OR — none match",
			selector: K8sSelector{OwnerNames: []services.GlobAttr{
				services.NewGlob("nope"),
				services.NewGlob("nada"),
			}},
			input: MatchInput{OwnerChain: []Owner{{Name: "my-app", Kind: "Deployment"}}},
			want:  false,
		},

		// OwnerKinds matching
		{
			name:     "ownerKinds match",
			selector: K8sSelector{OwnerKinds: []string{"Deployment"}},
			input:    MatchInput{OwnerChain: []Owner{{Name: "any", Kind: "Deployment"}}},
			want:     true,
		},
		{
			name:     "ownerKinds no match",
			selector: K8sSelector{OwnerKinds: []string{"Deployment"}},
			input:    MatchInput{OwnerChain: []Owner{{Name: "any", Kind: "DaemonSet"}}},
			want:     false,
		},
		{
			name:     "ownerKinds OR — kind is one of several",
			selector: K8sSelector{OwnerKinds: []string{"Deployment", "StatefulSet"}},
			input:    MatchInput{OwnerChain: []Owner{{Name: "any", Kind: "StatefulSet"}}},
			want:     true,
		},

		// OwnerKinds + OwnerNames combine per link (kind ∈ kinds AND name ∈ names)
		{
			name: "ownerNames and ownerKinds both satisfied by the same link",
			selector: K8sSelector{
				OwnerNames: []services.GlobAttr{services.NewGlob("my-app")},
				OwnerKinds: []string{"Deployment"},
			},
			input: MatchInput{OwnerChain: []Owner{
				{Name: "my-app-7d9f8b", Kind: "ReplicaSet"},
				{Name: "my-app", Kind: "Deployment"},
			}},
			want: true,
		},
		{
			name: "name and kind satisfied by different links does not match",
			selector: K8sSelector{
				OwnerNames: []services.GlobAttr{services.NewGlob("my-app-7d9f8b")},
				OwnerKinds: []string{"Deployment"},
			},
			input: MatchInput{OwnerChain: []Owner{
				{Name: "my-app-7d9f8b", Kind: "ReplicaSet"}, // name matches, kind does not
				{Name: "my-app", Kind: "Deployment"},        // kind matches, name does not
			}},
			want: false,
		},
		{
			name: "ownerNames matches but ownerKinds does not on same link",
			selector: K8sSelector{
				OwnerNames: []services.GlobAttr{services.NewGlob("my-app")},
				OwnerKinds: []string{"StatefulSet"},
			},
			input: MatchInput{OwnerChain: []Owner{
				{Name: "my-app", Kind: "Deployment"},
			}},
			want: false,
		},
		{
			// kinds: [Deployment, ReplicaSet], names: [my-app-rs] — the ReplicaSet
			// link satisfies both, so the pod matches.
			name: "multiple kinds with single name matched by the replicaset link",
			selector: K8sSelector{
				OwnerNames: []services.GlobAttr{services.NewGlob("my-app-rs")},
				OwnerKinds: []string{"Deployment", "ReplicaSet"},
			},
			input: MatchInput{OwnerChain: []Owner{
				{Name: "my-app-rs", Kind: "ReplicaSet"},
				{Name: "my-app", Kind: "Deployment"},
			}},
			want: true,
		},

		// PodLabels matching
		{
			name:     "label match",
			selector: K8sSelector{PodLabels: map[string]services.GlobAttr{"app": services.NewGlob("my-app")}},
			input:    MatchInput{Labels: map[string]string{"app": "my-app"}},
			want:     true,
		},
		{
			name:     "label no match",
			selector: K8sSelector{PodLabels: map[string]services.GlobAttr{"app": services.NewGlob("my-app")}},
			input:    MatchInput{Labels: map[string]string{"app": "other"}},
			want:     false,
		},
		{
			name:     "label key missing",
			selector: K8sSelector{PodLabels: map[string]services.GlobAttr{"app": services.NewGlob("my-app")}},
			input:    MatchInput{Labels: map[string]string{"env": "prod"}},
			want:     false,
		},
		{
			name: "multiple labels AND semantics — all match",
			selector: K8sSelector{PodLabels: map[string]services.GlobAttr{
				"app": services.NewGlob("my-app"),
				"env": services.NewGlob("prod"),
			}},
			input: MatchInput{Labels: map[string]string{"app": "my-app", "env": "prod"}},
			want:  true,
		},
		{
			name: "multiple labels AND semantics — one missing",
			selector: K8sSelector{PodLabels: map[string]services.GlobAttr{
				"app": services.NewGlob("my-app"),
				"env": services.NewGlob("prod"),
			}},
			input: MatchInput{Labels: map[string]string{"app": "my-app"}},
			want:  false,
		},

		// PodAnnotations matching
		{
			name:     "annotation match",
			selector: K8sSelector{PodAnnotations: map[string]services.GlobAttr{"version": services.NewGlob("v1.*")}},
			input:    MatchInput{Annotations: map[string]string{"version": "v1.2"}},
			want:     true,
		},
		{
			name:     "annotation no match",
			selector: K8sSelector{PodAnnotations: map[string]services.GlobAttr{"version": services.NewGlob("v1.*")}},
			input:    MatchInput{Annotations: map[string]string{"version": "v2.0"}},
			want:     false,
		},

		// Combined criteria
		{
			name: "namespace and labels — both match",
			selector: K8sSelector{
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
			selector: K8sSelector{
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
