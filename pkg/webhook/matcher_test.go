package webhook

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/appolly/services"

	"github.com/grafana/beyla/v2/pkg/beyla"
)

func TestPodMatcher_HasSelectionCriteria(t *testing.T) {
	tests := []struct {
		name      string
		selectors []services.Selector
		expected  bool
	}{
		{
			name:      "no selectors",
			selectors: []services.Selector{},
			expected:  false,
		},
		{
			name:      "with selectors",
			selectors: []services.Selector{nil},
			expected:  true,
		},
		{
			name: "multiple selectors",
			selectors: []services.Selector{
				&services.GlobAttributes{},
				&services.GlobAttributes{},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := &PodMatcher{
				selectors: tt.selectors,
			}
			result := matcher.HasSelectionCriteria()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPodMatcher_MatchProcessInfo(t *testing.T) {
	tests := []struct {
		name      string
		selectors []services.Selector
		process   *ProcessInfo
		expected  bool
	}{
		{
			name: "no k8s attributes, doesn't match on executable name",
			selectors: []services.Selector{
				&services.GlobAttributes{
					Path: *strToGlob("*node*"),
				},
			},
			process: &ProcessInfo{
				metadata: map[string]string{"k8s_namespace": "default"},
			},
			expected: false,
		},
		{
			name: "doesn't match on executable name, but has k8s attributes",
			selectors: []services.Selector{
				&services.GlobAttributes{
					Path: *strToGlob("*node*"),
					Metadata: map[string]*services.GlobAttr{
						"k8s_namespace": strToGlob("default"),
					},
				},
			},
			process: &ProcessInfo{
				metadata: map[string]string{"k8s_namespace": "default"},
			},
			expected: true,
		},
		{
			name:      "nil process info",
			selectors: []services.Selector{&services.GlobAttributes{}},
			process:   nil,
			expected:  false,
		},
		{
			name:      "no selectors - no match",
			selectors: []services.Selector{},
			process: &ProcessInfo{
				metadata: map[string]string{"k8s_namespace": "default"},
			},
			expected: false,
		},
		{
			name: "metadata match",
			selectors: []services.Selector{
				&services.GlobAttributes{
					Metadata: map[string]*services.GlobAttr{
						"k8s_namespace": strToGlob("default"),
					},
				},
			},
			process: &ProcessInfo{
				metadata: map[string]string{"k8s_namespace": "default"},
			},
			expected: true,
		},
		{
			name: "metadata no match",
			selectors: []services.Selector{
				&services.GlobAttributes{
					Metadata: map[string]*services.GlobAttr{
						"k8s_namespace": strToGlob("production"),
					},
				},
			},
			process: &ProcessInfo{
				metadata: map[string]string{"k8s_namespace": "default"},
			},
			expected: false,
		},
		{
			name: "pod labels match",
			selectors: []services.Selector{
				&services.GlobAttributes{
					PodLabels: map[string]*services.GlobAttr{
						"app": strToGlob("my-app"),
					},
				},
			},
			process: &ProcessInfo{
				podLabels: map[string]string{"app": "my-app"},
			},
			expected: true,
		},
		{
			name: "pod labels no match",
			selectors: []services.Selector{
				&services.GlobAttributes{
					PodLabels: map[string]*services.GlobAttr{
						"app": strToGlob("my-app"),
					},
				},
			},
			process: &ProcessInfo{
				podLabels: map[string]string{"app": "other-app"},
			},
			expected: false,
		},
		{
			name: "pod annotations match",
			selectors: []services.Selector{
				&services.GlobAttributes{
					PodAnnotations: map[string]*services.GlobAttr{
						"version": strToGlob("v1.0"),
					},
				},
			},
			process: &ProcessInfo{
				podAnnotations: map[string]string{"version": "v1.0"},
			},
			expected: true,
		},
		{
			name: "pod annotations no match",
			selectors: []services.Selector{
				&services.GlobAttributes{
					PodAnnotations: map[string]*services.GlobAttr{
						"version": strToGlob("v1.0"),
					},
				},
			},
			process: &ProcessInfo{
				podAnnotations: map[string]string{"version": "v2.0"},
			},
			expected: false,
		},
		{
			name: "multiple criteria all match",
			selectors: []services.Selector{
				&services.GlobAttributes{
					Metadata: map[string]*services.GlobAttr{
						"k8s_namespace": strToGlob("default"),
					},
					PodLabels: map[string]*services.GlobAttr{
						"app": strToGlob("my-app"),
					},
					PodAnnotations: map[string]*services.GlobAttr{
						"version": strToGlob("v1.0"),
					},
				},
			},
			process: &ProcessInfo{
				metadata:       map[string]string{"k8s_namespace": "default"},
				podLabels:      map[string]string{"app": "my-app"},
				podAnnotations: map[string]string{"version": "v1.0"},
			},
			expected: true,
		},
		{
			name: "multiple criteria one doesn't match",
			selectors: []services.Selector{
				&services.GlobAttributes{
					Metadata: map[string]*services.GlobAttr{
						"k8s_namespace": strToGlob("default"),
					},
					PodLabels: map[string]*services.GlobAttr{
						"app": strToGlob("my-app"),
					},
					PodAnnotations: map[string]*services.GlobAttr{
						"version": strToGlob("v1.0"),
					},
				},
			},
			process: &ProcessInfo{
				metadata:       map[string]string{"k8s_namespace": "default"},
				podLabels:      map[string]string{"app": "other-app"},
				podAnnotations: map[string]string{"version": "v1.0"},
			},
			expected: false,
		},
		{
			name: "multiple selectors - first matches",
			selectors: []services.Selector{
				&services.GlobAttributes{
					Metadata: map[string]*services.GlobAttr{
						"k8s_namespace": strToGlob("default"),
					},
				},
				&services.GlobAttributes{
					Metadata: map[string]*services.GlobAttr{
						"k8s_namespace": strToGlob("production"),
					},
				},
			},
			process: &ProcessInfo{
				metadata: map[string]string{"k8s_namespace": "default"},
			},
			expected: true,
		},
		{
			name: "multiple selectors - second matches",
			selectors: []services.Selector{
				&services.GlobAttributes{
					Metadata: map[string]*services.GlobAttr{
						"k8s_namespace": strToGlob("production"),
					},
				},
				&services.GlobAttributes{
					Metadata: map[string]*services.GlobAttr{
						"k8s_namespace": strToGlob("default"),
					},
				},
			},
			process: &ProcessInfo{
				metadata: map[string]string{"k8s_namespace": "default"},
			},
			expected: true,
		},
		{
			name: "regex pattern match",
			selectors: []services.Selector{
				&services.GlobAttributes{
					Metadata: map[string]*services.GlobAttr{
						"k8s_namespace": strToGlob("prod*"),
					},
				},
			},
			process: &ProcessInfo{
				metadata: map[string]string{"k8s_namespace": "production"},
			},
			expected: true,
		},
		{
			name: "missing required metadata field",
			selectors: []services.Selector{
				&services.GlobAttributes{
					Metadata: map[string]*services.GlobAttr{
						"k8s_namespace": strToGlob("default"),
						"k8s_pod_name":  strToGlob("*"),
					},
				},
			},
			process: &ProcessInfo{
				metadata: map[string]string{"k8s_namespace": "default"},
				// k8s_pod_name is missing
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := &PodMatcher{
				selectors: tt.selectors,
				logger:    slog.With("component", "webhook.Matcher"),
			}
			result := matcher.MatchProcessInfo(tt.process)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNewPodMatcher(t *testing.T) {
	t.Run("creates matcher with empty config", func(t *testing.T) {
		cfg := &beyla.Config{}
		matcher := NewPodMatcher(cfg)

		assert.NotNil(t, matcher)
		assert.NotNil(t, matcher.logger)
		assert.NotNil(t, matcher.selectors)
	})

	t.Run("creates matcher with instrumentation criteria", func(t *testing.T) {
		globs := []services.GlobAttributes{{
			Metadata: map[string]*services.GlobAttr{
				"k8s_namespace": strToGlob("prod*"),
			}},
		}
		cfg := &beyla.Config{
			Injector: beyla.SDKInject{
				Instrument: globs,
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
