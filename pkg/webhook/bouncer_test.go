package webhook

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMutationKey(t *testing.T) {
	tests := []struct {
		name           string
		namespace      string
		deploymentName string
		expected       string
	}{
		{
			name:           "normal case",
			namespace:      "default",
			deploymentName: "my-app",
			expected:       "default:my-app",
		},
		{
			name:           "empty namespace",
			namespace:      "",
			deploymentName: "my-app",
			expected:       ":my-app",
		},
		{
			name:           "empty deployment",
			namespace:      "default",
			deploymentName: "",
			expected:       "default:",
		},
		{
			name:           "both empty",
			namespace:      "",
			deploymentName: "",
			expected:       ":",
		},
		{
			name:           "special characters in names",
			namespace:      "kube-system",
			deploymentName: "coredns-12345",
			expected:       "kube-system:coredns-12345",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mutationKey(tt.namespace, tt.deploymentName)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPodBouncer_CanBeBounced(t *testing.T) {
	bouncer := &PodBouncer{
		bouncedDeployments: map[string]any{},
	}

	tests := []struct {
		name           string
		namespace      string
		deploymentName string
		expected       bool
	}{
		{
			name:           "both values present",
			namespace:      "default",
			deploymentName: "my-app",
			expected:       true,
		},
		{
			name:           "empty namespace",
			namespace:      "",
			deploymentName: "my-app",
			expected:       false,
		},
		{
			name:           "empty deployment",
			namespace:      "default",
			deploymentName: "",
			expected:       false,
		},
		{
			name:           "both empty",
			namespace:      "",
			deploymentName: "",
			expected:       false,
		},
		{
			name:           "whitespace namespace",
			namespace:      "   ",
			deploymentName: "my-app",
			expected:       false, // whitespace is not empty string
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := bouncer.CanBeBounced(tt.namespace, tt.deploymentName)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPodBouncer_AlreadyBounced(t *testing.T) {
	tests := []struct {
		name                   string
		setupBouncedMap        map[string]any
		namespace              string
		deploymentName         string
		expectedAlreadyBounced bool
	}{
		{
			name:                   "deployment not bounced",
			setupBouncedMap:        map[string]any{},
			namespace:              "default",
			deploymentName:         "my-app",
			expectedAlreadyBounced: false,
		},
		{
			name: "deployment already bounced",
			setupBouncedMap: map[string]any{
				"default:my-app": true,
			},
			namespace:              "default",
			deploymentName:         "my-app",
			expectedAlreadyBounced: true,
		},
		{
			name: "different deployment bounced",
			setupBouncedMap: map[string]any{
				"default:other-app": true,
			},
			namespace:              "default",
			deploymentName:         "my-app",
			expectedAlreadyBounced: false,
		},
		{
			name: "same deployment different namespace",
			setupBouncedMap: map[string]any{
				"production:my-app": true,
			},
			namespace:              "default",
			deploymentName:         "my-app",
			expectedAlreadyBounced: false,
		},
		{
			name: "multiple deployments bounced, checking existing one",
			setupBouncedMap: map[string]any{
				"default:app1":    true,
				"default:app2":    true,
				"production:app3": true,
			},
			namespace:              "default",
			deploymentName:         "app2",
			expectedAlreadyBounced: true,
		},
		{
			name: "multiple deployments bounced, checking non-existing one",
			setupBouncedMap: map[string]any{
				"default:app1":    true,
				"default:app2":    true,
				"production:app3": true,
			},
			namespace:              "staging",
			deploymentName:         "app1",
			expectedAlreadyBounced: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bouncer := &PodBouncer{
				bouncedDeployments: tt.setupBouncedMap,
			}

			result := bouncer.AlreadyBounced(tt.namespace, tt.deploymentName)
			assert.Equal(t, tt.expectedAlreadyBounced, result)
		})
	}
}
