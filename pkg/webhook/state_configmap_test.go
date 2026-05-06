package webhook

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"

	"go.opentelemetry.io/obi/pkg/appolly/services"
)

func TestContainerIDMatches(t *testing.T) {
	tests := []struct {
		name     string
		statusID string
		ownID    string
		want     bool
	}{
		{
			name:     "exact match",
			statusID: "containerd://abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
			ownID:    "abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
			want:     true,
		},
		{
			name:     "short cgroup suffix match",
			statusID: "containerd://abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
			ownID:    "def456abc1",
			want:     false,
		},
		{
			name:     "minimum length cgroup suffix match",
			statusID: "containerd://abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
			ownID:    "123def456abc1",
			want:     false,
		},
		{
			name:     "mismatch",
			statusID: "containerd://abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
			ownID:    "fff123def456abc123def456abc123def456abc123def456abc123def456abc1",
			want:     false,
		},
		{
			name:     "empty values do not match",
			statusID: "",
			ownID:    "",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, containerIDMatches(tt.statusID, tt.ownID))
		})
	}
}

func TestPodHasContainerID(t *testing.T) {
	const containerID = "abc123def456abc123def456abc123def456abc123def456abc123def456abc1"

	pod := &corev1.Pod{
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{{
				Name:        "beyla",
				ContainerID: "containerd://" + containerID,
			}},
		},
	}

	assert.True(t, podHasContainerID(pod, containerID))
}

func TestPodHasContainerIDNoMatch(t *testing.T) {
	pod := &corev1.Pod{
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{{
				Name:        "other",
				ContainerID: "containerd://fff123def456abc123def456abc123def456abc123def456abc123def456abc1",
			}},
		},
	}

	assert.False(t, podHasContainerID(pod, "abc123def456abc123def456abc123def456abc123def456abc123def456abc1"))
}

func TestMarshalNonZeroYAMLPrunesEmptyCriteriaFields(t *testing.T) {
	openPorts := services.IntEnum{}
	assert.NoError(t, openPorts.UnmarshalText([]byte("8080")))
	podLabel := services.NewGlob("checkout")

	out, err := marshalNonZeroYAML(services.GlobDefinitionCriteria{{
		Name:           "checkout",
		OpenPorts:      openPorts,
		Languages:      services.NewGlob("go"),
		PodLabels:      map[string]*services.GlobAttr{"app": &podLabel},
		ContainersOnly: false,
	}})
	assert.NoError(t, err)

	yamlText := string(out)
	assert.Contains(t, yamlText, "name: checkout")
	assert.Contains(t, yamlText, "open_ports:")
	assert.Contains(t, yamlText, "languages: go")
	assert.Contains(t, yamlText, "k8s_pod_labels:")
	assert.Contains(t, yamlText, "app: checkout")

	assert.NotContains(t, yamlText, "namespace:")
	assert.NotContains(t, yamlText, "target_pids:")
	assert.NotContains(t, yamlText, "exe_path:")
	assert.NotContains(t, yamlText, "cmd_args:")
	assert.NotContains(t, yamlText, "containers_only:")
	assert.NotContains(t, yamlText, "exports:")
	assert.NotContains(t, yamlText, "sampler:")
	assert.NotContains(t, yamlText, "routes:")
	assert.NotContains(t, yamlText, "metrics:")
}
