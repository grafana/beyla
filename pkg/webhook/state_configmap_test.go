package webhook

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

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

func TestTrimContainerIDScheme(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "containerd scheme", input: "containerd://abc123", expected: "abc123"},
		{name: "docker scheme", input: "docker://deadbeef", expected: "deadbeef"},
		{name: "cri-o scheme", input: "cri-o://feedface", expected: "feedface"},
		{name: "no scheme", input: "abc123", expected: "abc123"},
		{name: "empty", input: "", expected: ""},
		{name: "scheme only", input: "containerd://", expected: ""},
		{name: "extra colons in id", input: "containerd://abc://def", expected: "abc://def"},
		{name: "single colon (no //)", input: "containerd:abc", expected: "containerd:abc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, trimContainerIDScheme(tt.input))
		})
	}
}

func TestSortEligible(t *testing.T) {
	t.Run("orders by namespace then deployment", func(t *testing.T) {
		eligible := []*EligibleDeployment{
			{Namespace: "b-ns", Deployment: "z-app"},
			{Namespace: "a-ns", Deployment: "z-app"},
			{Namespace: "b-ns", Deployment: "a-app"},
			{Namespace: "a-ns", Deployment: "a-app"},
		}
		sortEligible(eligible)
		assert.Equal(t, []*EligibleDeployment{
			{Namespace: "a-ns", Deployment: "a-app"},
			{Namespace: "a-ns", Deployment: "z-app"},
			{Namespace: "b-ns", Deployment: "a-app"},
			{Namespace: "b-ns", Deployment: "z-app"},
		}, eligible)
	})

	t.Run("empty slice is a no-op", func(t *testing.T) {
		assert.NotPanics(t, func() { sortEligible(nil) })
		assert.NotPanics(t, func() { sortEligible([]*EligibleDeployment{}) })
	})

	t.Run("single element unchanged", func(t *testing.T) {
		eligible := []*EligibleDeployment{{Namespace: "x", Deployment: "y"}}
		sortEligible(eligible)
		assert.Equal(t, []*EligibleDeployment{{Namespace: "x", Deployment: "y"}}, eligible)
	})
}

func TestMarshalNonZeroYAML(t *testing.T) {
	t.Run("prunes zero scalars from a map", func(t *testing.T) {
		input := map[string]any{
			"keep_string":   "hello",
			"empty_string":  "",
			"keep_int":      42,
			"zero_int":      0,
			"keep_bool":     true,
			"false_bool":    false,
			"keep_float":    1.5,
			"zero_float":    0.0,
			"explicit_null": nil,
		}
		out, err := marshalNonZeroYAML(input)
		require.NoError(t, err)
		s := string(out)

		assert.Contains(t, s, "keep_string: hello")
		assert.Contains(t, s, "keep_int: 42")
		assert.Contains(t, s, "keep_bool: true")
		assert.Contains(t, s, "keep_float: 1.5")

		assert.NotContains(t, s, "empty_string")
		assert.NotContains(t, s, "zero_int")
		assert.NotContains(t, s, "false_bool")
		assert.NotContains(t, s, "zero_float")
		assert.NotContains(t, s, "explicit_null")
	})

	t.Run("prunes zero entries from a sequence", func(t *testing.T) {
		input := []any{"a", "", "b", 0, 1, false, true}
		out, err := marshalNonZeroYAML(input)
		require.NoError(t, err)

		var got []any
		require.NoError(t, yaml.Unmarshal(out, &got))
		assert.Equal(t, []any{"a", "b", 1, true}, got)
	})

	t.Run("prunes empty nested maps and sequences after their children are pruned", func(t *testing.T) {
		input := map[string]any{
			"outer": map[string]any{
				"inner_empty": "",
				"inner_zero":  0,
			},
			"list_of_empties": []any{"", 0, false},
			"surviving":       "kept",
		}
		out, err := marshalNonZeroYAML(input)
		require.NoError(t, err)

		var got map[string]any
		require.NoError(t, yaml.Unmarshal(out, &got))
		assert.Equal(t, map[string]any{"surviving": "kept"}, got)
	})

	t.Run("preserves struct yaml tags via Encode", func(t *testing.T) {
		input := []*EligibleDeployment{
			{Namespace: "ns1", Deployment: "dep1", Language: "java"},
			{Namespace: "ns2", Deployment: "dep2"},
		}
		out, err := marshalNonZeroYAML(input)
		require.NoError(t, err)

		var got []*EligibleDeployment
		require.NoError(t, yaml.Unmarshal(out, &got))
		assert.Equal(t, input, got)

		s := string(out)
		assert.Equal(t, 1, strings.Count(s, "language:"))
		assert.Equal(t, 0, strings.Count(s, "kind:"))
	})

	t.Run("returns valid yaml for an entirely-zero document", func(t *testing.T) {
		out, err := marshalNonZeroYAML(map[string]any{"a": "", "b": 0})
		require.NoError(t, err)
		var got map[string]any
		require.NoError(t, yaml.Unmarshal(out, &got))
		assert.Empty(t, got)
	})
}

func TestPruneZeroYAMLNodesDocumentNode(t *testing.T) {
	var doc yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte("a: \"\"\nb: keep\n"), &doc))
	pruneZeroYAMLNodes(&doc)
	out, err := yaml.Marshal(&doc)
	require.NoError(t, err)
	s := string(out)
	assert.Contains(t, s, "b: keep")
	assert.NotContains(t, s, "a:")
}

func TestIsZeroYAMLNode(t *testing.T) {
	scalar := func(tag, value string) *yaml.Node {
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: value}
	}

	tests := []struct {
		name string
		node *yaml.Node
		want bool
	}{
		{"null", scalar("!!null", ""), true},
		{"empty string", scalar("!!str", ""), true},
		{"non-empty string", scalar("!!str", "hi"), false},
		{"false bool", scalar("!!bool", "false"), true},
		{"true bool", scalar("!!bool", "true"), false},
		{"zero int", scalar("!!int", "0"), true},
		{"non-zero int", scalar("!!int", "7"), false},
		{"hex zero int", scalar("!!int", "0x0"), true},
		{"unparseable int treated as non-zero", scalar("!!int", "notanumber"), false},
		{"zero float", scalar("!!float", "0"), true},
		{"zero float with point", scalar("!!float", "0.0"), true},
		{"non-zero float", scalar("!!float", "1.5"), false},
		{"unknown tag empty value", scalar("!!custom", ""), true},
		{"unknown tag non-empty value", scalar("!!custom", "x"), false},
		{"empty sequence", &yaml.Node{Kind: yaml.SequenceNode}, true},
		{
			name: "non-empty sequence",
			node: &yaml.Node{
				Kind:    yaml.SequenceNode,
				Content: []*yaml.Node{scalar("!!str", "x")},
			},
			want: false,
		},
		{"empty mapping", &yaml.Node{Kind: yaml.MappingNode}, true},
		{
			name: "non-empty mapping",
			node: &yaml.Node{
				Kind:    yaml.MappingNode,
				Content: []*yaml.Node{scalar("!!str", "k"), scalar("!!str", "v")},
			},
			want: false,
		},
		{"document node returns false (not handled)", &yaml.Node{Kind: yaml.DocumentNode}, false},
		{"alias node returns false", &yaml.Node{Kind: yaml.AliasNode}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isZeroYAMLNode(tt.node))
		})
	}
}

func TestStateConfigMapName(t *testing.T) {
	tests := []struct {
		name          string
		daemonSetName string
		nodeName      string
		podName       string
		expected      string
	}{
		{
			name:          "simple names",
			daemonSetName: "beyla",
			nodeName:      "node-1",
			podName:       "beyla-abcde",
			expected:      "beyla-injector-state-node-1",
		},
		{
			name:          "node name with uppercase and dots is sanitized",
			daemonSetName: "beyla",
			nodeName:      "Node.Example.COM",
			podName:       "pod-xyz",
			expected:      "beyla-injector-state-node-example-com",
		},
		{
			name:          "empty node name falls back to 'unknown'",
			daemonSetName: "beyla",
			nodeName:      "",
			podName:       "pod-xyz",
			expected:      "beyla-injector-state-unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, stateConfigMapName(tt.daemonSetName, tt.nodeName))
		})
	}
}

func TestSanitizeDNS1123(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "already valid", input: "node-1", expected: "node-1"},
		{name: "uppercase lowercased", input: "NODE-1", expected: "node-1"},
		{name: "dots replaced", input: "node.example.com", expected: "node-example-com"},
		{name: "underscores and slashes replaced", input: "node_1/foo", expected: "node-1-foo"},
		{name: "leading/trailing dashes trimmed", input: "---node---", expected: "node"},
		{name: "leading/trailing invalid chars trimmed after sub", input: "...node...", expected: "node"},
		{name: "empty input", input: "", expected: "unknown"},
		{name: "all invalid chars", input: "!!!", expected: "unknown"},
		{name: "collapses contiguous invalid runs", input: "a..b__c", expected: "a-b-c"},
		{
			name:     "truncates to 63 chars",
			input:    strings.Repeat("a", 70),
			expected: strings.Repeat("a", 63),
		},
		{
			name:     "trims trailing dash after truncation",
			input:    strings.Repeat("a", 62) + "-extra",
			expected: strings.Repeat("a", 62),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeDNS1123(tt.input)
			assert.Equal(t, tt.expected, got)
			assert.LessOrEqual(t, len(got), 63)
		})
	}
}

func TestOwnContainerID(t *testing.T) {
	prev := containerInfoFunc
	t.Cleanup(func() { containerInfoFunc = prev })

	t.Run("returns container id from container info", func(t *testing.T) {
		containerInfoFunc = func(_ uint32) (Info, error) {
			return Info{ContainerID: "abc123"}, nil
		}
		got, err := ownContainerID()
		require.NoError(t, err)
		assert.Equal(t, "abc123", got)
	})

	t.Run("propagates underlying error", func(t *testing.T) {
		boom := errors.New("boom")
		containerInfoFunc = func(_ uint32) (Info, error) {
			return Info{}, boom
		}
		_, err := ownContainerID()
		assert.ErrorIs(t, err, boom)
	})

	t.Run("errors when container id is empty", func(t *testing.T) {
		containerInfoFunc = func(_ uint32) (Info, error) {
			return Info{ContainerID: ""}, nil
		}
		_, err := ownContainerID()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "container ID is empty")
	})
}

func TestOwnNamespace(t *testing.T) {
	prev := saNamespacePath
	t.Cleanup(func() { saNamespacePath = prev })

	t.Run("reads and trims namespace from file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "namespace")
		require.NoError(t, os.WriteFile(path, []byte("  beyla-system\n"), 0o600))
		saNamespacePath = path

		got, err := ownNamespace()
		require.NoError(t, err)
		assert.Equal(t, "beyla-system", got)
	})

	t.Run("returns error when file is missing", func(t *testing.T) {
		saNamespacePath = filepath.Join(t.TempDir(), "does-not-exist")
		_, err := ownNamespace()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "read SA namespace")
	})

	t.Run("returns error when file is empty or only whitespace", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "namespace")
		require.NoError(t, os.WriteFile(path, []byte("   \n  "), 0o600))
		saNamespacePath = path

		_, err := ownNamespace()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty")
	})
}

// makePod builds a minimal Pod with the given owner refs and a single container
// status whose ContainerID points at containerID (without any runtime scheme
// prefix; the caller can pass a scheme-prefixed string directly to test that).
func makePod(name, namespace, nodeName, containerID string, owners []metav1.OwnerReference) *corev1.Pod {
	statusContainerID := containerID
	if statusContainerID != "" && !strings.Contains(statusContainerID, "://") {
		statusContainerID = "containerd://" + statusContainerID
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       namespace,
			UID:             types.UID("uid-" + name),
			OwnerReferences: owners,
		},
		Spec: corev1.PodSpec{
			NodeName: nodeName,
		},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "main", ContainerID: statusContainerID},
			},
		},
	}
}

func newTestWriter(client *fake.Clientset, namespace, nodeName, containerID string) *StateConfigMapWriter {
	return &StateConfigMapWriter{
		logger:       slog.Default(),
		kubeClient:   client,
		nodeName:     nodeName,
		ownContainer: containerID,
		ownNamespace: namespace,
	}
}

func TestFindOwnPod(t *testing.T) {
	const (
		ns          = "beyla-system"
		node        = "node-1"
		containerID = "abc123def456"
	)

	t.Run("returns the pod whose container id matches", func(t *testing.T) {
		ourPod := makePod("beyla-xyz", ns, node, containerID, nil)
		other := makePod("other", ns, node, "ffffeeeeddddcccc", nil)
		client := fake.NewSimpleClientset(ourPod, other)
		w := newTestWriter(client, ns, node, containerID)

		got, err := w.findOwnPod(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "beyla-xyz", got.Name)
	})

	t.Run("only considers pods on the configured node (field selector applied)", func(t *testing.T) {
		// fake clientset doesn't natively honor field selectors - install a
		// reactor that filters by spec.nodeName like the real apiserver does.
		ourPod := makePod("beyla-on-our-node", ns, node, containerID, nil)
		offNode := makePod("beyla-on-other-node", ns, "other-node", containerID, nil)
		client := fake.NewSimpleClientset(ourPod, offNode)
		installNodeNameFieldSelectorReactor(client)

		w := newTestWriter(client, ns, node, containerID)

		got, err := w.findOwnPod(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "beyla-on-our-node", got.Name)
	})

	t.Run("errors when no pod matches the container id", func(t *testing.T) {
		other := makePod("not-us", ns, node, "ffffeeeeddddcccc", nil)
		client := fake.NewSimpleClientset(other)
		w := newTestWriter(client, ns, node, containerID)

		_, err := w.findOwnPod(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "own pod not found")
	})

	t.Run("errors when no pods exist in the namespace", func(t *testing.T) {
		client := fake.NewSimpleClientset()
		w := newTestWriter(client, ns, node, containerID)

		_, err := w.findOwnPod(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "own pod not found")
	})

	t.Run("propagates list errors", func(t *testing.T) {
		client := fake.NewSimpleClientset()
		client.PrependReactor("list", "pods", func(_ clienttesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewServiceUnavailable("apiserver down")
		})
		w := newTestWriter(client, ns, node, containerID)

		_, err := w.findOwnPod(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "list pods")
		assert.Contains(t, err.Error(), "apiserver down")
	})

	t.Run("matches when status container id has a runtime scheme prefix", func(t *testing.T) {
		ourPod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "beyla", Namespace: ns},
			Spec:       corev1.PodSpec{NodeName: node},
			Status: corev1.PodStatus{
				ContainerStatuses: []corev1.ContainerStatus{
					{Name: "main", ContainerID: "cri-o://" + containerID},
				},
			},
		}
		client := fake.NewSimpleClientset(ourPod)
		w := newTestWriter(client, ns, node, containerID) // own id has no scheme

		got, err := w.findOwnPod(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "beyla", got.Name)
	})
}

func TestFindDaemonSetOwner(t *testing.T) {
	const (
		ns          = "beyla-system"
		node        = "node-1"
		containerID = "abc123"
	)

	dsOwnerRef := metav1.OwnerReference{
		APIVersion: "apps/v1",
		Kind:       "DaemonSet",
		Name:       "beyla",
		UID:        types.UID("ds-uid"),
	}
	rsOwnerRef := metav1.OwnerReference{
		APIVersion: "apps/v1",
		Kind:       "ReplicaSet",
		Name:       "beyla-rs",
		UID:        types.UID("rs-uid"),
	}

	t.Run("returns owner ref for a daemonset-owned pod", func(t *testing.T) {
		pod := makePod("beyla-xyz", ns, node, containerID, []metav1.OwnerReference{dsOwnerRef})
		client := fake.NewSimpleClientset(pod)
		w := newTestWriter(client, ns, node, containerID)

		owner, err := w.findDaemonSetOwner(context.Background())
		require.NoError(t, err)
		require.NotNil(t, owner)
		assert.Equal(t, "apps/v1", owner.APIVersion)
		assert.Equal(t, "DaemonSet", owner.Kind)
		assert.Equal(t, "beyla", owner.Name)
		assert.Equal(t, types.UID("ds-uid"), owner.UID)
		require.NotNil(t, owner.Controller)
		assert.True(t, *owner.Controller)
		require.NotNil(t, owner.BlockOwnerDeletion)
		assert.False(t, *owner.BlockOwnerDeletion)
	})

	t.Run("nil owner when pod has no daemonset owner", func(t *testing.T) {
		pod := makePod("beyla-xyz", ns, node, containerID, []metav1.OwnerReference{rsOwnerRef})
		client := fake.NewSimpleClientset(pod)
		w := newTestWriter(client, ns, node, containerID)

		owner, err := w.findDaemonSetOwner(context.Background())
		require.NoError(t, err)
		assert.Nil(t, owner)
	})

	t.Run("nil owner when pod has no owner references at all", func(t *testing.T) {
		pod := makePod("beyla-xyz", ns, node, containerID, nil)
		client := fake.NewSimpleClientset(pod)
		w := newTestWriter(client, ns, node, containerID)

		owner, err := w.findDaemonSetOwner(context.Background())
		require.NoError(t, err)
		assert.Nil(t, owner)
	})

	t.Run("picks the daemonset owner among multiple owner refs", func(t *testing.T) {
		pod := makePod("beyla-xyz", ns, node, containerID,
			[]metav1.OwnerReference{rsOwnerRef, dsOwnerRef})
		client := fake.NewSimpleClientset(pod)
		w := newTestWriter(client, ns, node, containerID)

		owner, err := w.findDaemonSetOwner(context.Background())
		require.NoError(t, err)
		require.NotNil(t, owner)
		assert.Equal(t, "DaemonSet", owner.Kind)
		assert.Equal(t, "beyla", owner.Name)
	})

	t.Run("propagates pod lookup error", func(t *testing.T) {
		client := fake.NewSimpleClientset()
		w := newTestWriter(client, ns, node, containerID)

		_, err := w.findDaemonSetOwner(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "own pod not found")
	})
}

// installNodeNameFieldSelectorReactor makes the fake clientset honor a
// `spec.nodeName=<name>` field selector on `list pods`, which it does not do
// out of the box. Without this, every list returns every pod regardless of the
// FieldSelector option, hiding the production code's filtering from the test.
func installNodeNameFieldSelectorReactor(client *fake.Clientset) {
	client.PrependReactor("list", "pods", func(action clienttesting.Action) (bool, runtime.Object, error) {
		listAction, ok := action.(clienttesting.ListAction)
		if !ok {
			return false, nil, nil
		}
		fs := listAction.GetListRestrictions().Fields
		if fs == nil || fs.Empty() {
			return false, nil, nil
		}
		nodeName, ok := fs.RequiresExactMatch("spec.nodeName")
		if !ok {
			return false, nil, nil
		}

		// Pull the underlying tracker through a non-reactor path by reading all
		// pods and filtering. The fake clientset stores objects in a tracker we
		// can access via the typed list call (re-entry is safe because we only
		// match the original action via field selector).
		all, err := client.Tracker().List(
			schema.GroupVersionResource{Version: "v1", Resource: "pods"},
			schema.GroupVersionKind{Version: "v1", Kind: "Pod"},
			listAction.GetNamespace(),
		)
		if err != nil {
			return true, nil, err
		}
		list, ok := all.(*corev1.PodList)
		if !ok {
			return true, nil, errors.New("unexpected list type from tracker")
		}
		filtered := &corev1.PodList{ListMeta: list.ListMeta}
		for i := range list.Items {
			if list.Items[i].Spec.NodeName == nodeName {
				filtered.Items = append(filtered.Items, list.Items[i])
			}
		}
		return true, filtered, nil
	})
}
