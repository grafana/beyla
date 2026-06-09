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
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	"go.opentelemetry.io/obi/pkg/appolly/services"

	"github.com/grafana/beyla/v3/pkg/beyla"
	servicesextra "github.com/grafana/beyla/v3/pkg/services"
	"github.com/grafana/beyla/v3/pkg/webhook/configmap"
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

func TestBuildInjectConfig(t *testing.T) {
	// defaultEnv returns the minimum env var set produced for any rule when no
	// optional fields (propagators, sampler, debug, resources) are set.
	defaultEnv := func(endpoint, protocol string) []corev1.EnvVar {
		return []corev1.EnvVar{
			{Name: "OTEL_EXPORTER_OTLP_ENDPOINT", Value: endpoint},
			{Name: "OTEL_EXPORTER_OTLP_PROTOCOL", Value: protocol},
			{Name: "OTEL_TRACES_EXPORTER", Value: "otlp"},
			{Name: "OTEL_METRICS_EXPORTER", Value: "otlp"},
			{Name: "OTEL_LOGS_EXPORTER", Value: "none"},
		}
	}

	deployment := services.NewGlob("Deployment")
	statefulSet := services.NewGlob("StatefulSet")
	daemonSet := services.NewGlob("DaemonSet")

	tests := []struct {
		name     string
		cfg      beyla.Config
		endpoint string
		protocol string
		want     configmap.InjectConfig
	}{
		{
			name:     "empty instrument yields empty config",
			cfg:      beyla.Config{Injector: beyla.SDKInject{}},
			endpoint: "http://otel:4318",
			protocol: "http/protobuf",
			want:     configmap.InjectConfig{},
		},
		{
			name: "single selector becomes one rule with all default env vars",
			cfg: beyla.Config{Injector: beyla.SDKInject{
				Instrument: services.GlobDefinitionCriteria{{Metadata: services.MetadataGlobMap{"k8s_kind": &deployment}}},
			}},
			endpoint: "http://otel:4318",
			protocol: "http/protobuf",
			want: configmap.InjectConfig{Rules: []configmap.Rule{{
				Selector: configmap.K8sSelector{OwnerKinds: []string{"Deployment"}},
				Config:   configmap.RuleConfig{Env: defaultEnv("http://otel:4318", "http/protobuf")},
			}}},
		},
		{
			name: "multiple selectors each get the same env",
			cfg: beyla.Config{Injector: beyla.SDKInject{
				Instrument: services.GlobDefinitionCriteria{
					{Metadata: services.MetadataGlobMap{"k8s_kind": &deployment}},
					{Metadata: services.MetadataGlobMap{"k8s_kind": &statefulSet}},
				},
			}},
			endpoint: "http://otel:4318",
			protocol: "grpc",
			want: configmap.InjectConfig{Rules: []configmap.Rule{
				{Selector: configmap.K8sSelector{OwnerKinds: []string{"Deployment"}}, Config: configmap.RuleConfig{Env: defaultEnv("http://otel:4318", "grpc")}},
				{Selector: configmap.K8sSelector{OwnerKinds: []string{"StatefulSet"}}, Config: configmap.RuleConfig{Env: defaultEnv("http://otel:4318", "grpc")}},
			}},
		},
		{
			name: "ImageVersion is set at the top level",
			cfg: beyla.Config{Injector: beyla.SDKInject{
				ImageVersion: "ghcr.io/grafana/beyla/inject-sdk-image:v1.2.3",
				Instrument:   services.GlobDefinitionCriteria{{Metadata: services.MetadataGlobMap{"k8s_kind": &deployment}}},
			}},
			endpoint: "http://otel:4318",
			protocol: "http/protobuf",
			want: configmap.InjectConfig{
				ImageVersion: "ghcr.io/grafana/beyla/inject-sdk-image:v1.2.3",
				Rules: []configmap.Rule{{
					Selector: configmap.K8sSelector{OwnerKinds: []string{"Deployment"}},
					Config:   configmap.RuleConfig{Env: defaultEnv("http://otel:4318", "http/protobuf")},
				}},
			},
		},
		{
			name: "propagators written as OTEL_PROPAGATORS",
			cfg: beyla.Config{Injector: beyla.SDKInject{
				Instrument:  services.GlobDefinitionCriteria{{Metadata: services.MetadataGlobMap{"k8s_kind": &deployment}}},
				Propagators: []string{"tracecontext", "baggage"},
			}},
			endpoint: "http://otel:4318",
			protocol: "http/protobuf",
			want: configmap.InjectConfig{Rules: []configmap.Rule{{
				Selector: configmap.K8sSelector{OwnerKinds: []string{"Deployment"}},
				Config: configmap.RuleConfig{Env: append(
					defaultEnv("http://otel:4318", "http/protobuf"),
					corev1.EnvVar{Name: "OTEL_PROPAGATORS", Value: "tracecontext,baggage"},
				)},
			}}},
		},
		{
			name: "exclude_instrument becomes a leading skip rule",
			cfg: beyla.Config{Injector: beyla.SDKInject{
				Instrument:        services.GlobDefinitionCriteria{{Metadata: services.MetadataGlobMap{"k8s_kind": &deployment}}},
				ExcludeInstrument: services.GlobDefinitionCriteria{{Metadata: services.MetadataGlobMap{"k8s_kind": &daemonSet}}},
			}},
			endpoint: "http://otel:4318",
			protocol: "http/protobuf",
			want: configmap.InjectConfig{Rules: []configmap.Rule{
				{
					Selector: configmap.K8sSelector{OwnerKinds: []string{"DaemonSet"}},
					Config:   configmap.RuleConfig{Mode: configmap.ModeSkip},
				},
				{
					Selector: configmap.K8sSelector{OwnerKinds: []string{"Deployment"}},
					Config:   configmap.RuleConfig{Env: defaultEnv("http://otel:4318", "http/protobuf")},
				},
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildInjectConfig(&tt.cfg, tt.endpoint, tt.protocol)
			assert.Equal(t, tt.want, got)
		})
	}
}

func newGlobDef(namespace, ownerName, kind string, labels, annotations map[string]string) services.GlobAttributes {
	ptrGlobs := func(m map[string]string) map[string]*services.GlobAttr {
		if m == nil {
			return nil
		}
		out := make(map[string]*services.GlobAttr, len(m))
		for k, v := range m {
			g := services.NewGlob(v)
			out[k] = &g
		}
		return out
	}
	ns := services.NewGlob(namespace)
	owner := services.NewGlob(ownerName)
	metadata := services.MetadataGlobMap{
		services.AttrNamespace: &ns,
	}
	switch kind {
	case "Deployment":
		metadata[services.AttrDeploymentName] = &owner
	case "DaemonSet":
		metadata[services.AttrDaemonSetName] = &owner
	case "ReplicaSet":
		metadata[services.AttrReplicaSetName] = &owner
	case "StatefulSet":
		metadata[services.AttrStatefulSetName] = &owner
	case "Job":
		metadata[services.AttrJobName] = &owner
	case "CronJob":
		metadata[services.AttrCronJobName] = &owner
	case "Pod":
		metadata[services.AttrPodName] = &owner
	default:
		metadata[services.AttrOwnerName] = &owner
	}
	return services.GlobAttributes{
		Metadata:       metadata,
		PodLabels:      ptrGlobs(labels),
		PodAnnotations: ptrGlobs(annotations),
	}
}

func TestRuleFromDefinition(t *testing.T) {
	// valGlobs mirrors newGlobDef's pointer maps as the by-value maps the
	// resulting K8sSelector carries.
	valGlobs := func(m map[string]string) map[string]services.GlobAttr {
		out := map[string]services.GlobAttr{}
		for k, v := range m {
			out[k] = services.NewGlob(v)
		}
		return out
	}

	t.Run("maps metadata onto selector fields and carries the mode", func(t *testing.T) {
		def := newGlobDef("prod", "checkout", "Deployment", nil, nil)
		got := ruleFromDefinition(&def, configmap.ModeSkip)
		assert.Equal(t, &configmap.Rule{
			Selector: configmap.K8sSelector{
				Namespaces: []services.GlobAttr{services.NewGlob("prod")},
				OwnerNames: []services.GlobAttr{services.NewGlob("checkout")},
				OwnerKinds: []string{"Deployment"},
			},
			Config: configmap.RuleConfig{Mode: configmap.ModeSkip},
		}, got)
	})

	t.Run("copies pod labels and annotations", func(t *testing.T) {
		def := newGlobDef("*", "*", "*",
			map[string]string{"app": "checkout", "tier": "web-*"},
			map[string]string{"team": "payments"},
		)
		got := ruleFromDefinition(&def, configmap.ModeSkip)
		assert.Equal(t, valGlobs(map[string]string{"app": "checkout", "tier": "web-*"}), got.Selector.PodLabels)
		assert.Equal(t, valGlobs(map[string]string{"team": "payments"}), got.Selector.PodAnnotations)
	})

	t.Run("absent label/annotation maps stay nil", func(t *testing.T) {
		def := newGlobDef("ns", "owner", "Kind", nil, nil)
		got := ruleFromDefinition(&def, configmap.ModeSkip)
		assert.Nil(t, got.Selector.PodLabels)
		assert.Nil(t, got.Selector.PodAnnotations)
	})

	t.Run("mode is passed through unchanged", func(t *testing.T) {
		def := newGlobDef("ns", "owner", "Kind", nil, nil)
		got := ruleFromDefinition(&def, configmap.Mode(""))
		assert.Equal(t, configmap.Mode(""), got.Config.Mode)
	})

	t.Run("specific owner metadata infers kind without requiring namespace", func(t *testing.T) {
		// A definition carrying only a deployment name, with namespace and
		// generic owner-name absent from Metadata. The absent keys must not be
		// dereferenced.
		owner := services.NewGlob("checkout")
		def := services.GlobAttributes{
			Metadata: services.MetadataGlobMap{
				services.AttrDeploymentName: &owner,
			},
		}

		var got configmap.Rule
		require.NotPanics(t, func() { got = *ruleFromDefinition(&def, configmap.ModeSkip) })

		assert.Nil(t, got.Selector.Namespaces)
		assert.Equal(t, []services.GlobAttr{services.NewGlob("checkout")}, got.Selector.OwnerNames)
		assert.Equal(t, []string{"Deployment"}, got.Selector.OwnerKinds)
	})

	t.Run("maps all specific owner metadata keys onto owner kinds", func(t *testing.T) {
		tests := []struct {
			name        string
			metadataKey string
			kind        string
		}{
			{name: "deployment", metadataKey: services.AttrDeploymentName, kind: "Deployment"},
			{name: "daemonset", metadataKey: services.AttrDaemonSetName, kind: "DaemonSet"},
			{name: "replicaset", metadataKey: services.AttrReplicaSetName, kind: "ReplicaSet"},
			{name: "statefulset", metadataKey: services.AttrStatefulSetName, kind: "StatefulSet"},
			{name: "job", metadataKey: services.AttrJobName, kind: "Job"},
			{name: "cronjob", metadataKey: services.AttrCronJobName, kind: "CronJob"},
			{name: "pod", metadataKey: services.AttrPodName, kind: "Pod"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				owner := services.NewGlob("owner-*")
				def := services.GlobAttributes{
					Metadata: services.MetadataGlobMap{
						tt.metadataKey: &owner,
					},
				}

				got := ruleFromDefinition(&def, configmap.ModeSkip)
				assert.Equal(t, []services.GlobAttr{services.NewGlob("owner-*")}, got.Selector.OwnerNames)
				assert.Equal(t, []string{tt.kind}, got.Selector.OwnerKinds)
			})
		}
	})

	t.Run("empty metadata yields an all-wildcard selector without panicking", func(t *testing.T) {
		def := services.GlobAttributes{}

		var got *configmap.Rule
		require.NotPanics(t, func() { got = ruleFromDefinition(&def, configmap.ModeSkip) })

		assert.Nil(t, got)
	})
}

func TestRulesFromDiscoveryInstrument(t *testing.T) {
	t.Run("returns nil when nothing is configured", func(t *testing.T) {
		got := rulesFromDiscoveryInstrument(&servicesextra.BeylaDiscoveryConfig{})
		assert.Nil(t, got)
	})

	t.Run("instrument entries become install rules", func(t *testing.T) {
		d := &servicesextra.BeylaDiscoveryConfig{
			Instrument: services.GlobDefinitionCriteria{
				newGlobDef("ns", "checkout", "Deployment", nil, nil),
			},
		}
		got := rulesFromDiscoveryInstrument(d)
		require.Len(t, got, 1)
		assert.Equal(t, configmap.ModeInstall, got[0].Config.Mode)
		assert.Equal(t, []services.GlobAttr{services.NewGlob("checkout")}, got[0].Selector.OwnerNames)
	})

	t.Run("emits default-exclude, then exclude, then instrument rules in order", func(t *testing.T) {
		d := &servicesextra.BeylaDiscoveryConfig{
			DefaultExcludeInstrument: services.GlobDefinitionCriteria{
				newGlobDef("ns", "beyla", "DaemonSet", nil, nil),
			},
			ExcludeInstrument: services.GlobDefinitionCriteria{
				newGlobDef("ns", "alloy", "Deployment", nil, nil),
			},
			Instrument: services.GlobDefinitionCriteria{
				newGlobDef("ns", "checkout", "Deployment", nil, nil),
				newGlobDef("ns", "cart", "StatefulSet", nil, nil),
			},
		}
		got := rulesFromDiscoveryInstrument(d)
		require.Len(t, got, 4)

		// Order is default-excludes, then excludes, then instrument entries.
		// Excludes are emitted as skip rules; instrument entries as install rules.
		want := []struct {
			owner string
			mode  configmap.Mode
		}{
			{"beyla", configmap.ModeSkip},
			{"alloy", configmap.ModeSkip},
			{"checkout", configmap.ModeInstall},
			{"cart", configmap.ModeInstall},
		}
		for i, w := range want {
			assert.Equal(t, []services.GlobAttr{services.NewGlob(w.owner)}, got[i].Selector.OwnerNames, "rule %d owner", i)
			assert.Equal(t, w.mode, got[i].Config.Mode, "rule %d mode", i)
		}
	})

	t.Run("emits default-exclude, then instrument rules in order", func(t *testing.T) {
		d := &servicesextra.BeylaDiscoveryConfig{
			DefaultExcludeInstrument: servicesextra.DefaultExcludeInstrument,
			Instrument: services.GlobDefinitionCriteria{
				newGlobDef("ns", "checkout", "Deployment", nil, nil),
				newGlobDef("ns", "cart", "StatefulSet", nil, nil),
			},
		}
		got := rulesFromDiscoveryInstrument(d)
		require.Len(t, got, 3)
	})

}
