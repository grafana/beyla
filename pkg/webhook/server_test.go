package webhook

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/golang-lru/v2/simplelru"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
	"go.opentelemetry.io/obi/pkg/transform"

	"github.com/grafana/beyla/v3/pkg/beyla"
	"github.com/grafana/beyla/v3/pkg/webhook/configmap"
)

func TestEmptySelectionClearsInjectorState(t *testing.T) {
	for _, restrictLocal := range []bool{false, true} {
		t.Run(fmt.Sprintf("restrict_local_node=%v", restrictLocal), func(t *testing.T) {
			client := fake.NewSimpleClientset()
			pod := makePod("alloy-1", "monitoring", "node-1", "alloy-container", []metav1.OwnerReference{
				{APIVersion: "apps/v1", Kind: "DaemonSet", Name: "alloy", UID: "alloy-uid"},
			})
			writer := newTestWriter(client, pod)
			require.NoError(t, writer.Init(t.Context()))
			previous := &beyla.Config{}
			namespace := services.NewGlob("apps")
			previous.Injector.Instrument = services.GlobDefinitionCriteria{{
				Metadata: map[string]*services.GlobAttr{services.AttrNamespace: &namespace},
			}}
			oldConfig := buildInjectConfig(previous, "http://alloy:4318", "http/protobuf")
			require.NotEmpty(t, oldConfig.Rules)
			require.NoError(t, writer.Write(t.Context(), &oldConfig, nil))

			eligible, err := simplelru.NewLRU[string, *configmap.EligibleDeployment](maxEligibleDeployments, nil)
			require.NoError(t, err)
			// This workload list would exceed the 1 MiB ConfigMap limit. Empty
			// selections must publish a small payload regardless of cached targets.
			for i := range 8000 {
				d := &configmap.EligibleDeployment{
					Namespace: "production", Kind: "Deployment",
					Name: fmt.Sprintf("java-service-%05d", i), Hash: strings.Repeat("a", 64),
				}
				eligible.Add(d.Name, d)
			}
			largeYAML, err := yaml.Marshal(eligible.Values())
			require.NoError(t, err)
			require.Greater(t, len(largeYAML), 1<<20)
			cfg := &beyla.Config{}
			cfg.Attributes.Kubernetes.MetaRestrictLocalNode = restrictLocal
			server := &Server{
				cfg: cfg, matcher: NewPodMatcher(cfg), logger: slog.Default(),
				mutator:     &PodMutator{endpoint: "http://alloy:4318", proto: "http/protobuf"},
				stateWriter: writer, eligibleDeployments: eligible, nodeName: "node-1",
			}
			// No metadata provider or process scanner is needed for empty startup.
			server.startInitialState(t.Context())
			require.NotZero(t, server.stateWriteRequestNS.Load())
			server.rebuildEligibleDeployments()
			// Age the request to avoid waiting the production debounce interval.
			requested := time.Now().Add(-2 * stateConfigMapDebounceDelay).UnixNano()
			server.stateWriteRequestNS.Store(requested)
			event := &informer.Event{Type: informer.EventType_UPDATED, Resource: &informer.ObjectMeta{
				Name: "java", Namespace: "apps",
				Annotations: map[string]string{"beyla.grafana.com/inject": "old-config"},
				Pod:         &informer.PodInfo{NodeName: "node-1"},
			}}
			for range 1000 {
				require.NoError(t, server.On(event))
			}
			require.Equal(t, requested, server.stateWriteRequestNS.Load(), "pod events must not postpone empty configuration")
			var attempts atomic.Int64
			client.PrependReactor("update", "configmaps", func(clienttesting.Action) (bool, runtime.Object, error) {
				if attempts.Add(1) == 1 {
					return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "configmaps"}, "alloy", fmt.Errorf("stale resource version"))
				}
				return false, nil, nil
			})

			ctx, cancel := context.WithCancel(t.Context())
			stopped := make(chan struct{})
			go func() {
				defer close(stopped)
				server.runStateConfigMapWriter(ctx)
			}()
			defer func() { cancel(); <-stopped }()
			require.Eventually(t, func() bool {
				return attempts.Load() == 1 && server.stateWriteRequestNS.Load() > requested
			}, 5*time.Second, 10*time.Millisecond, "empty configuration must be retried after an API conflict")
			server.stateWriteRequestNS.Store(requested)
			require.Eventually(t, func() bool {
				cm, err := client.CoreV1().ConfigMaps("monitoring").Get(ctx, stateConfigMapName("alloy", "node-1"), metav1.GetOptions{})
				if err != nil {
					return false
				}
				var config configmap.InjectConfig
				if yaml.Unmarshal([]byte(cm.Data[configmap.KeyInstrumentation]), &config) != nil {
					return false
				}
				return len(config.Rules) == 0
			}, 5*time.Second, 10*time.Millisecond)
			cm, err := client.CoreV1().ConfigMaps("monitoring").Get(ctx, stateConfigMapName("alloy", "node-1"), metav1.GetOptions{})
			require.NoError(t, err)
			var targets []*configmap.EligibleDeployment
			require.NoError(t, yaml.Unmarshal([]byte(cm.Data[configmap.KeyEligibleForRestart]), &targets))
			assert.Empty(t, targets)
			assert.Equal(t, int64(2), attempts.Load())
			assert.Less(t, len(cm.Data[configmap.KeyEligibleForRestart])+len(cm.Data[configmap.KeyInstrumentation]), 1<<20)
		})
	}
}

func TestEnrichProcessInfo(t *testing.T) {
	tests := []struct {
		name         string
		initialState map[string][]*ProcessInfo
		pod          *informer.ObjectMeta
		expected     int
	}{
		{
			name: "matches containers with process info",
			initialState: map[string][]*ProcessInfo{
				"container-1": {
					{pid: 123},
					{pid: 456},
				},
				"container-2": {
					{pid: 789},
				},
			},
			pod: &informer.ObjectMeta{
				Name:      "test-pod",
				Namespace: "default",
				Pod: &informer.PodInfo{
					Containers: []*informer.ContainerInfo{
						{Id: "container-1"},
						{Id: "container-2"},
					},
				},
			},
			expected: 3, // 2 from container-1 + 1 from container-2
		},
		{
			name: "no matching containers",
			initialState: map[string][]*ProcessInfo{
				"container-1": {
					{pid: 123},
				},
			},
			pod: &informer.ObjectMeta{
				Name:      "test-pod",
				Namespace: "default",
				Pod: &informer.PodInfo{
					Containers: []*informer.ContainerInfo{
						{Id: "different-container"},
					},
				},
			},
			expected: 0,
		},
		{
			name: "partial match",
			initialState: map[string][]*ProcessInfo{
				"container-1": {
					{pid: 123},
				},
				"container-2": {
					{pid: 456},
				},
			},
			pod: &informer.ObjectMeta{
				Name:      "test-pod",
				Namespace: "default",
				Pod: &informer.PodInfo{
					Containers: []*informer.ContainerInfo{
						{Id: "container-1"},
						{Id: "container-3"}, // doesn't exist in initialState
					},
				},
			},
			expected: 1, // only container-1 matches
		},
		{
			name:         "empty initial state",
			initialState: map[string][]*ProcessInfo{},
			pod: &informer.ObjectMeta{
				Name:      "test-pod",
				Namespace: "default",
				Pod: &informer.PodInfo{
					Containers: []*informer.ContainerInfo{
						{Id: "container-1"},
					},
				},
			},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := &Server{
				initialState: tt.initialState,
			}

			result := server.enrichProcessInfo(tt.pod)

			assert.Len(t, result, tt.expected)
		})
	}
}

func TestTopOwner(t *testing.T) {
	tests := []struct {
		name     string
		owners   []*informer.Owner
		expected *informer.Owner
	}{
		{
			name: "returns last owner",
			owners: []*informer.Owner{
				{Kind: "ReplicaSet", Name: "my-app-abc123"},
				{Kind: "Deployment", Name: "my-app"},
			},
			expected: &informer.Owner{Kind: "Deployment", Name: "my-app"},
		},
		{
			name: "single owner",
			owners: []*informer.Owner{
				{Kind: "StatefulSet", Name: "my-statefulset"},
			},
			expected: &informer.Owner{Kind: "StatefulSet", Name: "my-statefulset"},
		},
		{
			name:     "empty owners",
			owners:   []*informer.Owner{},
			expected: nil,
		},
		{
			name:     "nil owners",
			owners:   nil,
			expected: nil,
		},
		{
			name: "three owners - returns last",
			owners: []*informer.Owner{
				{Kind: "ReplicaSet", Name: "my-app-abc123"},
				{Kind: "Deployment", Name: "my-app"},
				{Kind: "CustomResource", Name: "my-custom"},
			},
			expected: &informer.Owner{Kind: "CustomResource", Name: "my-custom"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := topOwner(tt.owners)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestServer_AddMetadata(t *testing.T) {
	tests := []struct {
		name                string
		processInfo         *ProcessInfo
		objectMeta          *informer.ObjectMeta
		expectedMetadata    map[string]string
		expectedLabels      map[string]string
		expectedAnnotations map[string]string
	}{
		{
			name: "basic pod with deployment owner",
			processInfo: &ProcessInfo{
				pid: 123,
			},
			objectMeta: &informer.ObjectMeta{
				Name:      "test-pod-abc",
				Namespace: "production",
				Labels: map[string]string{
					"app": "my-app",
				},
				Annotations: map[string]string{
					"version": "1.0.0",
				},
				Pod: &informer.PodInfo{
					Owners: []*informer.Owner{
						{Kind: "ReplicaSet", Name: "my-app-xyz123"},
						{Kind: "Deployment", Name: "my-app"},
					},
				},
			},
			expectedMetadata: map[string]string{
				services.AttrNamespace:                        "production",
				services.AttrPodName:                          "test-pod-abc",
				services.AttrOwnerName:                        "my-app",
				transform.OwnerLabelName("ReplicaSet").Prom(): "my-app-xyz123",
				transform.OwnerLabelName("Deployment").Prom(): "my-app",
			},
			expectedLabels: map[string]string{
				"app": "my-app",
			},
			expectedAnnotations: map[string]string{
				"version": "1.0.0",
			},
		},
		{
			name: "pod without owners",
			processInfo: &ProcessInfo{
				pid: 456,
			},
			objectMeta: &informer.ObjectMeta{
				Name:      "standalone-pod",
				Namespace: "default",
				Labels: map[string]string{
					"standalone": "true",
				},
				Pod: &informer.PodInfo{
					Owners: []*informer.Owner{},
				},
			},
			expectedMetadata: map[string]string{
				services.AttrNamespace: "default",
				services.AttrPodName:   "standalone-pod",
				services.AttrOwnerName: "standalone-pod", // uses pod name when no owners
			},
			expectedLabels: map[string]string{
				"standalone": "true",
			},
		},
		{
			name: "pod with statefulset owner",
			processInfo: &ProcessInfo{
				pid: 789,
			},
			objectMeta: &informer.ObjectMeta{
				Name:      "my-statefulset-0",
				Namespace: "databases",
				Pod: &informer.PodInfo{
					Owners: []*informer.Owner{
						{Kind: "StatefulSet", Name: "my-statefulset"},
					},
				},
			},
			expectedMetadata: map[string]string{
				services.AttrNamespace:                         "databases",
				services.AttrPodName:                           "my-statefulset-0",
				services.AttrOwnerName:                         "my-statefulset",
				transform.OwnerLabelName("StatefulSet").Prom(): "my-statefulset",
			},
		},
		{
			name: "pod with job and cronjob owners",
			processInfo: &ProcessInfo{
				pid: 999,
			},
			objectMeta: &informer.ObjectMeta{
				Name:      "my-cronjob-123456-abc",
				Namespace: "batch",
				Pod: &informer.PodInfo{
					Owners: []*informer.Owner{
						{Kind: "Job", Name: "my-cronjob-123456"},
						{Kind: "CronJob", Name: "my-cronjob"},
					},
				},
			},
			expectedMetadata: map[string]string{
				services.AttrNamespace:                     "batch",
				services.AttrPodName:                       "my-cronjob-123456-abc",
				services.AttrOwnerName:                     "my-cronjob",
				transform.OwnerLabelName("Job").Prom():     "my-cronjob-123456",
				transform.OwnerLabelName("CronJob").Prom(): "my-cronjob",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := addMetadata(tt.processInfo, tt.objectMeta)

			assert.NotNil(t, result)
			assert.Equal(t, tt.processInfo.pid, result.pid)

			// Check metadata
			for key, expected := range tt.expectedMetadata {
				actual, ok := result.metadata[key]
				assert.True(t, ok, "metadata key %s not found", key)
				assert.Equal(t, expected, actual, "metadata key %s has wrong value", key)
			}

			// Check labels
			if tt.expectedLabels != nil {
				assert.Equal(t, tt.expectedLabels, result.podLabels)
			}

			// Check annotations
			if tt.expectedAnnotations != nil {
				assert.Equal(t, tt.expectedAnnotations, result.podAnnotations)
			}
		})
	}
}

func TestServer_IsExternalWebhookEvent(t *testing.T) {
	tests := []struct {
		name            string
		externalWebhook string
		pod             *informer.ObjectMeta
		expected        bool
	}{
		{
			name:            "replicaset owner strips hash and matches deployment",
			externalWebhook: "observability/otel-injector",
			pod: &informer.ObjectMeta{
				Name:      "otel-injector-7bdbc6fc5d-d7zhx",
				Namespace: "observability",
				Labels: map[string]string{
					appsv1.DefaultDeploymentUniqueLabelKey: "7bdbc6fc5d",
				},
				Pod: &informer.PodInfo{
					Owners: []*informer.Owner{
						{Kind: "ReplicaSet", Name: "otel-injector-7bdbc6fc5d"},
					},
				},
			},
			expected: true,
		},
		{
			name:            "deployment owner matches directly",
			externalWebhook: "observability/otel-injector",
			pod: &informer.ObjectMeta{
				Name:      "otel-injector-7bdbc6fc5d-d7zhx",
				Namespace: "observability",
				Pod: &informer.PodInfo{
					Owners: []*informer.Owner{
						{Kind: "Deployment", Name: "otel-injector"},
					},
				},
			},
			expected: true,
		},
		{
			name:            "deployment name prefix does not match another deployment",
			externalWebhook: "observability/otel-injector",
			pod: &informer.ObjectMeta{
				Name:      "otel-injector-extra-7bdbc6fc5d-d7zhx",
				Namespace: "observability",
				Labels: map[string]string{
					appsv1.DefaultDeploymentUniqueLabelKey: "7bdbc6fc5d",
				},
				Pod: &informer.PodInfo{
					Owners: []*informer.Owner{
						{Kind: "ReplicaSet", Name: "otel-injector-extra-7bdbc6fc5d"},
					},
				},
			},
			expected: false,
		},
		{
			name:            "different namespace does not match",
			externalWebhook: "observability/otel-injector",
			pod: &informer.ObjectMeta{
				Name:      "otel-injector-7bdbc6fc5d-d7zhx",
				Namespace: "default",
				Labels: map[string]string{
					appsv1.DefaultDeploymentUniqueLabelKey: "7bdbc6fc5d",
				},
				Pod: &informer.PodInfo{
					Owners: []*informer.Owner{
						{Kind: "ReplicaSet", Name: "otel-injector-7bdbc6fc5d"},
					},
				},
			},
			expected: false,
		},
		{
			name:            "direct replicaset with hyphenated name matches without stripping",
			externalWebhook: "observability/cluster-sleeper",
			pod: &informer.ObjectMeta{
				Name:      "cluster-sleeper-mz7wk",
				Namespace: "observability",
				Pod: &informer.PodInfo{
					Owners: []*informer.Owner{
						{Kind: "ReplicaSet", Name: "cluster-sleeper"},
						{Kind: "Deployment", Name: "cluster"},
					},
				},
			},
			expected: true,
		},
		{
			name:            "direct replicaset with hyphenated name does not match stripped prefix",
			externalWebhook: "observability/cluster",
			pod: &informer.ObjectMeta{
				Name:      "cluster-sleeper-mz7wk",
				Namespace: "observability",
				Pod: &informer.PodInfo{
					Owners: []*informer.Owner{
						{Kind: "ReplicaSet", Name: "cluster-sleeper"},
						{Kind: "Deployment", Name: "cluster"},
					},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := &Server{
				cfg: &beyla.Config{},
			}
			server.cfg.Injector.Webhook.ExternalWebhook = tt.externalWebhook

			assert.Equal(t, tt.expected, server.isExternalWebhookEvent(tt.pod))
		})
	}
}
