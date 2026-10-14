package webhook

import (
	"testing"

	"github.com/stretchr/testify/assert"
	appsv1 "k8s.io/api/apps/v1"

	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
	"go.opentelemetry.io/obi/pkg/transform"

	"github.com/grafana/beyla/v3/pkg/beyla"
)

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
