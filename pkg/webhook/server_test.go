package webhook

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
	"go.opentelemetry.io/obi/pkg/transform"
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
			server := &Server{}

			result := server.addMetadata(tt.processInfo, tt.objectMeta)

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

func TestServer_CleanupOldInstrumentationVersions(t *testing.T) {
	tests := []struct {
		name           string
		minVersion     string
		setupDirs      []string
		expectError    bool
		expectedRemain []string
	}{
		{
			name:       "removes older versions",
			minVersion: "v0.0.5",
			setupDirs: []string{
				"v0.0.3",
				"v0.0.4",
				"v0.0.5",
				"v0.0.6",
			},
			expectError: false,
			expectedRemain: []string{
				"v0.0.5",
				"v0.0.6",
			},
		},
		{
			name:       "keeps all versions when min is oldest",
			minVersion: "v0.0.1",
			setupDirs: []string{
				"v0.0.3",
				"v0.0.4",
				"v0.0.5",
			},
			expectError: false,
			expectedRemain: []string{
				"v0.0.3",
				"v0.0.4",
				"v0.0.5",
			},
		},
		{
			name:       "removes all versions when min is newest",
			minVersion: "v1.0.0",
			setupDirs: []string{
				"v0.0.3",
				"v0.0.4",
				"v0.0.5",
			},
			expectError:    false,
			expectedRemain: []string{},
		},
		{
			name:       "ignores non-semver directories",
			minVersion: "v0.0.5",
			setupDirs: []string{
				"v0.0.3",
				"v0.0.5",
				"not-a-version",
				"temp",
				".hidden",
			},
			expectError: false,
			expectedRemain: []string{
				"v0.0.5",
				"not-a-version",
				"temp",
				".hidden",
			},
		},
		{
			name:        "error on invalid minimum version",
			minVersion:  "not-a-version",
			setupDirs:   []string{},
			expectError: true,
		},
		{
			name:           "handles empty directory",
			minVersion:     "v0.0.5",
			setupDirs:      []string{},
			expectError:    false,
			expectedRemain: []string{},
		},
		{
			name:       "handles versions with different major/minor",
			minVersion: "v0.1.0",
			setupDirs: []string{
				"v0.0.9",
				"v0.1.0",
				"v0.1.1",
				"v0.2.0",
				"v1.0.0",
			},
			expectError: false,
			expectedRemain: []string{
				"v0.1.0",
				"v0.1.1",
				"v0.2.0",
				"v1.0.0",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary directory
			tmpDir, err := os.MkdirTemp("", "instrumentation-test-*")
			require.NoError(t, err)
			defer os.RemoveAll(tmpDir)

			// Setup directories
			for _, dir := range tt.setupDirs {
				dirPath := filepath.Join(tmpDir, dir)
				err := os.Mkdir(dirPath, 0755)
				require.NoError(t, err)

				// Create a dummy file to ensure it's not empty
				dummyFile := filepath.Join(dirPath, "dummy.txt")
				err = os.WriteFile(dummyFile, []byte("test"), 0644)
				require.NoError(t, err)
			}

			// Also create some non-directory files to verify they're ignored
			if len(tt.setupDirs) > 0 {
				nonDirFile := filepath.Join(tmpDir, "file.txt")
				err = os.WriteFile(nonDirFile, []byte("test"), 0644)
				require.NoError(t, err)
			}

			server := &Server{
				logger: slog.With("component", "test"),
			}

			err = server.cleanupOldInstrumentationVersions(tmpDir, tt.minVersion)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)

			// Check remaining directories
			entries, err := os.ReadDir(tmpDir)
			require.NoError(t, err)

			var remainingDirs []string
			for _, entry := range entries {
				if entry.IsDir() {
					remainingDirs = append(remainingDirs, entry.Name())
				}
			}

			assert.ElementsMatch(t, tt.expectedRemain, remainingDirs)
		})
	}

	t.Run("error when directory doesn't exist", func(t *testing.T) {
		server := &Server{
			logger: slog.With("component", "test"),
		}

		err := server.cleanupOldInstrumentationVersions("/nonexistent/path", "v0.0.5")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read directory")
	})
}
