package webhook

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"

	"github.com/grafana/beyla/v2/pkg/beyla"
)

func TestChooseServiceName(t *testing.T) {
	tests := []struct {
		name                           string
		meta                           *metav1.ObjectMeta
		useLabelsForResourceAttributes bool
		podName                        string
		resources                      map[attribute.Key]string
		expected                       string
	}{
		{
			name: "uses annotation over all other options",
			meta: &metav1.ObjectMeta{
				Annotations: map[string]string{
					ResourceAttributeAnnotationPrefix + string(semconv.ServiceNameKey): "annotated-service",
				},
				Labels: map[string]string{
					"app.kubernetes.io/name": "labeled-service",
				},
			},
			useLabelsForResourceAttributes: true,
			podName:                        "my-pod",
			resources: map[attribute.Key]string{
				semconv.K8SDeploymentNameKey: "deployment-name",
			},
			expected: "annotated-service",
		},
		{
			name: "uses app.kubernetes.io/name label when enabled",
			meta: &metav1.ObjectMeta{
				Labels: map[string]string{
					"app.kubernetes.io/name": "labeled-service",
				},
			},
			useLabelsForResourceAttributes: true,
			podName:                        "my-pod",
			expected:                       "labeled-service",
		},
		{
			name: "uses app.kubernetes.io/instance label when name is missing",
			meta: &metav1.ObjectMeta{
				Labels: map[string]string{
					"app.kubernetes.io/instance": "instance-service",
				},
			},
			useLabelsForResourceAttributes: true,
			podName:                        "my-pod",
			expected:                       "instance-service",
		},
		{
			name: "does not use labels when disabled",
			meta: &metav1.ObjectMeta{
				Labels: map[string]string{
					"app.kubernetes.io/name": "labeled-service",
				},
			},
			useLabelsForResourceAttributes: false,
			podName:                        "my-pod",
			resources: map[attribute.Key]string{
				semconv.K8SDeploymentNameKey: "deployment-name",
			},
			expected: "deployment-name",
		},
		{
			name:                           "uses deployment name from resources",
			meta:                           &metav1.ObjectMeta{},
			useLabelsForResourceAttributes: false,
			podName:                        "my-pod",
			resources: map[attribute.Key]string{
				semconv.K8SDeploymentNameKey: "deployment-name",
			},
			expected: "deployment-name",
		},
		{
			name:                           "uses replicaset name from resources",
			meta:                           &metav1.ObjectMeta{},
			useLabelsForResourceAttributes: false,
			podName:                        "my-pod",
			resources: map[attribute.Key]string{
				semconv.K8SReplicaSetNameKey: "replicaset-name",
			},
			expected: "replicaset-name",
		},
		{
			name:                           "uses statefulset name from resources",
			meta:                           &metav1.ObjectMeta{},
			useLabelsForResourceAttributes: false,
			podName:                        "my-pod",
			resources: map[attribute.Key]string{
				semconv.K8SStatefulSetNameKey: "statefulset-name",
			},
			expected: "statefulset-name",
		},
		{
			name:                           "uses daemonset name from resources",
			meta:                           &metav1.ObjectMeta{},
			useLabelsForResourceAttributes: false,
			podName:                        "my-pod",
			resources: map[attribute.Key]string{
				semconv.K8SDaemonSetNameKey: "daemonset-name",
			},
			expected: "daemonset-name",
		},
		{
			name:                           "uses cronjob name from resources",
			meta:                           &metav1.ObjectMeta{},
			useLabelsForResourceAttributes: false,
			podName:                        "my-pod",
			resources: map[attribute.Key]string{
				semconv.K8SCronJobNameKey: "cronjob-name",
			},
			expected: "cronjob-name",
		},
		{
			name:                           "uses job name from resources",
			meta:                           &metav1.ObjectMeta{},
			useLabelsForResourceAttributes: false,
			podName:                        "my-pod",
			resources: map[attribute.Key]string{
				semconv.K8SJobNameKey: "job-name",
			},
			expected: "job-name",
		},
		{
			name:                           "falls back to pod name",
			meta:                           &metav1.ObjectMeta{},
			useLabelsForResourceAttributes: false,
			podName:                        "my-pod",
			resources:                      map[attribute.Key]string{},
			expected:                       "my-pod",
		},
		{
			name:                           "deployment takes precedence over replicaset",
			meta:                           &metav1.ObjectMeta{},
			useLabelsForResourceAttributes: false,
			podName:                        "my-pod",
			resources: map[attribute.Key]string{
				semconv.K8SDeploymentNameKey: "deployment-name",
				semconv.K8SReplicaSetNameKey: "replicaset-name",
			},
			expected: "deployment-name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := chooseServiceName(tt.meta, tt.useLabelsForResourceAttributes, tt.podName, tt.resources)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestChooseServiceVersion(t *testing.T) {
	tests := []struct {
		name                           string
		meta                           *metav1.ObjectMeta
		useLabelsForResourceAttributes bool
		container                      *corev1.Container
		expected                       string
	}{
		{
			name: "uses annotation over label and image",
			meta: &metav1.ObjectMeta{
				Annotations: map[string]string{
					ResourceAttributeAnnotationPrefix + string(semconv.ServiceVersionKey): "v2.0.0",
				},
				Labels: map[string]string{
					"app.kubernetes.io/version": "v1.0.0",
				},
			},
			useLabelsForResourceAttributes: true,
			container: &corev1.Container{
				Image: "myapp:v0.5.0",
			},
			expected: "v2.0.0",
		},
		{
			name: "uses label when enabled",
			meta: &metav1.ObjectMeta{
				Labels: map[string]string{
					"app.kubernetes.io/version": "v1.0.0",
				},
			},
			useLabelsForResourceAttributes: true,
			container: &corev1.Container{
				Image: "myapp:v0.5.0",
			},
			expected: "v1.0.0",
		},
		{
			name: "does not use label when disabled",
			meta: &metav1.ObjectMeta{
				Labels: map[string]string{
					"app.kubernetes.io/version": "v1.0.0",
				},
			},
			useLabelsForResourceAttributes: false,
			container: &corev1.Container{
				Image: "myapp:v0.5.0",
			},
			expected: "v0.5.0",
		},
		{
			name:                           "parses version from image tag",
			meta:                           &metav1.ObjectMeta{},
			useLabelsForResourceAttributes: false,
			container: &corev1.Container{
				Image: "myapp:v1.2.3",
			},
			expected: "v1.2.3",
		},
		{
			name:                           "parses version from image with registry",
			meta:                           &metav1.ObjectMeta{},
			useLabelsForResourceAttributes: false,
			container: &corev1.Container{
				Image: "docker.io/library/myapp:latest",
			},
			expected: "latest",
		},
		{
			name:                           "returns empty for image without tag",
			meta:                           &metav1.ObjectMeta{},
			useLabelsForResourceAttributes: false,
			container: &corev1.Container{
				Image: "myapp",
			},
			expected: "",
		},
		{
			name:                           "digest only",
			meta:                           &metav1.ObjectMeta{},
			useLabelsForResourceAttributes: false,
			container: &corev1.Container{
				Image: "myapp@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			},
			expected: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name:                           "tag and digest",
			meta:                           &metav1.ObjectMeta{},
			useLabelsForResourceAttributes: false,
			container: &corev1.Container{
				Image: "myapp:v1.0.0@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			},
			expected: "v1.0.0@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := chooseServiceVersion(tt.meta, tt.useLabelsForResourceAttributes, tt.container)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestChooseServiceNamespace(t *testing.T) {
	tests := []struct {
		name                           string
		meta                           *metav1.ObjectMeta
		useLabelsForResourceAttributes bool
		namespaceName                  string
		expected                       string
	}{
		{
			name: "uses annotation",
			meta: &metav1.ObjectMeta{
				Annotations: map[string]string{
					ResourceAttributeAnnotationPrefix + string(semconv.ServiceNamespaceKey): "annotated-ns",
				},
			},
			useLabelsForResourceAttributes: true,
			namespaceName:                  "default",
			expected:                       "annotated-ns",
		},
		{
			name:                           "falls back to namespace name",
			meta:                           &metav1.ObjectMeta{},
			useLabelsForResourceAttributes: true,
			namespaceName:                  "production",
			expected:                       "production",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := chooseServiceNamespace(tt.meta, tt.useLabelsForResourceAttributes, tt.namespaceName)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseServiceVersionFromImage(t *testing.T) {
	tests := []struct {
		name      string
		image     string
		expected  string
		expectErr bool
	}{
		{
			name:     "simple tag",
			image:    "myapp:v1.0.0",
			expected: "v1.0.0",
		},
		{
			name:     "tag with registry",
			image:    "docker.io/myapp:v1.0.0",
			expected: "v1.0.0",
		},
		{
			name:     "tag with full path",
			image:    "gcr.io/project/myapp:v1.0.0",
			expected: "v1.0.0",
		},
		{
			name:     "digest only",
			image:    "myapp@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			expected: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name:     "tag and digest",
			image:    "myapp:v1.0.0@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			expected: "v1.0.0@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name:      "invalid digest format - too short",
			image:     "myapp@sha256:abcdef",
			expectErr: true,
		},
		{
			name:      "invalid tag and digest format - too short",
			image:     "myapp:v1.0.0@sha256:abcdef",
			expectErr: true,
		},
		{
			name:     "latest tag",
			image:    "myapp:latest",
			expected: "latest",
		},
		{
			name:      "no tag or digest",
			image:     "myapp",
			expected:  "",
			expectErr: true,
		},
		{
			name:      "invalid image format",
			image:     ":::invalid:::",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseServiceVersionFromImage(tt.image)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestCreateServiceInstanceId(t *testing.T) {
	tests := []struct {
		name          string
		meta          *metav1.ObjectMeta
		namespaceName string
		podName       string
		containerName string
		expected      string
	}{
		{
			name: "uses annotation",
			meta: &metav1.ObjectMeta{
				Annotations: map[string]string{
					ResourceAttributeAnnotationPrefix + string(semconv.ServiceInstanceIDKey): "custom-instance-id",
				},
			},
			namespaceName: "default",
			podName:       "my-pod",
			containerName: "my-container",
			expected:      "custom-instance-id",
		},
		{
			name:          "creates from namespace, pod and container",
			meta:          &metav1.ObjectMeta{},
			namespaceName: "production",
			podName:       "web-server-abc123",
			containerName: "nginx",
			expected:      "production.web-server-abc123.nginx",
		},
		{
			name:          "returns empty when namespace is missing",
			meta:          &metav1.ObjectMeta{},
			namespaceName: "",
			podName:       "my-pod",
			containerName: "my-container",
			expected:      "",
		},
		{
			name:          "returns empty when pod name is missing",
			meta:          &metav1.ObjectMeta{},
			namespaceName: "default",
			podName:       "",
			containerName: "my-container",
			expected:      "",
		},
		{
			name:          "returns empty when container name is missing",
			meta:          &metav1.ObjectMeta{},
			namespaceName: "default",
			podName:       "my-pod",
			containerName: "",
			expected:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := createServiceInstanceId(tt.meta, tt.namespaceName, tt.podName, tt.containerName)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetResourceAttribute(t *testing.T) {
	tests := []struct {
		kind     string
		expected attribute.Key
	}{
		{"ReplicaSet", semconv.K8SReplicaSetNameKey},
		{"replicaset", semconv.K8SReplicaSetNameKey},
		{"REPLICASET", semconv.K8SReplicaSetNameKey},
		{"Deployment", semconv.K8SDeploymentNameKey},
		{"StatefulSet", semconv.K8SStatefulSetNameKey},
		{"DaemonSet", semconv.K8SDaemonSetNameKey},
		{"Job", semconv.K8SJobNameKey},
		{"CronJob", semconv.K8SCronJobNameKey},
		{"Unknown", ""},
		{"Pod", ""},
	}

	for _, tt := range tests {
		t.Run(tt.kind, func(t *testing.T) {
			result := getResourceAttribute(tt.kind)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAddParentResourceLabels(t *testing.T) {
	tests := []struct {
		name       string
		meta       *metav1.ObjectMeta
		includeUID bool
		expected   map[attribute.Key]string
	}{
		{
			name: "adds deployment owner",
			meta: &metav1.ObjectMeta{
				OwnerReferences: []metav1.OwnerReference{
					{
						Kind: "Deployment",
						Name: "my-deployment",
						UID:  "deployment-uid-123",
					},
				},
			},
			includeUID: false,
			expected: map[attribute.Key]string{
				semconv.K8SDeploymentNameKey: "my-deployment",
			},
		},
		{
			name: "adds deployment owner with UID",
			meta: &metav1.ObjectMeta{
				OwnerReferences: []metav1.OwnerReference{
					{
						Kind: "Deployment",
						Name: "my-deployment",
						UID:  "deployment-uid-123",
					},
				},
			},
			includeUID: true,
			expected: map[attribute.Key]string{
				semconv.K8SDeploymentNameKey: "deployment-uid-123",
			},
		},
		{
			name: "adds replicaset owner",
			meta: &metav1.ObjectMeta{
				OwnerReferences: []metav1.OwnerReference{
					{
						Kind: "ReplicaSet",
						Name: "my-replicaset",
						UID:  "rs-uid-456",
					},
				},
			},
			includeUID: false,
			expected: map[attribute.Key]string{
				semconv.K8SReplicaSetNameKey: "my-replicaset",
			},
		},
		{
			name: "adds statefulset owner",
			meta: &metav1.ObjectMeta{
				OwnerReferences: []metav1.OwnerReference{
					{
						Kind: "StatefulSet",
						Name: "my-statefulset",
						UID:  "ss-uid-789",
					},
				},
			},
			includeUID: false,
			expected: map[attribute.Key]string{
				semconv.K8SStatefulSetNameKey: "my-statefulset",
			},
		},
		{
			name: "adds daemonset owner",
			meta: &metav1.ObjectMeta{
				OwnerReferences: []metav1.OwnerReference{
					{
						Kind: "DaemonSet",
						Name: "my-daemonset",
						UID:  "ds-uid-101",
					},
				},
			},
			includeUID: false,
			expected: map[attribute.Key]string{
				semconv.K8SDaemonSetNameKey: "my-daemonset",
			},
		},
		{
			name: "adds job owner",
			meta: &metav1.ObjectMeta{
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion: "batch/v1",
						Kind:       "Job",
						Name:       "my-job-202",
						UID:        "job-uid-202",
					},
				},
			},
			includeUID: false,
			expected: map[attribute.Key]string{
				semconv.K8SJobNameKey:     "my-job-202",
				semconv.K8SCronJobNameKey: "my-job",
			},
		},
		{
			name: "adds cronjob owner",
			meta: &metav1.ObjectMeta{
				OwnerReferences: []metav1.OwnerReference{
					{
						Kind: "CronJob",
						Name: "my-cronjob",
						UID:  "cj-uid-303",
					},
				},
			},
			includeUID: false,
			expected: map[attribute.Key]string{
				semconv.K8SCronJobNameKey: "my-cronjob",
			},
		},
		{
			name: "ignores unknown owner kind",
			meta: &metav1.ObjectMeta{
				OwnerReferences: []metav1.OwnerReference{
					{
						Kind: "UnknownKind",
						Name: "some-name",
						UID:  "unknown-uid",
					},
				},
			},
			includeUID: false,
			expected:   map[attribute.Key]string{},
		},
		{
			name: "handles multiple owners",
			meta: &metav1.ObjectMeta{
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion: "apps/v1",
						Kind:       "ReplicaSet",
						Name:       "my-deployment-1",
						UID:        "rs-uid-456",
					},
				},
			},
			includeUID: false,
			expected: map[attribute.Key]string{
				semconv.K8SReplicaSetNameKey: "my-deployment-1",
				semconv.K8SDeploymentNameKey: "my-deployment",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm := &PodMutator{}
			resources := map[attribute.Key]string{}
			pm.addParentResourceLabels(tt.meta, resources, tt.includeUID)
			assert.Equal(t, tt.expected, resources)
		})
	}
}

func TestChooseLabelOrAnnotation(t *testing.T) {
	tests := []struct {
		name                           string
		meta                           *metav1.ObjectMeta
		useLabelsForResourceAttributes bool
		resource                       attribute.Key
		labelKeys                      []string
		expected                       string
	}{
		{
			name: "annotation takes precedence over label",
			meta: &metav1.ObjectMeta{
				Annotations: map[string]string{
					ResourceAttributeAnnotationPrefix + "service.name": "annotated-value",
				},
				Labels: map[string]string{
					"app.kubernetes.io/name": "labeled-value",
				},
			},
			useLabelsForResourceAttributes: true,
			resource:                       semconv.ServiceNameKey,
			labelKeys:                      []string{"app.kubernetes.io/name"},
			expected:                       "annotated-value",
		},
		{
			name: "uses label when annotation is missing",
			meta: &metav1.ObjectMeta{
				Labels: map[string]string{
					"app.kubernetes.io/name": "labeled-value",
				},
			},
			useLabelsForResourceAttributes: true,
			resource:                       semconv.ServiceNameKey,
			labelKeys:                      []string{"app.kubernetes.io/name"},
			expected:                       "labeled-value",
		},
		{
			name: "does not use label when disabled",
			meta: &metav1.ObjectMeta{
				Labels: map[string]string{
					"app.kubernetes.io/name": "labeled-value",
				},
			},
			useLabelsForResourceAttributes: false,
			resource:                       semconv.ServiceNameKey,
			labelKeys:                      []string{"app.kubernetes.io/name"},
			expected:                       "",
		},
		{
			name: "tries multiple label keys in order",
			meta: &metav1.ObjectMeta{
				Labels: map[string]string{
					"app.kubernetes.io/instance": "instance-value",
				},
			},
			useLabelsForResourceAttributes: true,
			resource:                       semconv.ServiceNameKey,
			labelKeys:                      []string{"app.kubernetes.io/name", "app.kubernetes.io/instance"},
			expected:                       "instance-value",
		},
		{
			name: "returns first matching label",
			meta: &metav1.ObjectMeta{
				Labels: map[string]string{
					"app.kubernetes.io/name":     "name-value",
					"app.kubernetes.io/instance": "instance-value",
				},
			},
			useLabelsForResourceAttributes: true,
			resource:                       semconv.ServiceNameKey,
			labelKeys:                      []string{"app.kubernetes.io/name", "app.kubernetes.io/instance"},
			expected:                       "name-value",
		},
		{
			name:                           "returns empty when nothing matches",
			meta:                           &metav1.ObjectMeta{},
			useLabelsForResourceAttributes: true,
			resource:                       semconv.ServiceNameKey,
			labelKeys:                      []string{"app.kubernetes.io/name"},
			expected:                       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := chooseLabelOrAnnotation(tt.meta, tt.useLabelsForResourceAttributes, tt.resource, tt.labelKeys)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConfigureContainerEnvVars(t *testing.T) {
	tests := []struct {
		name                   string
		cfg                    *beyla.Config
		meta                   *metav1.ObjectMeta
		container              *corev1.Container
		expectedEnvVarCount    int
		checkEnvVars           map[string]string
		checkEnvVarsContaining map[string][]string // key -> list of substrings to check
	}{
		{
			name: "sets basic resource attributes",
			cfg: &beyla.Config{
				Injector: beyla.SDKInject{
					Resources: beyla.SDKResource{
						Attributes:                     map[string]string{},
						UseLabelsForResourceAttributes: false,
						AddK8sUIDAttributes:            false,
					},
				},
			},
			meta: &metav1.ObjectMeta{
				Name:      "test-pod",
				Namespace: "default",
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion: "apps/v1",
						Kind:       "Deployment",
						Name:       "test-deployment",
					},
				},
			},
			container: &corev1.Container{
				Name:  "test-container",
				Image: "myapp:v1.0.0",
				Env:   []corev1.EnvVar{},
			},
			checkEnvVars: map[string]string{
				envInjectorOtelK8sContainerName: "test-container",
				envInjectorOtelServiceName:      "test-deployment",
				envInjectorOtelServiceVersion:   "v1.0.0",
			},
			checkEnvVarsContaining: map[string][]string{
				envInjectorOtelExtraResourceAttrs: {"k8s.deployment.name=test-deployment"},
			},
		},
		{
			name: "uses labels for resource attributes",
			cfg: &beyla.Config{
				Injector: beyla.SDKInject{
					Resources: beyla.SDKResource{
						Attributes:                     map[string]string{},
						UseLabelsForResourceAttributes: true,
						AddK8sUIDAttributes:            false,
					},
				},
			},
			meta: &metav1.ObjectMeta{
				Name:      "test-pod",
				Namespace: "production",
				Labels: map[string]string{
					"app.kubernetes.io/name":    "my-app",
					"app.kubernetes.io/version": "v2.0.0",
				},
			},
			container: &corev1.Container{
				Name:  "test-container",
				Image: "myapp:v1.0.0",
				Env:   []corev1.EnvVar{},
			},
			checkEnvVars: map[string]string{
				envInjectorOtelK8sContainerName: "test-container",
				envInjectorOtelServiceName:      "my-app",
				envInjectorOtelServiceVersion:   "v2.0.0",
			},
		},
		{
			name: "adds K8s UID attributes when enabled",
			cfg: &beyla.Config{
				Injector: beyla.SDKInject{
					Resources: beyla.SDKResource{
						Attributes:                     map[string]string{},
						UseLabelsForResourceAttributes: false,
						AddK8sUIDAttributes:            true,
					},
				},
			},
			meta: &metav1.ObjectMeta{
				Name:      "test-pod",
				Namespace: "default",
			},
			container: &corev1.Container{
				Name:  "test-container",
				Image: "myapp:v1.0.0",
				Env:   []corev1.EnvVar{},
			},
			checkEnvVars: map[string]string{
				envInjectorOtelK8sContainerName: "test-container",
			},
		},
		{
			name: "includes custom resource attributes from config",
			cfg: &beyla.Config{
				Injector: beyla.SDKInject{
					Resources: beyla.SDKResource{
						Attributes: map[string]string{
							"custom.attr1": "value1",
							"custom.attr2": "value2",
						},
						UseLabelsForResourceAttributes: false,
						AddK8sUIDAttributes:            false,
					},
				},
			},
			meta: &metav1.ObjectMeta{
				Name:      "test-pod",
				Namespace: "default",
			},
			container: &corev1.Container{
				Name:  "test-container",
				Image: "myapp:v1.0.0",
				Env:   []corev1.EnvVar{},
			},
			checkEnvVarsContaining: map[string][]string{
				envInjectorOtelExtraResourceAttrs: {"custom.attr1=value1", "custom.attr2=value2"},
			},
		},
		{
			name: "annotation overrides config attributes",
			cfg: &beyla.Config{
				Injector: beyla.SDKInject{
					Resources: beyla.SDKResource{
						Attributes: map[string]string{
							"service.name": "config-name",
						},
						UseLabelsForResourceAttributes: false,
						AddK8sUIDAttributes:            false,
					},
				},
			},
			meta: &metav1.ObjectMeta{
				Name:      "test-pod",
				Namespace: "default",
				Annotations: map[string]string{
					ResourceAttributeAnnotationPrefix + "service.name": "annotated-name",
				},
			},
			container: &corev1.Container{
				Name:  "test-container",
				Image: "myapp:v1.0.0",
				Env:   []corev1.EnvVar{},
			},
			checkEnvVars: map[string]string{
				envInjectorOtelServiceName: "annotated-name",
			},
			checkEnvVarsContaining: map[string][]string{
				envInjectorOtelExtraResourceAttrs: {"service.name=annotated-name"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm := &PodMutator{cfg: tt.cfg}
			pm.configureContainerEnvVars(tt.meta, tt.container, nil)

			// Check specific environment variables
			for envName, expectedValue := range tt.checkEnvVars {
				found := false
				for _, env := range tt.container.Env {
					if env.Name == envName {
						found = true
						if env.Value != "" {
							assert.Equal(t, expectedValue, env.Value, "env var %s value mismatch", envName)
						}
						// Some env vars use ValueFrom instead of Value
						break
					}
				}
				assert.True(t, found, "expected env var %s not found", envName)
			}

			// Check environment variables containing substrings
			for envName, expectedSubstrings := range tt.checkEnvVarsContaining {
				found := false
				for _, env := range tt.container.Env {
					if env.Name == envName {
						found = true
						for _, substring := range expectedSubstrings {
							assert.Contains(t, env.Value, substring, "env var %s should contain %s", envName, substring)
						}
						break
					}
				}
				assert.True(t, found, "expected env var %s not found", envName)
			}
		})
	}
}

func TestConfigureContainerEnvVars_Propagators(t *testing.T) {
	tests := []struct {
		name            string
		propagators     []string
		expectedEnvVars map[string]string
	}{
		{
			name:        "configures default propagators",
			propagators: []string{"tracecontext", "baggage"},
			expectedEnvVars: map[string]string{
				envOtelPropagatorsName: "tracecontext,baggage",
			},
		},
		{
			name:        "configures multiple propagators including b3 and jaeger",
			propagators: []string{"tracecontext", "baggage", "b3multi", "jaeger", "xray"},
			expectedEnvVars: map[string]string{
				envOtelPropagatorsName: "tracecontext,baggage,b3multi,jaeger,xray",
			},
		},
		{
			name:            "no propagators configured - env var not set",
			propagators:     []string{},
			expectedEnvVars: map[string]string{},
		},
		{
			name:            "nil propagators - env var not set",
			propagators:     nil,
			expectedEnvVars: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &beyla.Config{
				Injector: beyla.SDKInject{
					Propagators: tt.propagators,
					Resources: beyla.SDKResource{
						Attributes:                     map[string]string{},
						UseLabelsForResourceAttributes: false,
						AddK8sUIDAttributes:            false,
					},
				},
			}
			meta := &metav1.ObjectMeta{
				Name:      "test-pod",
				Namespace: "default",
			}
			container := &corev1.Container{
				Name:  "test-container",
				Image: "myapp:v1.0.0",
				Env:   []corev1.EnvVar{},
			}

			pm := &PodMutator{cfg: cfg}
			pm.configureContainerEnvVars(meta, container, nil)

			// Check propagator env vars
			for envName, expectedValue := range tt.expectedEnvVars {
				found := false
				for _, env := range container.Env {
					if env.Name == envName {
						found = true
						assert.Equal(t, expectedValue, env.Value, "env var %s value mismatch", envName)
						break
					}
				}
				assert.True(t, found, "expected env var %s not found", envName)
			}

			// If no propagators, ensure env var is not set
			if len(tt.expectedEnvVars) == 0 {
				for _, env := range container.Env {
					assert.NotEqual(t, envOtelPropagatorsName, env.Name,
						"propagators env var should not be set when propagators list is empty")
				}
			}
		})
	}
}

func TestConfigureContainerEnvVars_SamplerPriority(t *testing.T) {
	tests := []struct {
		name                   string
		defaultSampler         *services.SamplerConfig
		selectorSampler        *services.SamplerConfig
		expectedSamplerEnvVars map[string]string
	}{
		{
			name: "selector sampler takes precedence over default",
			defaultSampler: &services.SamplerConfig{
				Name: "always_on",
				Arg:  "",
			},
			selectorSampler: &services.SamplerConfig{
				Name: "traceidratio",
				Arg:  "0.1",
			},
			expectedSamplerEnvVars: map[string]string{
				envOtelTracesSamplerName:    "traceidratio",
				envOtelTracesSamplerArgName: "0.1",
			},
		},
		{
			name: "uses default sampler when selector has no sampler",
			defaultSampler: &services.SamplerConfig{
				Name: "parentbased_traceidratio",
				Arg:  "0.5",
			},
			selectorSampler: nil,
			expectedSamplerEnvVars: map[string]string{
				envOtelTracesSamplerName:    "parentbased_traceidratio",
				envOtelTracesSamplerArgName: "0.5",
			},
		},
		{
			name:                   "no sampler configured - no env vars set",
			defaultSampler:         nil,
			selectorSampler:        nil,
			expectedSamplerEnvVars: map[string]string{},
		},
		{
			name:           "only selector sampler configured",
			defaultSampler: nil,
			selectorSampler: &services.SamplerConfig{
				Name: "always_off",
				Arg:  "",
			},
			expectedSamplerEnvVars: map[string]string{
				envOtelTracesSamplerName: "always_off",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &beyla.Config{
				Injector: beyla.SDKInject{
					DefaultSampler: tt.defaultSampler,
					Resources: beyla.SDKResource{
						Attributes:                     map[string]string{},
						UseLabelsForResourceAttributes: false,
						AddK8sUIDAttributes:            false,
					},
				},
			}
			meta := &metav1.ObjectMeta{
				Name:      "test-pod",
				Namespace: "default",
			}
			container := &corev1.Container{
				Name:  "test-container",
				Image: "myapp:v1.0.0",
				Env:   []corev1.EnvVar{},
			}

			// Create a mock selector with sampler config if needed
			var selector services.Selector
			if tt.selectorSampler != nil {
				selector = &services.GlobAttributes{
					SamplerConfig: tt.selectorSampler,
				}
			}

			pm := &PodMutator{cfg: cfg}
			pm.configureContainerEnvVars(meta, container, selector)

			// Check sampler env vars
			for envName, expectedValue := range tt.expectedSamplerEnvVars {
				found := false
				for _, env := range container.Env {
					if env.Name == envName {
						found = true
						assert.Equal(t, expectedValue, env.Value, "env var %s value mismatch", envName)
						break
					}
				}
				assert.True(t, found, "expected env var %s not found", envName)
			}

			// If no sampler configured, ensure env vars are not set
			if len(tt.expectedSamplerEnvVars) == 0 {
				for _, env := range container.Env {
					assert.NotEqual(t, envOtelTracesSamplerName, env.Name,
						"sampler name env var should not be set")
					assert.NotEqual(t, envOtelTracesSamplerArgName, env.Name,
						"sampler arg env var should not be set")
				}
			}
		})
	}
}

func TestConfigureContainerEnvVars_SpanMetrics(t *testing.T) {
	tests := []struct {
		name               string
		spanMetricsEnabled bool
		shouldHaveSkipAttr bool
	}{
		{
			name:               "span metrics enabled - adds skip attribute",
			spanMetricsEnabled: true,
			shouldHaveSkipAttr: true,
		},
		{
			name:               "span metrics disabled - no skip attribute",
			spanMetricsEnabled: false,
			shouldHaveSkipAttr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &beyla.Config{
				Metrics: perapp.MetricsConfig{
					Features: 0, // Will be set below
				},
				Injector: beyla.SDKInject{
					Resources: beyla.SDKResource{
						Attributes:                     map[string]string{},
						UseLabelsForResourceAttributes: false,
						AddK8sUIDAttributes:            false,
					},
				},
			}

			if tt.spanMetricsEnabled {
				// Set feature flag for span metrics
				cfg.Metrics.Features = export.FeatureSpanLegacy
			}

			meta := &metav1.ObjectMeta{
				Name:      "test-pod",
				Namespace: "default",
			}
			container := &corev1.Container{
				Name:  "test-container",
				Image: "myapp:v1.0.0",
				Env:   []corev1.EnvVar{},
			}

			pm := &PodMutator{cfg: cfg}
			pm.configureContainerEnvVars(meta, container, nil)

			// Check if skip_span_metrics attribute is present in extra resource attrs
			foundResourceAttrs := false
			hasSkipAttr := false
			for _, env := range container.Env {
				if env.Name == envInjectorOtelExtraResourceAttrs {
					foundResourceAttrs = true
					if tt.shouldHaveSkipAttr {
						assert.Contains(t, env.Value, "span.metrics.skip=true",
							"should contain span.metrics.skip when span metrics enabled")
						hasSkipAttr = true
					} else {
						assert.NotContains(t, env.Value, "span.metrics.skip",
							"should not contain span.metrics.skip when disabled")
					}
					break
				}
			}

			if tt.shouldHaveSkipAttr {
				assert.True(t, foundResourceAttrs && hasSkipAttr,
					"span.metrics.skip attribute should be set when span metrics enabled")
			}
		})
	}
}

func TestConfigureContainerEnvVars_WithExporters(t *testing.T) {
	tests := []struct {
		name                   string
		cfg                    *beyla.Config
		meta                   *metav1.ObjectMeta
		container              *corev1.Container
		selector               services.Selector
		checkEnvVars           map[string]string
		checkEnvVarsContaining map[string][]string
	}{
		{
			name: "selector with only metrics export enabled",
			cfg: &beyla.Config{
				Injector: beyla.SDKInject{
					Resources: beyla.SDKResource{
						Attributes:                     map[string]string{},
						UseLabelsForResourceAttributes: false,
						AddK8sUIDAttributes:            false,
					},
				},
			},
			meta: &metav1.ObjectMeta{
				Name:      "test-pod",
				Namespace: "default",
			},
			container: &corev1.Container{
				Name:  "test-container",
				Image: "myapp:latest",
				Env:   []corev1.EnvVar{},
			},
			selector: createSelectorWithExportModes(true, false), // metrics only
			checkEnvVars: map[string]string{
				envOtelMetricsExporterName: "otlp",
				envOtelTracesExporterName:  "none",
			},
		},
		{
			name: "selector with only traces export enabled",
			cfg: &beyla.Config{
				Injector: beyla.SDKInject{
					Resources: beyla.SDKResource{
						Attributes:                     map[string]string{},
						UseLabelsForResourceAttributes: false,
						AddK8sUIDAttributes:            false,
					},
				},
			},
			meta: &metav1.ObjectMeta{
				Name:      "test-pod",
				Namespace: "default",
			},
			container: &corev1.Container{
				Name:  "test-container",
				Image: "myapp:latest",
				Env:   []corev1.EnvVar{},
			},
			selector: createSelectorWithExportModes(false, true), // traces only
			checkEnvVars: map[string]string{
				envOtelMetricsExporterName: "none",
				envOtelTracesExporterName:  "otlp",
			},
		},
		{
			name: "selector with both exports enabled",
			cfg: &beyla.Config{
				Injector: beyla.SDKInject{
					Resources: beyla.SDKResource{
						Attributes:                     map[string]string{},
						UseLabelsForResourceAttributes: false,
						AddK8sUIDAttributes:            false,
					},
				},
			},
			meta: &metav1.ObjectMeta{
				Name:      "test-pod",
				Namespace: "default",
			},
			container: &corev1.Container{
				Name:  "test-container",
				Image: "myapp:latest",
				Env:   []corev1.EnvVar{},
			},
			selector: createSelectorWithExportModes(true, true), // both enabled
			checkEnvVars: map[string]string{
				envOtelMetricsExporterName: "otlp",
				envOtelTracesExporterName:  "otlp",
			},
		},
		{
			name: "nil selector - no exporter env vars",
			cfg: &beyla.Config{
				Injector: beyla.SDKInject{
					Resources: beyla.SDKResource{
						Attributes:                     map[string]string{},
						UseLabelsForResourceAttributes: false,
						AddK8sUIDAttributes:            false,
					},
				},
			},
			meta: &metav1.ObjectMeta{
				Name:      "test-pod",
				Namespace: "default",
			},
			container: &corev1.Container{
				Name:  "test-container",
				Image: "myapp:latest",
				Env:   []corev1.EnvVar{},
			},
			selector:     nil,
			checkEnvVars: map[string]string{
				// No exporter env vars should be set
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm := &PodMutator{cfg: tt.cfg}
			pm.configureContainerEnvVars(tt.meta, tt.container, tt.selector)

			// Check specific environment variables
			for envName, expectedValue := range tt.checkEnvVars {
				found := false
				for _, env := range tt.container.Env {
					if env.Name == envName {
						found = true
						assert.Equal(t, expectedValue, env.Value, "env var %s value mismatch", envName)
						break
					}
				}
				assert.True(t, found, "expected env var %s not found", envName)
			}

			// Check environment variables containing substrings
			for envName, expectedSubstrings := range tt.checkEnvVarsContaining {
				found := false
				for _, env := range tt.container.Env {
					if env.Name == envName {
						found = true
						for _, substring := range expectedSubstrings {
							assert.Contains(t, env.Value, substring, "env var %s should contain %s", envName, substring)
						}
						break
					}
				}
				assert.True(t, found, "expected env var %s not found", envName)
			}
		})
	}
}

func TestConfigureContainerEnvVars_Integration(t *testing.T) {
	tests := []struct {
		name                   string
		cfg                    *beyla.Config
		meta                   *metav1.ObjectMeta
		container              *corev1.Container
		selector               services.Selector
		checkEnvVars           map[string]string
		checkEnvVarsContaining map[string][]string
		checkEnvVarsNotSet     []string
	}{
		{
			name: "all features enabled - propagators, sampler, span metrics",
			cfg: &beyla.Config{
				Metrics: perapp.MetricsConfig{
					Features: export.FeatureSpanLegacy, // Span metrics enabled
				},
				Injector: beyla.SDKInject{
					Propagators: []string{"tracecontext", "baggage", "b3"},
					DefaultSampler: &services.SamplerConfig{
						Name: "traceidratio",
						Arg:  "0.75",
					},
					Resources: beyla.SDKResource{
						Attributes: map[string]string{
							"environment": "production",
							"region":      "us-west-2",
						},
						UseLabelsForResourceAttributes: true,
						AddK8sUIDAttributes:            true,
					},
				},
			},
			meta: &metav1.ObjectMeta{
				Name:      "test-pod",
				Namespace: "production",
				Labels: map[string]string{
					"app.kubernetes.io/name":    "my-service",
					"app.kubernetes.io/version": "v1.2.3",
				},
				Annotations: map[string]string{
					ResourceAttributeAnnotationPrefix + "custom.annotation": "custom-value",
				},
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion: "apps/v1",
						Kind:       "Deployment",
						Name:       "my-deployment",
						UID:        "deploy-uid-123",
					},
				},
			},
			container: &corev1.Container{
				Name:  "app-container",
				Image: "myapp:v1.2.3",
				Env:   []corev1.EnvVar{},
			},
			selector: nil,
			checkEnvVars: map[string]string{
				envOtelPropagatorsName:          "tracecontext,baggage,b3",
				envOtelTracesSamplerName:        "traceidratio",
				envOtelTracesSamplerArgName:     "0.75",
				envInjectorOtelK8sContainerName: "app-container",
				envInjectorOtelServiceName:      "my-service",
				envInjectorOtelServiceVersion:   "v1.2.3",
			},
			checkEnvVarsContaining: map[string][]string{
				envInjectorOtelExtraResourceAttrs: {
					"environment=production",
					"region=us-west-2",
					"custom.annotation=custom-value",
					"span.metrics.skip=true",
					// Note: when AddK8sUIDAttributes is true, the UID is used instead of the name
					"k8s.deployment.name=deploy-uid-123",
				},
			},
		},
		{
			name: "selector sampler overrides default",
			cfg: &beyla.Config{
				Injector: beyla.SDKInject{
					DefaultSampler: &services.SamplerConfig{
						Name: "always_on",
						Arg:  "",
					},
					Resources: beyla.SDKResource{
						Attributes:                     map[string]string{},
						UseLabelsForResourceAttributes: false,
						AddK8sUIDAttributes:            false,
					},
				},
			},
			meta: &metav1.ObjectMeta{
				Name:      "test-pod",
				Namespace: "default",
			},
			container: &corev1.Container{
				Name:  "test-container",
				Image: "myapp:latest",
				Env:   []corev1.EnvVar{},
			},
			selector: &services.GlobAttributes{
				SamplerConfig: &services.SamplerConfig{
					Name: "parentbased_traceidratio",
					Arg:  "0.01",
				},
			},
			checkEnvVars: map[string]string{
				envOtelTracesSamplerName:    "parentbased_traceidratio",
				envOtelTracesSamplerArgName: "0.01",
			},
		},
		{
			name: "minimal configuration - no optional features",
			cfg: &beyla.Config{
				Injector: beyla.SDKInject{
					Resources: beyla.SDKResource{
						Attributes:                     map[string]string{},
						UseLabelsForResourceAttributes: false,
						AddK8sUIDAttributes:            false,
					},
				},
			},
			meta: &metav1.ObjectMeta{
				Name:      "simple-pod",
				Namespace: "default",
			},
			container: &corev1.Container{
				Name:  "simple-container",
				Image: "simple:latest",
				Env:   []corev1.EnvVar{},
			},
			selector: nil,
			checkEnvVars: map[string]string{
				envInjectorOtelK8sContainerName: "simple-container",
				// Note: service name uses ValueFrom, so it will be $(OTEL_INJECTOR_K8S_POD_NAME)
				envInjectorOtelServiceName: "$(OTEL_INJECTOR_K8S_POD_NAME)",
			},
			checkEnvVarsNotSet: []string{
				envOtelPropagatorsName,
				envOtelTracesSamplerName,
				envOtelTracesSamplerArgName,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm := &PodMutator{cfg: tt.cfg}
			pm.configureContainerEnvVars(tt.meta, tt.container, tt.selector)

			// Check specific environment variables
			for envName, expectedValue := range tt.checkEnvVars {
				found := false
				for _, env := range tt.container.Env {
					if env.Name == envName {
						found = true
						if env.Value != "" {
							assert.Equal(t, expectedValue, env.Value, "env var %s value mismatch", envName)
						}
						break
					}
				}
				assert.True(t, found, "expected env var %s not found", envName)
			}

			// Check environment variables containing substrings
			for envName, expectedSubstrings := range tt.checkEnvVarsContaining {
				found := false
				for _, env := range tt.container.Env {
					if env.Name == envName {
						found = true
						for _, substring := range expectedSubstrings {
							assert.Contains(t, env.Value, substring, "env var %s should contain %s", envName, substring)
						}
						break
					}
				}
				assert.True(t, found, "expected env var %s not found", envName)
			}

			// Check that certain env vars are NOT set
			for _, envName := range tt.checkEnvVarsNotSet {
				for _, env := range tt.container.Env {
					assert.NotEqual(t, envName, env.Name, "env var %s should not be set", envName)
				}
			}
		})
	}
}

func TestConfigureSampler(t *testing.T) {
	tests := []struct {
		name            string
		samplerConfig   *services.SamplerConfig
		expectedEnvVars map[string]string
	}{
		{
			name: "sampler with name and arg",
			samplerConfig: &services.SamplerConfig{
				Name: "traceidratio",
				Arg:  "0.5",
			},
			expectedEnvVars: map[string]string{
				envOtelTracesSamplerName:    "traceidratio",
				envOtelTracesSamplerArgName: "0.5",
			},
		},
		{
			name: "sampler with only name - empty arg not set",
			samplerConfig: &services.SamplerConfig{
				Name: "always_on",
				Arg:  "",
			},
			expectedEnvVars: map[string]string{
				envOtelTracesSamplerName: "always_on",
			},
		},
		{
			name: "sampler with parentbased_always_off",
			samplerConfig: &services.SamplerConfig{
				Name: "parentbased_always_off",
				Arg:  "",
			},
			expectedEnvVars: map[string]string{
				envOtelTracesSamplerName: "parentbased_always_off",
			},
		},
		{
			name: "sampler with traceidratio and low probability",
			samplerConfig: &services.SamplerConfig{
				Name: "traceidratio",
				Arg:  "0.1",
			},
			expectedEnvVars: map[string]string{
				envOtelTracesSamplerName:    "traceidratio",
				envOtelTracesSamplerArgName: "0.1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm := &PodMutator{}
			container := &corev1.Container{
				Name: "test-container",
				Env:  []corev1.EnvVar{},
			}

			pm.configureSampler(container, tt.samplerConfig)

			// Check that expected environment variables are set
			for envName, expectedValue := range tt.expectedEnvVars {
				found := false
				for _, env := range container.Env {
					if env.Name == envName {
						found = true
						assert.Equal(t, expectedValue, env.Value, "env var %s value mismatch", envName)
						break
					}
				}
				assert.True(t, found, "expected env var %s not found", envName)
			}
		})
	}
}

func TestConfigurePropagators(t *testing.T) {
	tests := []struct {
		name            string
		propagators     []string
		expectedEnvVars map[string]string
	}{
		{
			name:        "standard propagators - tracecontext and baggage",
			propagators: []string{"tracecontext", "baggage"},
			expectedEnvVars: map[string]string{
				envOtelPropagatorsName: "tracecontext,baggage",
			},
		},
		{
			name:        "single propagator",
			propagators: []string{"b3"},
			expectedEnvVars: map[string]string{
				envOtelPropagatorsName: "b3",
			},
		},
		{
			name:        "multiple propagators with b3multi and jaeger",
			propagators: []string{"tracecontext", "baggage", "b3multi", "jaeger"},
			expectedEnvVars: map[string]string{
				envOtelPropagatorsName: "tracecontext,baggage,b3multi,jaeger",
			},
		},
		{
			name:            "empty propagators list - no env var set",
			propagators:     []string{},
			expectedEnvVars: map[string]string{},
		},
		{
			name:            "nil propagators - no env var set",
			propagators:     nil,
			expectedEnvVars: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm := &PodMutator{}
			container := &corev1.Container{
				Name: "test-container",
				Env:  []corev1.EnvVar{},
			}

			if len(tt.propagators) > 0 {
				pm.configurePropagators(container, tt.propagators)
			}

			// Check that expected environment variables are set
			for envName, expectedValue := range tt.expectedEnvVars {
				found := false
				for _, env := range container.Env {
					if env.Name == envName {
						found = true
						assert.Equal(t, expectedValue, env.Value, "env var %s value mismatch", envName)
						break
					}
				}
				assert.True(t, found, "expected env var %s not found", envName)
			}

			// If no env vars expected, ensure OTEL_PROPAGATORS is not set
			if len(tt.expectedEnvVars) == 0 {
				for _, env := range container.Env {
					assert.NotEqual(t, envOtelPropagatorsName, env.Name,
						"OTEL_PROPAGATORS should not be set for empty/nil propagators")
				}
			}
		})
	}
}

// createExportModes creates ExportModes programmatically for testing
func createExportModes(metrics, traces bool) services.ExportModes {
	modes := services.NewExportModes()
	if metrics {
		modes.AllowMetrics()
	}
	if traces {
		modes.AllowTraces()
	}
	return modes
}

// createSelectorWithExportModes creates a selector with specific export modes for testing
func createSelectorWithExportModes(metrics, traces bool) *services.GlobAttributes {
	return &services.GlobAttributes{
		ExportModes: createExportModes(metrics, traces),
	}
}

func TestConfigureExporters(t *testing.T) {
	tests := []struct {
		name            string
		exportModes     services.ExportModes
		logsEnabled     bool
		expectedEnvVars map[string]string
	}{
		{
			name:        "both metrics and traces enabled, logs disabled",
			exportModes: createExportModes(true, true),
			logsEnabled: false,
			expectedEnvVars: map[string]string{
				envOtelMetricsExporterName: "otlp",
				envOtelTracesExporterName:  "otlp",
				envOtelLogsExporterName:    "none",
			},
		},
		{
			name:        "only metrics enabled, logs disabled",
			exportModes: createExportModes(true, false),
			logsEnabled: false,
			expectedEnvVars: map[string]string{
				envOtelMetricsExporterName: "otlp",
				envOtelTracesExporterName:  "none",
				envOtelLogsExporterName:    "none",
			},
		},
		{
			name:        "only traces enabled, logs disabled",
			exportModes: createExportModes(false, true),
			logsEnabled: false,
			expectedEnvVars: map[string]string{
				envOtelMetricsExporterName: "none",
				envOtelTracesExporterName:  "otlp",
				envOtelLogsExporterName:    "none",
			},
		},
		{
			name:        "all disabled",
			exportModes: createExportModes(false, false),
			logsEnabled: false,
			expectedEnvVars: map[string]string{
				envOtelMetricsExporterName: "none",
				envOtelTracesExporterName:  "none",
				envOtelLogsExporterName:    "none",
			},
		},
		{
			name:        "unset export modes, logs enabled",
			exportModes: services.ExportModeUnset,
			logsEnabled: true,
			expectedEnvVars: map[string]string{
				envOtelMetricsExporterName: "otlp",
				envOtelTracesExporterName:  "otlp",
				envOtelLogsExporterName:    "otlp",
			},
		},
		{
			name:        "only logs enabled",
			exportModes: createExportModes(false, false),
			logsEnabled: true,
			expectedEnvVars: map[string]string{
				envOtelMetricsExporterName: "none",
				envOtelTracesExporterName:  "none",
				envOtelLogsExporterName:    "otlp",
			},
		},
		{
			name:        "all signals enabled",
			exportModes: createExportModes(true, true),
			logsEnabled: true,
			expectedEnvVars: map[string]string{
				envOtelMetricsExporterName: "otlp",
				envOtelTracesExporterName:  "otlp",
				envOtelLogsExporterName:    "otlp",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm := &PodMutator{}
			container := &corev1.Container{
				Name: "test-container",
				Env:  []corev1.EnvVar{},
			}

			pm.configureExporters(container, tt.exportModes, tt.logsEnabled)

			// Check that expected environment variables are set
			for envName, expectedValue := range tt.expectedEnvVars {
				found := false
				for _, env := range container.Env {
					if env.Name == envName {
						found = true
						assert.Equal(t, expectedValue, env.Value, "env var %s value mismatch", envName)
						break
					}
				}
				assert.True(t, found, "expected env var %s not found", envName)
			}
		})
	}
}

func TestConfigureExporters_OverridesExistingVars(t *testing.T) {
	pm := &PodMutator{}
	container := &corev1.Container{
		Name: "test-container",
		Env: []corev1.EnvVar{
			{Name: envOtelMetricsExporterName, Value: "prometheus"},
			{Name: envOtelTracesExporterName, Value: "jaeger"},
			{Name: envOtelLogsExporterName, Value: "stdout"},
		},
	}

	exportModes := createExportModes(true, true)
	logsEnabled := true

	pm.configureExporters(container, exportModes, logsEnabled)

	// Verify existing values ARE overridden by the export modes configuration
	// Note: setEnvVar will override existing values with export mode-based config
	for _, env := range container.Env {
		if env.Name == envOtelMetricsExporterName {
			assert.Equal(t, "otlp", env.Value, "metrics exporter should be overridden based on export modes")
		}
		if env.Name == envOtelTracesExporterName {
			assert.Equal(t, "otlp", env.Value, "traces exporter should be overridden based on export modes")
		}
		if env.Name == envOtelLogsExporterName {
			assert.Equal(t, "otlp", env.Value, "logs exporter should be overridden to otlp")
		}
	}
}

func TestConfigureContainerEnvVars_SDKExportConfig(t *testing.T) {
	trueVal := true
	falseVal := false

	tests := []struct {
		name         string
		sdkExport    beyla.SDKExport
		selector     services.Selector
		checkEnvVars map[string]string
	}{
		{
			name: "SDK export defaults (traces/metrics enabled, logs disabled)",
			sdkExport: beyla.SDKExport{
				// nil values default to enabled for traces/metrics, disabled for logs
			},
			selector: nil,
			checkEnvVars: map[string]string{
				envOtelMetricsExporterName: "otlp",
				envOtelTracesExporterName:  "otlp",
				envOtelLogsExporterName:    "none",
			},
		},
		{
			name: "SDK export: only traces enabled",
			sdkExport: beyla.SDKExport{
				Traces:  &trueVal,
				Metrics: &falseVal,
				Logs:    &falseVal,
			},
			selector: nil,
			checkEnvVars: map[string]string{
				envOtelMetricsExporterName: "none",
				envOtelTracesExporterName:  "otlp",
				envOtelLogsExporterName:    "none",
			},
		},
		{
			name: "SDK export: only metrics enabled",
			sdkExport: beyla.SDKExport{
				Traces:  &falseVal,
				Metrics: &trueVal,
				Logs:    &falseVal,
			},
			selector: nil,
			checkEnvVars: map[string]string{
				envOtelMetricsExporterName: "otlp",
				envOtelTracesExporterName:  "none",
				envOtelLogsExporterName:    "none",
			},
		},
		{
			name: "SDK export: all disabled",
			sdkExport: beyla.SDKExport{
				Traces:  &falseVal,
				Metrics: &falseVal,
				Logs:    &falseVal,
			},
			selector: nil,
			checkEnvVars: map[string]string{
				envOtelMetricsExporterName: "none",
				envOtelTracesExporterName:  "none",
				envOtelLogsExporterName:    "none",
			},
		},
		{
			name: "SDK export: all enabled",
			sdkExport: beyla.SDKExport{
				Traces:  &trueVal,
				Metrics: &trueVal,
				Logs:    &trueVal,
			},
			selector: nil,
			checkEnvVars: map[string]string{
				envOtelMetricsExporterName: "otlp",
				envOtelTracesExporterName:  "otlp",
				envOtelLogsExporterName:    "otlp",
			},
		},
		{
			name: "SDK export disabled, but selector overrides (logs stay disabled)",
			sdkExport: beyla.SDKExport{
				Traces:  &falseVal,
				Metrics: &falseVal,
				Logs:    &falseVal,
			},
			selector: createSelectorWithExportModes(true, true),
			checkEnvVars: map[string]string{
				envOtelMetricsExporterName: "otlp",
				envOtelTracesExporterName:  "otlp",
				envOtelLogsExporterName:    "none", // logs not overridden by selector
			},
		},
		{
			name: "SDK export enabled, but selector overrides to partial",
			sdkExport: beyla.SDKExport{
				Traces:  &trueVal,
				Metrics: &trueVal,
				Logs:    &trueVal,
			},
			selector: createSelectorWithExportModes(false, true), // only traces
			checkEnvVars: map[string]string{
				envOtelMetricsExporterName: "none",
				envOtelTracesExporterName:  "otlp",
				envOtelLogsExporterName:    "otlp", // logs not affected by selector override
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &beyla.Config{
				Injector: beyla.SDKInject{
					Export: tt.sdkExport,
					Resources: beyla.SDKResource{
						Attributes:                     map[string]string{},
						UseLabelsForResourceAttributes: false,
						AddK8sUIDAttributes:            false,
					},
				},
			}
			meta := &metav1.ObjectMeta{
				Name:      "test-pod",
				Namespace: "default",
			}
			container := &corev1.Container{
				Name:  "test-container",
				Image: "myapp:latest",
				Env:   []corev1.EnvVar{},
			}

			pm := &PodMutator{cfg: cfg}
			pm.configureContainerEnvVars(meta, container, tt.selector)

			// Check specific environment variables
			for envName, expectedValue := range tt.checkEnvVars {
				found := false
				for _, env := range container.Env {
					if env.Name == envName {
						found = true
						assert.Equal(t, expectedValue, env.Value, "env var %s value mismatch", envName)
						break
					}
				}
				assert.True(t, found, "expected env var %s not found", envName)
			}
		})
	}
}
