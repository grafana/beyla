package webhook

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"

	"github.com/grafana/beyla/v2/pkg/beyla"
)

func TestErrorResponse(t *testing.T) {
	tests := []struct {
		name     string
		message  string
		expected string
	}{
		{
			name:     "simple error message",
			message:  "something went wrong",
			expected: "something went wrong",
		},
		{
			name:     "empty message",
			message:  "",
			expected: "",
		},
		{
			name:     "long error message",
			message:  "this is a very long error message that describes what went wrong in great detail",
			expected: "this is a very long error message that describes what went wrong in great detail",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			admResponse := &admissionv1.AdmissionResponse{
				Allowed: true, // Start as allowed
			}

			errorResponse(admResponse, tt.message)

			assert.False(t, admResponse.Allowed)
			assert.NotNil(t, admResponse.Result)
			assert.Equal(t, tt.expected, admResponse.Result.Message)
		})
	}
}

func TestPodMutator_CanInstrument(t *testing.T) {
	mutator := &PodMutator{}

	tests := []struct {
		name     string
		kind     svc.InstrumentableType
		expected bool
	}{
		{
			name:     "Java is supported",
			kind:     svc.InstrumentableJava,
			expected: true,
		},
		{
			name:     "Dotnet is supported",
			kind:     svc.InstrumentableDotnet,
			expected: true,
		},
		{
			name:     "NodeJS is supported",
			kind:     svc.InstrumentableNodejs,
			expected: true,
		},
		{
			name:     "Go is not supported",
			kind:     svc.InstrumentableGolang,
			expected: false,
		},
		{
			name:     "Python is not supported",
			kind:     svc.InstrumentablePython,
			expected: false,
		},
		{
			name:     "Ruby is not supported",
			kind:     svc.InstrumentableRuby,
			expected: false,
		},
		{
			name:     "Generic is not supported",
			kind:     svc.InstrumentableGeneric,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mutator.CanInstrument(tt.kind)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPodMutator_PreloadsSomethingElse(t *testing.T) {
	mutator := &PodMutator{}

	tests := []struct {
		name     string
		info     *ProcessInfo
		expected bool
	}{
		{
			name: "no LD_PRELOAD set",
			info: &ProcessInfo{
				env: map[string]string{},
			},
			expected: false,
		},
		{
			name: "LD_PRELOAD set to our injector",
			info: &ProcessInfo{
				env: map[string]string{
					envVarLdPreloadName: envVarLdPreloadValue,
				},
			},
			expected: false,
		},
		{
			name: "LD_PRELOAD set to something else",
			info: &ProcessInfo{
				env: map[string]string{
					envVarLdPreloadName: "/some/other/library.so",
				},
			},
			expected: true,
		},
		{
			name: "LD_PRELOAD set to multiple libraries",
			info: &ProcessInfo{
				env: map[string]string{
					envVarLdPreloadName: "/lib1.so:/lib2.so",
				},
			},
			expected: true,
		},
		{
			name: "LD_PRELOAD empty string",
			info: &ProcessInfo{
				env: map[string]string{
					envVarLdPreloadName: "",
				},
			},
			expected: true,
		},
		{
			name: "nil env map",
			info: &ProcessInfo{
				env: nil,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mutator.PreloadsSomethingElse(tt.info)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPodMutator_AlreadyInstrumented(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *beyla.Config
		info     *ProcessInfo
		expected bool
	}{
		{
			name: "not instrumented - no labels or env",
			cfg: &beyla.Config{
				Injector: beyla.SDKInject{
					SDKPkgVersion: "v0.0.3",
				},
			},
			info: &ProcessInfo{
				podLabels: map[string]string{},
				env:       map[string]string{},
			},
			expected: false,
		},
		{
			name: "instrumented - matching label version",
			cfg: &beyla.Config{
				Injector: beyla.SDKInject{
					SDKPkgVersion: "v0.0.3",
				},
			},
			info: &ProcessInfo{
				podLabels: map[string]string{
					instrumentedLabel: "v0.0.3",
				},
				env: map[string]string{},
			},
			expected: true,
		},
		{
			name: "not instrumented - different label version",
			cfg: &beyla.Config{
				Injector: beyla.SDKInject{
					SDKPkgVersion: "v0.0.3",
				},
			},
			info: &ProcessInfo{
				podLabels: map[string]string{
					instrumentedLabel: "v0.0.2",
				},
				env: map[string]string{},
			},
			expected: false,
		},
		{
			name: "instrumented - matching env var version",
			cfg: &beyla.Config{
				Injector: beyla.SDKInject{
					SDKPkgVersion: "v0.0.3",
				},
			},
			info: &ProcessInfo{
				podLabels: map[string]string{},
				env: map[string]string{
					envVarSDKVersion: "v0.0.3",
				},
			},
			expected: true,
		},
		{
			name: "not instrumented - different env var version",
			cfg: &beyla.Config{
				Injector: beyla.SDKInject{
					SDKPkgVersion: "v0.0.3",
				},
			},
			info: &ProcessInfo{
				podLabels: map[string]string{},
				env: map[string]string{
					envVarSDKVersion: "v0.0.2",
				},
			},
			expected: false,
		},
		{
			name: "instrumented - label takes precedence",
			cfg: &beyla.Config{
				Injector: beyla.SDKInject{
					SDKPkgVersion: "v0.0.3",
				},
			},
			info: &ProcessInfo{
				podLabels: map[string]string{
					instrumentedLabel: "v0.0.3",
				},
				env: map[string]string{
					envVarSDKVersion: "v0.0.2", // different version in env
				},
			},
			expected: true,
		},
		{
			name: "not instrumented - empty label value",
			cfg: &beyla.Config{
				Injector: beyla.SDKInject{
					SDKPkgVersion: "v0.0.3",
				},
			},
			info: &ProcessInfo{
				podLabels: map[string]string{
					instrumentedLabel: "",
				},
				env: map[string]string{},
			},
			expected: false,
		},
		{
			name: "not instrumented - empty env var value",
			cfg: &beyla.Config{
				Injector: beyla.SDKInject{
					SDKPkgVersion: "v0.0.3",
				},
			},
			info: &ProcessInfo{
				podLabels: map[string]string{},
				env: map[string]string{
					envVarSDKVersion: "",
				},
			},
			expected: false,
		},
		{
			name: "not instrumented - nil maps",
			cfg: &beyla.Config{
				Injector: beyla.SDKInject{
					SDKPkgVersion: "v0.0.3",
				},
			},
			info: &ProcessInfo{
				podLabels: nil,
				env:       nil,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mutator := &PodMutator{
				cfg: tt.cfg,
			}
			result := mutator.AlreadyInstrumented(tt.info)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPodMutator_MutatePod(t *testing.T) {
	tests := []struct {
		name           string
		cfg            *beyla.Config
		matcher        *PodMatcher
		pod            *corev1.Pod
		expectModified bool
		expectLabel    bool
		expectVolume   bool
		expectEnvVars  bool
	}{
		{
			name: "successful mutation - single container",
			cfg: &beyla.Config{
				Injector: beyla.SDKInject{
					SDKPkgVersion:     "v0.0.3",
					HostPathVolumeDir: "/var/lib/beyla/instrumentation",
				},
				Traces: otelcfg.TracesConfig{
					CommonEndpoint: "http://localhost:4318",
				},
			},
			matcher: &PodMatcher{
				logger: slog.With("component", "webhook.Matcher"),
				selectors: []services.Selector{
					&services.GlobAttributes{
						Metadata: map[string]*services.GlobAttr{
							"k8s_namespace": strToGlob("*"),
						},
					},
				},
			},
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "default",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "app"},
					},
				},
			},
			expectModified: true,
			expectLabel:    true,
			expectVolume:   true,
			expectEnvVars:  true,
		},
		{
			name: "already instrumented - skip mutation",
			cfg: &beyla.Config{
				Injector: beyla.SDKInject{
					SDKPkgVersion:     "v0.0.3",
					HostPathVolumeDir: "/var/lib/beyla/instrumentation",
				},
			},
			matcher: &PodMatcher{
				selectors: []services.Selector{
					&services.GlobAttributes{
						Metadata: map[string]*services.GlobAttr{
							"k8s_namespace": strToGlob("*"),
						},
					},
				},
				logger: slog.With("component", "webhook.Matcher"),
			},
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "default",
					Labels: map[string]string{
						instrumentedLabel: "v0.0.3",
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "app"},
					},
				},
			},
			expectModified: false,
			expectLabel:    false,
			expectVolume:   false,
			expectEnvVars:  false,
		},
		{
			name: "doesn't match selection - skip mutation",
			cfg: &beyla.Config{
				Injector: beyla.SDKInject{
					SDKPkgVersion:     "v0.0.3",
					HostPathVolumeDir: "/var/lib/beyla/instrumentation",
				},
			},
			matcher: &PodMatcher{
				logger: slog.With("component", "webhook.Matcher"),
				selectors: []services.Selector{
					&services.GlobAttributes{
						Metadata: map[string]*services.GlobAttr{
							"k8s_namespace": strToGlob("production"),
						},
					},
				},
			},
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "default", // doesn't match production
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "app"},
					},
				},
			},
			expectModified: false,
			expectLabel:    false,
			expectVolume:   false,
			expectEnvVars:  false,
		},
		{
			name: "successful mutation - multiple containers",
			cfg: &beyla.Config{
				Injector: beyla.SDKInject{
					SDKPkgVersion:     "v0.0.3",
					HostPathVolumeDir: "/var/lib/beyla/instrumentation",
				},
				Traces: otelcfg.TracesConfig{
					CommonEndpoint: "http://localhost:4318",
				},
			},
			matcher: &PodMatcher{
				logger: slog.With("component", "webhook.Matcher"),
				selectors: []services.Selector{
					&services.GlobAttributes{
						Metadata: map[string]*services.GlobAttr{
							"k8s_namespace": strToGlob("*"),
						},
					},
				},
			},
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "default",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "app1"},
						{Name: "app2"},
						{Name: "app3"},
					},
				},
			},
			expectModified: true,
			expectLabel:    true,
			expectVolume:   true,
			expectEnvVars:  true,
		},
		{
			name: "skip container with existing LD_PRELOAD",
			cfg: &beyla.Config{
				Injector: beyla.SDKInject{
					SDKPkgVersion:     "v0.0.3",
					HostPathVolumeDir: "/var/lib/beyla/instrumentation",
				},
				Traces: otelcfg.TracesConfig{
					CommonEndpoint: "http://localhost:4318",
				},
			},
			matcher: &PodMatcher{
				logger: slog.With("component", "webhook.Matcher"),
				selectors: []services.Selector{
					&services.GlobAttributes{
						Metadata: map[string]*services.GlobAttr{
							"k8s_namespace": strToGlob("*"),
						},
					},
				},
			},
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "default",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name: "app-with-preload",
							Env: []corev1.EnvVar{
								{Name: envVarLdPreloadName, Value: "/some/other/lib.so"},
							},
						},
						{Name: "app-without-preload"},
					},
				},
			},
			expectModified: true,
			expectLabel:    true,
			expectVolume:   true,
			expectEnvVars:  true, // at least one container should be instrumented
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mutator := &PodMutator{
				logger:   slog.With("component", "webhook.Mutator"),
				cfg:      tt.cfg,
				matcher:  tt.matcher,
				endpoint: "http://localhost:4318",
				proto:    "http/protobuf",
			}

			modified := mutator.mutatePod(tt.pod)

			assert.Equal(t, tt.expectModified, modified, "mutation result mismatch")

			if tt.expectLabel {
				label, ok := tt.pod.Labels[instrumentedLabel]
				assert.True(t, ok, "instrumented label should be present")
				assert.Equal(t, tt.cfg.Injector.SDKPkgVersion, label)
			}

			if tt.expectVolume {
				found := false
				for _, vol := range tt.pod.Spec.Volumes {
					if vol.Name == injectVolumeName {
						found = true
						assert.NotNil(t, vol.HostPath)
						assert.Equal(t, tt.cfg.Injector.HostPathVolumeDir+"/"+tt.cfg.Injector.SDKPkgVersion, vol.HostPath.Path)
						break
					}
				}
				assert.True(t, found, "inject volume should be present")
			}

			if tt.expectEnvVars {
				// Check at least one container has instrumentation env vars
				foundInstrumented := false
				for _, c := range tt.pod.Spec.Containers {
					hasLdPreload := false
					hasConfigFile := false
					for _, env := range c.Env {
						if env.Name == envVarLdPreloadName && env.Value == envVarLdPreloadValue {
							hasLdPreload = true
						}
						if env.Name == envOtelInjectorConfigFileName {
							hasConfigFile = true
						}
					}
					if hasLdPreload && hasConfigFile {
						foundInstrumented = true
						break
					}
				}
				assert.True(t, foundInstrumented, "at least one container should be instrumented")
			}
		})
	}
}

func TestPodMutator_AddLabel(t *testing.T) {
	tests := []struct {
		name     string
		meta     *metav1.ObjectMeta
		key      string
		value    string
		expected map[string]string
	}{
		{
			name:  "add label to empty labels",
			meta:  &metav1.ObjectMeta{},
			key:   "test-key",
			value: "test-value",
			expected: map[string]string{
				"test-key": "test-value",
			},
		},
		{
			name: "add label to existing labels",
			meta: &metav1.ObjectMeta{
				Labels: map[string]string{
					"existing": "label",
				},
			},
			key:   "new-key",
			value: "new-value",
			expected: map[string]string{
				"existing": "label",
				"new-key":  "new-value",
			},
		},
		{
			name: "overwrite existing label",
			meta: &metav1.ObjectMeta{
				Labels: map[string]string{
					"test-key": "old-value",
				},
			},
			key:   "test-key",
			value: "new-value",
			expected: map[string]string{
				"test-key": "new-value",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mutator := &PodMutator{}
			mutator.addLabel(tt.meta, tt.key, tt.value)
			assert.Equal(t, tt.expected, tt.meta.Labels)
		})
	}
}

func TestPodMutator_GetLabel(t *testing.T) {
	tests := []struct {
		name          string
		meta          *metav1.ObjectMeta
		key           string
		expectedValue string
		expectedOk    bool
	}{
		{
			name: "get existing label",
			meta: &metav1.ObjectMeta{
				Labels: map[string]string{
					"test-key": "test-value",
				},
			},
			key:           "test-key",
			expectedValue: "test-value",
			expectedOk:    true,
		},
		{
			name: "get non-existent label",
			meta: &metav1.ObjectMeta{
				Labels: map[string]string{
					"other-key": "other-value",
				},
			},
			key:           "test-key",
			expectedValue: "",
			expectedOk:    false,
		},
		{
			name:          "get label from nil labels",
			meta:          &metav1.ObjectMeta{},
			key:           "test-key",
			expectedValue: "",
			expectedOk:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mutator := &PodMutator{}
			value, ok := mutator.getLabel(tt.meta, tt.key)
			assert.Equal(t, tt.expectedValue, value)
			assert.Equal(t, tt.expectedOk, ok)
		})
	}
}

func TestFindEnvVar(t *testing.T) {
	tests := []struct {
		name        string
		container   *corev1.Container
		envName     string
		expectedPos int
		expectedOk  bool
	}{
		{
			name: "find existing env var at position 0",
			container: &corev1.Container{
				Env: []corev1.EnvVar{
					{Name: "TEST_VAR", Value: "test-value"},
					{Name: "OTHER_VAR", Value: "other-value"},
				},
			},
			envName:     "TEST_VAR",
			expectedPos: 0,
			expectedOk:  true,
		},
		{
			name: "find existing env var at position 1",
			container: &corev1.Container{
				Env: []corev1.EnvVar{
					{Name: "OTHER_VAR", Value: "other-value"},
					{Name: "TEST_VAR", Value: "test-value"},
				},
			},
			envName:     "TEST_VAR",
			expectedPos: 1,
			expectedOk:  true,
		},
		{
			name: "env var not found",
			container: &corev1.Container{
				Env: []corev1.EnvVar{
					{Name: "OTHER_VAR", Value: "other-value"},
				},
			},
			envName:     "TEST_VAR",
			expectedPos: -1,
			expectedOk:  false,
		},
		{
			name:        "empty env list",
			container:   &corev1.Container{},
			envName:     "TEST_VAR",
			expectedPos: -1,
			expectedOk:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pos, ok := findEnvVar(tt.container, tt.envName)
			assert.Equal(t, tt.expectedPos, pos)
			assert.Equal(t, tt.expectedOk, ok)
		})
	}
}

func TestSetEnvVar(t *testing.T) {
	tests := []struct {
		name        string
		container   *corev1.Container
		envVarName  string
		value       string
		expectedEnv []corev1.EnvVar
	}{
		{
			name:       "add new env var to empty list",
			container:  &corev1.Container{},
			envVarName: "TEST_VAR",
			value:      "test-value",
			expectedEnv: []corev1.EnvVar{
				{Name: "TEST_VAR", Value: "test-value"},
			},
		},
		{
			name: "add new env var to existing list",
			container: &corev1.Container{
				Env: []corev1.EnvVar{
					{Name: "EXISTING", Value: "existing-value"},
				},
			},
			envVarName: "TEST_VAR",
			value:      "test-value",
			expectedEnv: []corev1.EnvVar{
				{Name: "EXISTING", Value: "existing-value"},
				{Name: "TEST_VAR", Value: "test-value"},
			},
		},
		{
			name: "overwrite existing env var",
			container: &corev1.Container{
				Env: []corev1.EnvVar{
					{Name: "TEST_VAR", Value: "old-value"},
				},
			},
			envVarName: "TEST_VAR",
			value:      "new-value",
			expectedEnv: []corev1.EnvVar{
				{Name: "TEST_VAR", Value: "new-value"},
			},
		},
		{
			name: "overwrite env var with ValueFrom",
			container: &corev1.Container{
				Env: []corev1.EnvVar{
					{
						Name: "TEST_VAR",
						ValueFrom: &corev1.EnvVarSource{
							FieldRef: &corev1.ObjectFieldSelector{
								FieldPath: "metadata.name",
							},
						},
					},
				},
			},
			envVarName: "TEST_VAR",
			value:      "new-value",
			expectedEnv: []corev1.EnvVar{
				{Name: "TEST_VAR", Value: "new-value", ValueFrom: nil},
			},
		},
		{
			name: "don't add env var with empty value",
			container: &corev1.Container{
				Env: []corev1.EnvVar{
					{Name: "EXISTING", Value: "existing-value"},
				},
			},
			envVarName: "TEST_VAR",
			value:      "",
			expectedEnv: []corev1.EnvVar{
				{Name: "EXISTING", Value: "existing-value"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setEnvVar(tt.container, tt.envVarName, tt.value)
			assert.Equal(t, tt.expectedEnv, tt.container.Env)
		})
	}
}

func TestPodMutator_AddEnvVars(t *testing.T) {
	tests := []struct {
		name             string
		meta             *metav1.ObjectMeta
		container        *corev1.Container
		cfg              *beyla.Config
		endpoint         string
		proto            string
		exportHeaders    map[string]string
		expectedEnvCount int
		checkEnvVars     map[string]string
	}{
		{
			name: "add basic env vars",
			meta: &metav1.ObjectMeta{
				Name:      "test-pod",
				Namespace: "default",
			},
			container: &corev1.Container{
				Name: "test-container",
			},
			cfg: &beyla.Config{
				Injector: beyla.SDKInject{
					SDKPkgVersion: "v0.0.3",
				},
			},
			endpoint:      "http://localhost:4318",
			proto:         "http/protobuf",
			exportHeaders: map[string]string{},
			checkEnvVars: map[string]string{
				envVarSDKVersion:                "v0.0.3",
				envVarLdPreloadName:             envVarLdPreloadValue,
				envOtelInjectorConfigFileName:   envOtelInjectorConfigFileValue,
				envOtelExporterOtlpEndpointName: "http://localhost:4318",
				envOtelExporterOtlpProtocolName: "http/protobuf",
				envOtelSemConvStabilityName:     "http",
			},
		},
		{
			name: "add env vars with export headers",
			meta: &metav1.ObjectMeta{
				Name:      "test-pod",
				Namespace: "default",
			},
			container: &corev1.Container{
				Name: "test-container",
			},
			cfg: &beyla.Config{
				Injector: beyla.SDKInject{
					SDKPkgVersion: "v0.0.4",
				},
			},
			endpoint: "http://localhost:4318",
			proto:    "grpc",
			exportHeaders: map[string]string{
				"OTEL_EXPORTER_OTLP_HEADERS": "Authorization=Bearer token",
			},
			checkEnvVars: map[string]string{
				envVarSDKVersion:                "v0.0.4",
				envVarLdPreloadName:             envVarLdPreloadValue,
				envOtelExporterOtlpEndpointName: "http://localhost:4318",
				envOtelExporterOtlpProtocolName: "grpc",
				"OTEL_EXPORTER_OTLP_HEADERS":    "Authorization=Bearer token",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mutator := &PodMutator{
				logger:        slog.With("component", "webhook.test"),
				cfg:           tt.cfg,
				endpoint:      tt.endpoint,
				proto:         tt.proto,
				exportHeaders: tt.exportHeaders,
			}

			mutator.addEnvVars(tt.meta, tt.container, nil)

			// Check that expected env vars are present
			for key, expectedValue := range tt.checkEnvVars {
				found := false
				for _, env := range tt.container.Env {
					if env.Name == key {
						found = true
						assert.Equal(t, expectedValue, env.Value, "env var %s has wrong value", key)
						break
					}
				}
				assert.True(t, found, "env var %s not found", key)
			}
		})
	}
}

func TestOwnersFrom(t *testing.T) {
	tests := []struct {
		name        string
		meta        *metav1.ObjectMeta
		expected    int
		checkOwners func(t *testing.T, owners []*informer.Owner)
	}{
		{
			name: "no owner references",
			meta: &metav1.ObjectMeta{
				Name: "test-pod",
			},
			expected: 1,
			checkOwners: func(t *testing.T, owners []*informer.Owner) {
				assert.Equal(t, "Pod", owners[0].Kind)
				assert.Equal(t, "test-pod", owners[0].Name)
			},
		},
		{
			name: "single owner reference",
			meta: &metav1.ObjectMeta{
				Name: "test-pod",
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion: "apps/v1",
						Kind:       "StatefulSet",
						Name:       "test-statefulset",
					},
				},
			},
			expected: 1,
			checkOwners: func(t *testing.T, owners []*informer.Owner) {
				assert.Equal(t, "StatefulSet", owners[0].Kind)
				assert.Equal(t, "test-statefulset", owners[0].Name)
			},
		},
		{
			name: "replicaset owner extracts deployment",
			meta: &metav1.ObjectMeta{
				Name: "test-pod",
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion: "apps/v1",
						Kind:       "ReplicaSet",
						Name:       "my-deployment-abc123",
					},
				},
			},
			expected: 2,
			checkOwners: func(t *testing.T, owners []*informer.Owner) {
				assert.Equal(t, "ReplicaSet", owners[0].Kind)
				assert.Equal(t, "my-deployment-abc123", owners[0].Name)
				assert.Equal(t, "Deployment", owners[1].Kind)
				assert.Equal(t, "my-deployment", owners[1].Name)
			},
		},
		{
			name: "job owner extracts cronjob",
			meta: &metav1.ObjectMeta{
				Name: "test-pod",
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion: "batch/v1",
						Kind:       "Job",
						Name:       "my-cronjob-1234567890",
					},
				},
			},
			expected: 2,
			checkOwners: func(t *testing.T, owners []*informer.Owner) {
				assert.Equal(t, "Job", owners[0].Kind)
				assert.Equal(t, "my-cronjob-1234567890", owners[0].Name)
				assert.Equal(t, "CronJob", owners[1].Kind)
				assert.Equal(t, "my-cronjob", owners[1].Name)
			},
		},
		{
			name: "multiple owner references",
			meta: &metav1.ObjectMeta{
				Name: "test-pod",
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion: "apps/v1",
						Kind:       "DaemonSet",
						Name:       "my-daemonset",
					},
					{
						APIVersion: "v1",
						Kind:       "Node",
						Name:       "my-node",
					},
				},
			},
			expected: 2,
			checkOwners: func(t *testing.T, owners []*informer.Owner) {
				assert.Equal(t, "DaemonSet", owners[0].Kind)
				assert.Equal(t, "my-daemonset", owners[0].Name)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owners := ownersFrom(tt.meta)
			assert.Len(t, owners, tt.expected)
			if tt.checkOwners != nil {
				tt.checkOwners(t, owners)
			}
		})
	}
}

func TestProcessMetadata(t *testing.T) {
	tests := []struct {
		name             string
		meta             *metav1.ObjectMeta
		checkMetadata    map[string]string
		checkLabels      map[string]string
		checkAnnotations map[string]string
	}{
		{
			name: "simple pod metadata",
			meta: &metav1.ObjectMeta{
				Name:      "test-pod",
				Namespace: "default",
				Labels: map[string]string{
					"app": "test-app",
				},
				Annotations: map[string]string{
					"annotation": "value",
				},
			},
			checkMetadata: map[string]string{
				services.AttrNamespace: "default",
				services.AttrPodName:   "test-pod",
				services.AttrOwnerName: "test-pod",
			},
			checkLabels: map[string]string{
				"app": "test-app",
			},
			checkAnnotations: map[string]string{
				"annotation": "value",
			},
		},
		{
			name: "pod with replicaset owner",
			meta: &metav1.ObjectMeta{
				Name:      "test-pod-abc",
				Namespace: "production",
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion: "apps/v1",
						Kind:       "ReplicaSet",
						Name:       "my-deployment-xyz123",
					},
				},
			},
			checkMetadata: map[string]string{
				services.AttrNamespace: "production",
				services.AttrPodName:   "test-pod-abc",
				services.AttrOwnerName: "my-deployment",
			},
		},
		{
			name: "pod with job owner",
			meta: &metav1.ObjectMeta{
				Name:      "test-pod-xyz",
				Namespace: "batch-jobs",
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion: "batch/v1",
						Kind:       "Job",
						Name:       "my-cronjob-1234567890",
					},
				},
			},
			checkMetadata: map[string]string{
				services.AttrNamespace: "batch-jobs",
				services.AttrPodName:   "test-pod-xyz",
				services.AttrOwnerName: "my-cronjob",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := processMetadata(tt.meta)

			assert.NotNil(t, info)

			if tt.checkMetadata != nil {
				for key, expected := range tt.checkMetadata {
					actual, ok := info.metadata[key]
					assert.True(t, ok, "metadata key %s not found", key)
					assert.Equal(t, expected, actual, "metadata key %s has wrong value", key)
				}
			}

			if tt.checkLabels != nil {
				assert.Equal(t, tt.checkLabels, info.podLabels)
			}

			if tt.checkAnnotations != nil {
				assert.Equal(t, tt.checkAnnotations, info.podAnnotations)
			}
		})
	}
}

func TestEnabledSDKs(t *testing.T) {
	tests := []struct {
		name         string
		disabledSDKs []string
		expected     map[svc.InstrumentableType]any
	}{
		{
			name:         "no SDKs disabled - all enabled by default",
			disabledSDKs: []string{},
			expected: map[svc.InstrumentableType]any{
				svc.InstrumentableJava:   true,
				svc.InstrumentableDotnet: true,
				svc.InstrumentableNodejs: true,
			},
		},
		{
			name:         "disable Java SDK",
			disabledSDKs: []string{"java"},
			expected: map[svc.InstrumentableType]any{
				svc.InstrumentableDotnet: true,
				svc.InstrumentableNodejs: true,
			},
		},
		{
			name:         "disable Dotnet SDK",
			disabledSDKs: []string{"dotnet"},
			expected: map[svc.InstrumentableType]any{
				svc.InstrumentableJava:   true,
				svc.InstrumentableNodejs: true,
			},
		},
		{
			name:         "disable NodeJS SDK",
			disabledSDKs: []string{"nodejs"},
			expected: map[svc.InstrumentableType]any{
				svc.InstrumentableJava:   true,
				svc.InstrumentableDotnet: true,
			},
		},
		{
			name:         "disable multiple SDKs",
			disabledSDKs: []string{"java", "nodejs"},
			expected: map[svc.InstrumentableType]any{
				svc.InstrumentableDotnet: true,
			},
		},
		{
			name:         "disable all SDKs",
			disabledSDKs: []string{"java", "dotnet", "nodejs"},
			expected:     map[svc.InstrumentableType]any{},
		},
		{
			name:         "case insensitive - uppercase",
			disabledSDKs: []string{"JAVA", "DOTNET"},
			expected: map[svc.InstrumentableType]any{
				svc.InstrumentableNodejs: true,
			},
		},
		{
			name:         "case insensitive - mixed case",
			disabledSDKs: []string{"Java", "NodeJS"},
			expected: map[svc.InstrumentableType]any{
				svc.InstrumentableDotnet: true,
			},
		},
		{
			name:         "unknown SDK language - ignored",
			disabledSDKs: []string{"python", "go"},
			expected: map[svc.InstrumentableType]any{
				svc.InstrumentableJava:   true,
				svc.InstrumentableDotnet: true,
				svc.InstrumentableNodejs: true,
			},
		},
		{
			name:         "mixed valid and invalid SDKs",
			disabledSDKs: []string{"java", "python", "nodejs", "ruby"},
			expected: map[svc.InstrumentableType]any{
				svc.InstrumentableDotnet: true,
			},
		},
		{
			name:         "duplicate disabled SDKs",
			disabledSDKs: []string{"java", "java", "dotnet"},
			expected: map[svc.InstrumentableType]any{
				svc.InstrumentableNodejs: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &beyla.Config{
				Injector: beyla.SDKInject{
					DisabledSDKs: tt.disabledSDKs,
				},
			}
			log := slog.Default()

			result := enabledSDKs(cfg, log)

			assert.Equal(t, len(tt.expected), len(result), "number of enabled SDKs doesn't match")
			for expectedType := range tt.expected {
				_, exists := result[expectedType]
				assert.True(t, exists, "expected SDK %s to be enabled", expectedType)
			}

			// Check that disabled SDKs are not in the result
			allSupportedSDKs := []svc.InstrumentableType{
				svc.InstrumentableJava,
				svc.InstrumentableDotnet,
				svc.InstrumentableNodejs,
			}
			for _, sdkType := range allSupportedSDKs {
				_, shouldExist := tt.expected[sdkType]
				_, exists := result[sdkType]
				assert.Equal(t, shouldExist, exists, "SDK %s existence mismatch", sdkType)
			}
		})
	}
}
