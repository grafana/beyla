package meta

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestSetEnvFromConfigMap(t *testing.T) {
	inputs := []struct {
		name      string
		configMap *corev1.ConfigMap
		result    string
		key       string
		err       error
		hasError  bool
	}{
		{
			name: "lowercase map",
			configMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "testconfigmap"},
				Data: map[string]string{
					"env":          "prod",
					"test-key":     "testValue",
					"test-key-two": "testValueTwo",
				},
			},
			key:      "test-key",
			result:   "testValue",
			err:      nil,
			hasError: false,
		},
		{
			name: "uppercase map",
			configMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "testconfigmapuppercasekey"},
				Data: map[string]string{
					"ENV":          "prod",
					"TEST_KEY":     "testValue",
					"TEST_KEY_TWO": "testValueTwo",
				},
			},
			key:      "TEST_KEY",
			result:   "testValue",
			err:      nil,
			hasError: false,
		},
		{
			name: "key not exists",
			configMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "testconfigmapuppercasekey"},
				Data: map[string]string{
					"ENV":          "prod",
					"TEST_KEY":     "testValue",
					"TEST_KEY_TWO": "testValueTwo",
				},
			},
			key:      "TEST_KEY_NOT_EXISTS",
			result:   "",
			err:      nil,
			hasError: true,
		},
		{
			name: "uppercase map with error",
			configMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "testconfigmapuppercasekey"},
				Data: map[string]string{
					"ENV":          "prod",
					"TEST_KEY":     "testValue",
					"TEST_KEY_TWO": "testValueTwo",
				},
			},
			key:      "TEST_KEY",
			result:   "",
			err:      fmt.Errorf("Whatever"),
			hasError: true,
		},
	}

	for _, i := range inputs {
		t.Run(i.name, func(t *testing.T) {
			v, err := extractConfigMapRefValue(i.configMap, i.err, &corev1.ConfigMapKeySelector{Key: i.key})
			assert.Equal(t, i.hasError, err != nil)
			assert.Equal(t, i.result, v)
		})
	}
}

func TestSetEnvFromSecret(t *testing.T) {
	inputs := []struct {
		name      string
		configMap *corev1.Secret
		result    string
		key       string
		err       error
		hasError  bool
	}{
		{
			name: "lowercase map",
			configMap: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "testsecret"},
				Data: map[string][]byte{
					"env":          []byte("prod"),
					"test-key":     []byte("testValue"),
					"test-key-two": []byte("testValueTwo"),
				},
			},
			key:      "test-key",
			result:   "testValue",
			err:      nil,
			hasError: false,
		},
		{
			name: "uppercase map",
			configMap: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "testsecretuppercasekey"},
				Data: map[string][]byte{
					"ENV":          []byte("prod"),
					"TEST_KEY":     []byte("testValue"),
					"TEST_KEY_TWO": []byte("testValueTwo"),
				},
			},
			key:      "TEST_KEY",
			result:   "testValue",
			err:      nil,
			hasError: false,
		},
		{
			name: "key not exists",
			configMap: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "testsecretuppercasekey"},
				Data: map[string][]byte{
					"ENV":          []byte("prod"),
					"TEST_KEY":     []byte("testValue"),
					"TEST_KEY_TWO": []byte("testValueTwo"),
				},
			},
			key:      "TEST_KEY_NOT_EXISTS",
			result:   "",
			err:      nil,
			hasError: true,
		},
		{
			name: "uppercase map with error",
			configMap: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "testsecretuppercasekey"},
				Data: map[string][]byte{
					"ENV":          []byte("prod"),
					"TEST_KEY":     []byte("testValue"),
					"TEST_KEY_TWO": []byte("testValueTwo"),
				},
			},
			key:      "TEST_KEY",
			result:   "",
			err:      fmt.Errorf("Whatever"),
			hasError: true,
		},
	}

	for _, i := range inputs {
		t.Run(i.name, func(t *testing.T) {
			v, err := extractSecretRefValue(i.configMap, i.err, &corev1.SecretKeySelector{Key: i.key})
			assert.Equal(t, i.hasError, err != nil)
			assert.Equal(t, i.result, v)
		})
	}
}

func TestFieldRef(t *testing.T) {
	source := corev1.EnvVarSource{
		FieldRef: &corev1.ObjectFieldSelector{
			FieldPath: "metadata.labels['app.kubernetes.io/component']",
		},
	}

	obj := metav1.ObjectMeta{
		Labels: map[string]string{
			"opentelemetry.io/name":       "opentelemetry-demo-kafka",
			"app.kubernetes.io/instance":  "opentelemetry-demo",
			"app.kubernetes.io/component": "kafka",
			"app.kubernetes.io/name":      "opentelemetry-demo-kafka",
		},
	}

	v, err := getFieldRef(obj, &source)
	assert.NoError(t, err)
	assert.Equal(t, "kafka", v)
}
