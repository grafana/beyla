package meta

import (
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestEnvironmentFiltering(t *testing.T) {
	vars := []v1.EnvVar{{Name: "A", Value: "B"}, {Value: "C"}, {}, {Name: "OTEL_SERVICE_NAME", Value: "service_name"}, {Name: "OTEL_RESOURCE_ATTRIBUTES", Value: "resource_attributes"}}

	filtered := envToMap(nil, metav1.ObjectMeta{}, vars)
	assert.Equal(t, 2, len(filtered))

	serviceName, ok := filtered["OTEL_SERVICE_NAME"]
	assert.True(t, ok)
	assert.Equal(t, "service_name", serviceName)

	resourceAttrs, ok := filtered["OTEL_RESOURCE_ATTRIBUTES"]
	assert.True(t, ok)
	assert.Equal(t, "resource_attributes", resourceAttrs)
}
