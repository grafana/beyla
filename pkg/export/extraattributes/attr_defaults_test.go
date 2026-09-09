package extraattributes

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

// service.name and service.namespace are always reported as OTEL resource
// attributes (and joinable via target_info in Prometheus). Some Grafana Cloud
// apps however, read service identity directly off the metric series,
// so Beyla additionally wants these two attributes reported at the metric-attribute
// level by default, unless overridden by the users.
func TestServiceNameAndNamespace_DefaultOnAppMetrics(t *testing.T) {
	for _, section := range []attributes.Name{
		attributes.HTTPServerDuration,
		attributes.HTTPClientDuration,
		attributes.RPCServerDuration,
		attributes.RPCClientDuration,
	} {
		t.Run(string(section.Section), func(t *testing.T) {
			p, err := attributes.NewAttrSelector(0, &attributes.SelectorConfig{})
			require.NoError(t, err)

			got := p.For(section)
			assert.Contains(t, got, attr.ServiceName,
				"service.name should be reported by default on metric attributes, in addition to resource attributes")
			assert.Contains(t, got, attr.ServiceNamespace,
				"service.namespace should be reported by default on metric attributes, in addition to resource attributes")
		})
	}
}
