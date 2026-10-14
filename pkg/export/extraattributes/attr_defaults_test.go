package extraattributes

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

var appMetricSections = []attributes.Name{
	attributes.HTTPServerDuration,
	attributes.HTTPClientDuration,
	attributes.RPCServerDuration,
	attributes.RPCClientDuration,
}

// service.name and service.namespace are always reported as OTEL resource
// attributes (and joinable via target_info in Prometheus). Some Grafana Cloud
// apps however, read service identity directly off the metric series,
// so Beyla additionally wants these two attributes reported at the metric-attribute
// level by default, unless overridden by the users.
// This test configuration mimics the default Beyla behavior (defaulting ExtraGroupAttributesCfg to app)
func TestServiceNameAndNamespace_DefaultOnAppMetrics_BeylaOverride(t *testing.T) {
	for _, section := range appMetricSections {
		t.Run(string(section.Section), func(t *testing.T) {
			p, err := attributes.NewAttrSelector(0, &attributes.SelectorConfig{
				ExtraGroupAttributesCfg: map[string][]attr.Name{
					"app": {attr.ServiceName, attr.ServiceNamespace},
				},
			})
			require.NoError(t, err)

			got := p.For(section)
			assert.Contains(t, got, attr.ServiceName)
			assert.Contains(t, got, attr.ServiceNamespace)
		})
	}
}

// similar test scenario to TestServiceNameAndNamespace_DefaultOnAppMetrics_BeylaOverride
// but not providing any app extra attribute (default OBI configuration) so we
// expect that service name and namespace are not reported
func TestServiceNameAndNamespace_DefaultOnAppMetrics(t *testing.T) {
	for _, section := range appMetricSections {
		t.Run(string(section.Section), func(t *testing.T) {
			p, err := attributes.NewAttrSelector(0, &attributes.SelectorConfig{})
			require.NoError(t, err)

			got := p.For(section)
			assert.NotContains(t, got, attr.ServiceName)
			assert.NotContains(t, got, attr.ServiceNamespace)
		})
	}
}
