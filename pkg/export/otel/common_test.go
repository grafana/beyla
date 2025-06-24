package otel

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolveOTLPEndpoint(t *testing.T) {
	grafana1 := GrafanaOTLP{
		CloudZone: "foo",
	}

	const grafanaEndpoint = "https://otlp-gateway-foo.grafana.net/otlp"

	grafana2 := GrafanaOTLP{}

	type expected struct {
		e      string
		common bool
	}

	type testCase struct {
		endpoint string
		common   string
		grafana  *GrafanaOTLP
		expected expected
	}

	testCases := []testCase{
		{endpoint: "e1", common: "c1", grafana: nil, expected: expected{e: "e1", common: false}},
		{endpoint: "e1", common: "", grafana: nil, expected: expected{e: "e1", common: false}},
		{endpoint: "", common: "c1", grafana: nil, expected: expected{e: "c1", common: true}},
		{endpoint: "", common: "", grafana: nil, expected: expected{e: "", common: false}},
		{endpoint: "e1", common: "c1", grafana: &grafana1, expected: expected{e: "e1", common: false}},
		{endpoint: "", common: "c1", grafana: &grafana1, expected: expected{e: "c1", common: true}},
		{endpoint: "", common: "", grafana: &grafana1, expected: expected{e: grafanaEndpoint, common: true}},
		{endpoint: "", common: "", grafana: &grafana2, expected: expected{e: "", common: false}},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprint(tc), func(t *testing.T) {
			ep, common := ResolveOTLPEndpoint(tc.endpoint, tc.common, tc.grafana)

			assert.Equal(t, ep, tc.expected.e)
			assert.Equal(t, common, tc.expected.common)
		})
	}
}
