// Copyright Grafana Labs
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/services"

	"github.com/grafana/beyla/v3/pkg/beyla"
)

func TestSurveySchemaIncludesNestedGlobAttributes(t *testing.T) {
	g := NewSchemaGenerator()
	g.inlineFields["SurveySelector"] = []string{"GlobAttributes"}
	g.inlineFields["GlobAttributes"] = []string{"MetadataGlobMap"}
	reflector := &jsonschema.Reflector{
		FieldNameTag: "yaml", RequiredFromJSONSchemaTags: true,
		AllowAdditionalProperties: true, ExpandedStruct: true,
		Mapper: g.customMapper(),
	}
	schema := reflector.Reflect(&beyla.Config{})
	g.processInlineFields(schema)

	survey, ok := schema.Definitions["SurveySelector"]
	require.True(t, ok)
	for _, field := range []string{"exe_path", "cmd_args", "open_ports", "k8s_pod_labels", "socket_apps"} {
		_, ok := survey.Properties.Get(field)
		assert.True(t, ok, "survey schema must include %s", field)
	}
	for field := range services.AllowedAttributeNames {
		_, ok := survey.Properties.Get(field)
		assert.True(t, ok, "survey schema must include metadata field %s", field)
	}
	_, ok = schema.Definitions["GlobAttributes"].Properties.Get("socket_apps")
	assert.False(t, ok, "socket_apps must remain survey-only")
	_, ok = schema.Definitions["BeylaDiscoveryConfig"].Properties.Get("socket_apps")
	assert.False(t, ok, "socket_apps must not be a global discovery option")
}
