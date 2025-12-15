package components

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/transform"

	"github.com/grafana/beyla/v2/pkg/beyla"
)

func TestServiceNameTemplate(t *testing.T) {

	cfg := &beyla.Config{
		Attributes: beyla.Attributes{
			Kubernetes: transform.KubernetesDecorator{
				ServiceNameTemplate: "{{asdf}}",
			},
		},
	}

	temp, err := buildServiceNameTemplate(cfg)

	assert.Nil(t, temp)
	if assert.Error(t, err) {
		assert.Equal(t, `unable to parse service name template: template: serviceNameTemplate:1: function "asdf" not defined`, err.Error())
	}

	cfg.Attributes.Kubernetes.ServiceNameTemplate = `{{- if eq .Meta.Pod nil }}{{.Meta.Name}}{{ else }}{{- .Meta.Namespace }}/{{ index .Meta.Labels "app.kubernetes.io/name" }}/{{ index .Meta.Labels "app.kubernetes.io/component" -}}{{ if .ContainerName }}/{{ .ContainerName -}}{{ end -}}{{ end -}}`
	temp, err = buildServiceNameTemplate(cfg)

	assert.NoError(t, err)
	assert.NotNil(t, temp)

	cfg.Attributes.Kubernetes.ServiceNameTemplate = ""
	temp, err = buildServiceNameTemplate(cfg)

	assert.Nil(t, temp)
	assert.Nil(t, err)
}
