package kube

import (
	"bytes"
	"context"
	"testing"
	"text/template"

	"github.com/stretchr/testify/require"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
)

// Template allows creating and deploying a K8s manifest from a Go template
type Template[T any] struct {
	TemplateFile string
	Data         T

	compiledManifest string
}

func (tm *Template[T]) Deploy() features.Func {
	return func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
		tmpl, err := template.ParseFiles(tm.TemplateFile)
		require.NoError(t, err)
		compiled := &bytes.Buffer{}
		require.NoError(t, tmpl.Execute(compiled, tm.Data))
		tm.compiledManifest = compiled.String()

		require.NoError(t, deployManifest(cfg, tm.compiledManifest))
		return ctx
	}
}

func (tm *Template[T]) Delete() features.Func {
	return func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
		require.NoError(t, deleteManifest(cfg, tm.compiledManifest))
		return ctx
	}
}
