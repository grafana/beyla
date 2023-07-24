package cluster

import (
	"path"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOrderManifests(t *testing.T) {
	tc := NewKind("foo", ".",
		Deploy(Deployment{Order: Preconditions, ManifestFile: "pods.yml"}),
		Deploy(Deployment{Order: ExternalServices, ManifestFile: "sql"}),
		Override(OtelcolSetup, Deployment{Order: ExternalServices, ManifestFile: "otelcol"}))

	// verify that deployments are overridden and/or inserted in proper order, this is
	// 1st criteria: Order (in descending order)
	// 2nd criteria: DeploymentID (for override) or Manifest File (for non-overriding deployments),
	//               in alphabetical order
	require.Equal(t, []Deployment{
		// 3 - pods.yml
		{Order: Preconditions, ManifestFile: "pods.yml"},
		// 3 - /Users/..../01-volumes.yml
		{Order: Preconditions, ManifestFile: path.Join(packageDir(), "base", "01-volumes.yml")},
		// 2 - jaeger
		{Order: ExternalServices, ManifestFile: path.Join(packageDir(), "base", "04-jaeger.yml")},
		// 2 - otelcol
		{Order: ExternalServices, ManifestFile: "otelcol"},
		// 2 - prometheus
		{Order: ExternalServices, ManifestFile: path.Join(packageDir(), "base", "02-prometheus.yml")},
		// 2 - sql
		{Order: ExternalServices, ManifestFile: "sql"},
		// 1 - autoinstrument
		{Order: Autoinstrument, ManifestFile: path.Join(packageDir(), "base", "05-instrumented-service.yml")},
	}, tc.orderedManifests())
}
