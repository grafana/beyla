package beyla

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/transform"
)

func TestNameResolverConfigConversion(t *testing.T) {
	defer unsetOBIEnv(t)
	cfg, err := LoadConfig(strings.NewReader(`
trace_printer: text
discovery:
  instrument:
    - open_ports: 8080
name_resolver:
  sources: [gce, azure]
  cache_len: 2048
  cache_expiry: 2m
  gce:
    project_id: test-project
    zone: europe-west3-a
    endpoint: http://compute-mock:8080
  azure:
    subscription_id: test-subscription
    resource_group: test-group
`))
	require.NoError(t, err)
	require.NoError(t, cfg.Validate())
	want := &transform.NameResolverConfig{
		Sources:  []transform.Source{transform.SourceGCE, transform.SourceAzure},
		CacheLen: 2048,
		CacheTTL: 2 * time.Minute,
		GCE: transform.GCENameResolverConfig{
			ProjectID: "test-project",
			Zone:      "europe-west3-a",
			Endpoint:  "http://compute-mock:8080",
		},
		Azure: transform.AzureNameResolverConfig{
			SubscriptionID: "test-subscription",
			ResourceGroup:  "test-group",
		},
	}
	assert.Equal(t, want, cfg.AsOBI().NameResolver)
	restored := FromOBI(cfg.AsOBI())
	assert.Equal(t, cfg.NameResolver, restored.NameResolver)
	assert.Equal(t, want, restored.AsOBI().NameResolver)
}

func TestNameResolverEnvironmentOverrides(t *testing.T) {
	t.Setenv("BEYLA_NAME_RESOLVER_SOURCES", "gce,azure")
	t.Setenv("BEYLA_NAME_RESOLVER_CACHE_LEN", "4096")
	t.Setenv("BEYLA_NAME_RESOLVER_CACHE_TTL", "3m")
	t.Setenv("BEYLA_NAME_RESOLVER_GCE_PROJECT_ID", "env-project")
	t.Setenv("BEYLA_NAME_RESOLVER_GCE_ZONE", "env-zone")
	t.Setenv("BEYLA_NAME_RESOLVER_GCE_ENDPOINT", "http://env-compute:8080")
	t.Setenv("BEYLA_NAME_RESOLVER_AZURE_SUBSCRIPTION_ID", "env-subscription")
	t.Setenv("BEYLA_NAME_RESOLVER_AZURE_RESOURCE_GROUP", "env-group")
	defer unsetOBIEnv(t)
	cfg, err := LoadConfig(strings.NewReader(`
name_resolver:
  sources: [dns]
  gce:
    project_id: yaml-project
    zone: yaml-zone
    endpoint: http://yaml-compute:8080
  azure:
    subscription_id: yaml-subscription
    resource_group: yaml-group
`))
	require.NoError(t, err)
	got := cfg.AsOBI().NameResolver
	assert.Equal(t, []transform.Source{transform.SourceGCE, transform.SourceAzure}, got.Sources)
	assert.Equal(t, 4096, got.CacheLen)
	assert.Equal(t, 3*time.Minute, got.CacheTTL)
	assert.Equal(t, transform.GCENameResolverConfig{
		ProjectID: "env-project", Zone: "env-zone", Endpoint: "http://env-compute:8080",
	}, got.GCE)
	assert.Equal(t, transform.AzureNameResolverConfig{
		SubscriptionID: "env-subscription", ResourceGroup: "env-group",
	}, got.Azure)
}

func TestNameResolverDefaults(t *testing.T) {
	defer unsetOBIEnv(t)
	cfg, err := LoadConfig(strings.NewReader("name_resolver:\n  sources: [gce, azure]\n"))
	require.NoError(t, err)
	got := cfg.AsOBI().NameResolver
	assert.Equal(t, []transform.Source{transform.SourceGCE, transform.SourceAzure}, got.Sources)
	assert.Equal(t, obi.DefaultConfig.NameResolver.CacheLen, got.CacheLen)
	assert.Equal(t, obi.DefaultConfig.NameResolver.CacheTTL, got.CacheTTL)
	assert.Empty(t, got.GCE)
	assert.Empty(t, got.Azure)
}

func TestResolverIntegrationConfigs(t *testing.T) {
	for _, provider := range []string{"gce", "azure"} {
		for _, detected := range []bool{false, true} {
			name := provider + "/explicit"
			if detected {
				name = provider + "/detected"
			}
			t.Run(name, func(t *testing.T) {
				project, zone, subscription, group := "test-project", "test-zone", "test-subscription", "test-group"
				if detected {
					project, zone, subscription, group = "", "", "", ""
				}
				t.Setenv("GCE_TEST_PROJECT_ID", project)
				t.Setenv("GCE_TEST_ZONE", zone)
				t.Setenv("GCE_TEST_ENDPOINT", "http://compute-mock:8080")
				t.Setenv("AZURE_TEST_SUBSCRIPTION_ID", subscription)
				t.Setenv("AZURE_TEST_RESOURCE_GROUP", group)
				defer unsetOBIEnv(t)
				file, err := os.Open("../../internal/test/beyla_extensions/configs/obi-config-" + provider + ".yml")
				require.NoError(t, err)
				defer file.Close()
				cfg, err := LoadConfig(file)
				require.NoError(t, err)
				require.NoError(t, cfg.Validate())
				converted := cfg.AsOBI()
				assert.Equal(t, []transform.Source{transform.Source(provider)}, converted.NameResolver.Sources)
				if provider == "gce" {
					assert.Equal(t, transform.GCENameResolverConfig{
						ProjectID: project, Zone: zone, Endpoint: "http://compute-mock:8080",
					}, converted.NameResolver.GCE)
				} else {
					assert.Equal(t, transform.AzureNameResolverConfig{
						SubscriptionID: subscription, ResourceGroup: group,
					}, converted.NameResolver.Azure)
				}
				assert.Equal(t, "custom-exported-host", cfg.Attributes.HostID.Override)
				assert.Equal(t, time.Second, cfg.CloudMetadata.RefreshInterval)
				require.Len(t, cfg.Discovery.Instrument, 1)
				assert.True(t, cfg.Discovery.Instrument[0].OpenPorts.Matches(8080))
			})
		}
	}
}
