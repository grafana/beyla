package pipe

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	obicfg "go.opentelemetry.io/obi/pkg/config"
)

func TestHostnameResolver(t *testing.T) {
	failed := errors.New("hostname unavailable")
	for _, tc := range []struct {
		name        string
		override    string
		dns         bool
		short       string
		internal    string
		internalErr error
		fqdn        string
		fqdnErr     error
		want        string
	}{
		{name: "override", override: "configured.example.com", want: "configured.example.com"},
		{name: "override with DNS", override: "configured.example.com", dns: true, want: "configured.example.com"},
		{name: "localhost override", override: "localhost", want: "localhost"},
		{name: "internal", short: "node", internal: "node.example.com", want: "node.example.com"},
		{name: "DNS", dns: true, short: "node", fqdn: "node.example.com", want: "node.example.com"},
		{name: "DNS failure", dns: true, short: "node", fqdnErr: failed, internal: "node.internal", want: "node.internal"},
		{name: "DNS localhost", dns: true, short: "node", fqdn: "localhost", internal: "node.internal", want: "node.internal"},
		{name: "internal failure", short: "node", internalErr: failed, want: "node"},
		{name: "all lookups fail", dns: true, short: "node", fqdnErr: failed, internalErr: failed, want: "node"},
		{name: "internal localhost", short: "node", internal: "ip6-localhost", want: "node"},
		{name: "only localhost", short: "localhost", internal: "ipv6-loopback"},
		{name: "no hostname", internalErr: failed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolver := hostnameResolver{
				short: func() (string, error) {
					require.Empty(t, tc.override)
					return tc.short, nil
				},
				internal: func() (string, error) { return tc.internal, tc.internalErr },
				fqdn: func(short string) (string, error) {
					require.True(t, tc.dns)
					assert.Equal(t, tc.short, short)
					return tc.fqdn, tc.fqdnErr
				},
			}
			assert.Equal(t, tc.want, resolver.resolve(&obicfg.InstanceIDConfig{
				OverrideHostname: tc.override, HostnameDNSResolution: tc.dns,
			}))
		})
	}
}

func TestInternalHostname(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux hostname command fallback")
	}
	for _, tc := range []struct {
		name    string
		script  string
		want    string
		wantErr bool
	}{
		{name: "FQDN", script: "echo node.example.com", want: "node.example.com"},
		{name: "short fallback", script: "if [ \"$1\" = '-f' ]; then exit 1; fi\necho node", want: "node"},
		{name: "failed commands", script: "echo failure >&2\nexit 1", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, "hostname"), []byte("#!/bin/sh\n"+tc.script+"\n"), 0o755))
			t.Setenv("PATH", dir)
			got, err := internalHostname()
			assert.Equal(t, tc.want, got)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
