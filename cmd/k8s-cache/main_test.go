package main

import (
	"testing"

	"go.opentelemetry.io/obi/pkg/kube/kubecache"

	"github.com/grafana/beyla/v3/cmd/k8s-cache/cfg"
	configutil "github.com/grafana/beyla/v3/pkg/helpers/config"
)

func TestCacheConfigConvertsTLS(t *testing.T) {
	t.Run("disabled by default", func(t *testing.T) {
		obiConfig := &kubecache.Config{}
		configutil.Convert(cfg.DefaultConfig, obiConfig, map[string]string{})
		if obiConfig.TLS != (kubecache.TLSConfig{}) {
			t.Fatalf("expected TLS to remain disabled by default, got %+v", obiConfig.TLS)
		}
	})

	t.Run("configured TLS fields are preserved", func(t *testing.T) {
		cacheConfig := cfg.DefaultConfig
		cacheConfig.TLS = cfg.TLSConfig{
			CertFile:     "/certs/server.crt",
			KeyFile:      "/certs/server.key",
			ClientCAFile: "/certs/client-ca.crt",
		}

		obiConfig := &kubecache.Config{}
		configutil.Convert(cacheConfig, obiConfig, map[string]string{})
		want := kubecache.TLSConfig{
			CertFile:     "/certs/server.crt",
			KeyFile:      "/certs/server.key",
			ClientCAFile: "/certs/client-ca.crt",
		}
		if obiConfig.TLS != want {
			t.Fatalf("unexpected converted TLS config: got %+v, want %+v", obiConfig.TLS, want)
		}
	})
}
