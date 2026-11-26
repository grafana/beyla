package cfg

import (
	"strings"
	"testing"
)

func TestLoadConfigTLS(t *testing.T) {
	t.Run("yaml", func(t *testing.T) {
		got, err := LoadConfig(strings.NewReader("tls:\n  cert_file: /certs/server.crt\n  key_file: /certs/server.key\n  client_ca_file: /certs/client-ca.crt\n"))
		if err != nil {
			t.Fatal(err)
		}
		want := TLSConfig{
			CertFile:     "/certs/server.crt",
			KeyFile:      "/certs/server.key",
			ClientCAFile: "/certs/client-ca.crt",
		}
		if got.TLS != want {
			t.Fatalf("unexpected TLS config: got %+v, want %+v", got.TLS, want)
		}
	})

	t.Run("environment", func(t *testing.T) {
		t.Setenv("BEYLA_K8S_CACHE_TLS_CERT_FILE", "/certs/server.crt")
		t.Setenv("BEYLA_K8S_CACHE_TLS_KEY_FILE", "/certs/server.key")
		t.Setenv("BEYLA_K8S_CACHE_TLS_CLIENT_CA_FILE", "/certs/client-ca.crt")

		got, err := LoadConfig(nil)
		if err != nil {
			t.Fatal(err)
		}
		want := TLSConfig{
			CertFile:     "/certs/server.crt",
			KeyFile:      "/certs/server.key",
			ClientCAFile: "/certs/client-ca.crt",
		}
		if got.TLS != want {
			t.Fatalf("unexpected TLS config: got %+v, want %+v", got.TLS, want)
		}
	})
}
