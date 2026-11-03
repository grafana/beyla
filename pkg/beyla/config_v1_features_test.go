package beyla

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/plog"

	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/metadata/peer"
	"go.opentelemetry.io/obi/pkg/obi"
)

func TestV1PeerMetadataConfig(t *testing.T) {
	defer unsetOBIEnv(t)
	cfg, err := LoadConfig(strings.NewReader(`
trace_printer: text
discovery:
  instrument:
    - open_ports: 8080
peer_metadata:
  enabled: true
  mode: peer
  listen_address: 127.0.0.1
  port: 9000
  peer_cidrs: ["10.0.0.0/8"]
  refresh_interval: 1s
  caller_ttl: 6s
  cache_ttl: 7s
  request_timeout: 3s
  max_peers: 10
  max_concurrent: 2
  max_caller_entries: 100
  max_response_bytes: 2048
  max_cache_bytes: 4096
  token: secret
  tls:
    enabled: true
    cert_file: /cert
    key_file: /key
    ca_file: /ca
    server_name: peer.internal
`))
	require.NoError(t, err)
	require.NoError(t, cfg.Validate())

	want := peer.MetadataConfig{
		Enabled:          true,
		Mode:             peer.ModePeer,
		ListenAddress:    "127.0.0.1",
		Port:             9000,
		PeerCIDRs:        []string{"10.0.0.0/8"},
		RefreshInterval:  time.Second,
		CallerTTL:        6 * time.Second,
		CacheTTL:         7 * time.Second,
		RequestTimeout:   3 * time.Second,
		MaxPeers:         10,
		MaxConcurrent:    2,
		MaxCallerEntries: 100,
		MaxResponseBytes: 2048,
		MaxCacheBytes:    4096,
		Token:            "secret",
		TLS: peer.MetadataTLSConfig{
			Enabled:    true,
			CertFile:   "/cert",
			KeyFile:    "/key",
			CAFile:     "/ca",
			ServerName: "peer.internal",
		},
	}
	assert.Equal(t, want, cfg.AsOBI().PeerMetadata)
	restored := FromOBI(cfg.AsOBI())
	assert.Equal(t, cfg.PeerMetadata, restored.PeerMetadata)
	assert.Equal(t, want, restored.AsOBI().PeerMetadata)
}

func TestV1PeerMetadataEnvironmentOverrides(t *testing.T) {
	t.Setenv("BEYLA_PEER_METADATA_ENABLED", "true")
	t.Setenv("BEYLA_PEER_METADATA_MODE", "central")
	t.Setenv("BEYLA_PEER_METADATA_LISTEN_ADDRESS", "10.1.0.1")
	t.Setenv("BEYLA_PEER_METADATA_PORT", "9100")
	t.Setenv("BEYLA_PEER_METADATA_PEER_CIDRS", "10.2.0.0/16,10.3.0.0/16")
	t.Setenv("BEYLA_PEER_METADATA_REFRESH_INTERVAL", "2s")
	t.Setenv("BEYLA_PEER_METADATA_CALLER_TTL", "8s")
	t.Setenv("BEYLA_PEER_METADATA_CACHE_TTL", "9s")
	t.Setenv("BEYLA_PEER_METADATA_REQUEST_TIMEOUT", "4s")
	t.Setenv("BEYLA_PEER_METADATA_MAX_PEERS", "11")
	t.Setenv("BEYLA_PEER_METADATA_MAX_CONCURRENT", "3")
	t.Setenv("BEYLA_PEER_METADATA_MAX_CALLER_ENTRIES", "101")
	t.Setenv("BEYLA_PEER_METADATA_MAX_RESPONSE_BYTES", "4096")
	t.Setenv("BEYLA_PEER_METADATA_MAX_CACHE_BYTES", "8192")
	t.Setenv("BEYLA_PEER_METADATA_TOKEN", "env-secret")
	t.Setenv("BEYLA_PEER_METADATA_TLS_ENABLED", "true")
	t.Setenv("BEYLA_PEER_METADATA_TLS_CERT_FILE", "/env-cert")
	t.Setenv("BEYLA_PEER_METADATA_TLS_KEY_FILE", "/env-key")
	t.Setenv("BEYLA_PEER_METADATA_TLS_CA_FILE", "/env-ca")
	t.Setenv("BEYLA_PEER_METADATA_TLS_SERVER_NAME", "env.internal")
	defer unsetOBIEnv(t)

	cfg, err := LoadConfig(strings.NewReader(`
peer_metadata:
  enabled: false
  port: 1
`))
	require.NoError(t, err)
	got := cfg.AsOBI().PeerMetadata
	assert.Equal(t, peer.MetadataConfig{
		Enabled:          true,
		Mode:             peer.ModeCentral,
		ListenAddress:    "10.1.0.1",
		Port:             9100,
		PeerCIDRs:        []string{"10.2.0.0/16", "10.3.0.0/16"},
		RefreshInterval:  2 * time.Second,
		CallerTTL:        8 * time.Second,
		CacheTTL:         9 * time.Second,
		RequestTimeout:   4 * time.Second,
		MaxPeers:         11,
		MaxConcurrent:    3,
		MaxCallerEntries: 101,
		MaxResponseBytes: 4096,
		MaxCacheBytes:    8192,
		Token:            "env-secret",
		TLS: peer.MetadataTLSConfig{
			Enabled:    true,
			CertFile:   "/env-cert",
			KeyFile:    "/env-key",
			CAFile:     "/env-ca",
			ServerName: "env.internal",
		},
	}, got)
}

func TestV1PeerMetadataDefaults(t *testing.T) {
	defer unsetOBIEnv(t)
	cfg, err := LoadConfig(strings.NewReader("discovery:\n  instrument:\n    - open_ports: 8080\n"))
	require.NoError(t, err)
	assert.Equal(t, obi.DefaultConfig.PeerMetadata, cfg.AsOBI().PeerMetadata)
}

func TestV1PeerMetadataRejectsTokenWithoutTLS(t *testing.T) {
	defer unsetOBIEnv(t)
	cfg, err := LoadConfig(strings.NewReader(`
trace_printer: text
discovery:
  instrument:
    - open_ports: 8080
peer_metadata:
  enabled: true
  token: secret
`))
	require.NoError(t, err)
	require.ErrorContains(t, cfg.Validate(), "peer metadata token requires TLS")
}

func TestV1ExceptionsAndLogsConfig(t *testing.T) {
	defer unsetOBIEnv(t)
	cfg, err := LoadConfig(strings.NewReader(`
trace_printer: text
discovery:
  instrument:
    - open_ports: 8080
exceptions:
  enabled: true
otel_logs_export:
  endpoint: http://localhost:4318/v1/logs
  protocol: http/protobuf
  compression: gzip
  batch_max_size: 100
  queue_size: 400
  batch_timeout: 2s
attributes:
  sanitize_sql_query_text: true
`))
	require.NoError(t, err)
	require.NoError(t, cfg.Validate())
	assert.True(t, cfg.ExceptionsEnabled())
	assert.True(t, cfg.Attributes.SanitizeSQLQueryText)

	got := cfg.AsOBI()
	assert.True(t, got.Exceptions.Enabled)
	assert.True(t, got.Attributes.SanitizeSQLQueryText)
	assert.Equal(t, otelcfg.LogsConfig{
		Endpoint:     "http://localhost:4318/v1/logs",
		Protocol:     otelcfg.ProtocolHTTPProtobuf,
		Compression:  "gzip",
		BatchMaxSize: 100,
		QueueSize:    400,
		BatchTimeout: 2 * time.Second,
	}, got.Logs)

	restored := FromOBI(got)
	assert.Equal(t, cfg.Exceptions, restored.Exceptions)
	assert.Equal(t, cfg.Logs, restored.Logs)
	assert.Equal(t, cfg.Attributes.SanitizeSQLQueryText, restored.Attributes.SanitizeSQLQueryText)
}

func TestV1ExceptionsAndLogsEnvironmentOverrides(t *testing.T) {
	t.Setenv("BEYLA_EXCEPTIONS_ENABLED", "true")
	t.Setenv("BEYLA_OTLP_LOGS_ENDPOINT", "http://env:4318/v1/logs")
	t.Setenv("BEYLA_OTLP_LOGS_PROTOCOL", "grpc")
	t.Setenv("BEYLA_OTLP_LOGS_COMPRESSION", "gzip")
	t.Setenv("BEYLA_OTLP_LOGS_BATCH_MAX_SIZE", "50")
	t.Setenv("BEYLA_OTLP_LOGS_QUEUE_SIZE", "200")
	t.Setenv("BEYLA_OTLP_LOGS_BATCH_TIMEOUT", "3s")
	t.Setenv("BEYLA_SANITIZE_SQL_QUERY_TEXT", "true")
	defer unsetOBIEnv(t)

	cfg, err := LoadConfig(strings.NewReader(`
exceptions:
  enabled: false
otel_logs_export:
  endpoint: http://yaml:4318/v1/logs
  protocol: http/protobuf
attributes:
  sanitize_sql_query_text: false
`))
	require.NoError(t, err)
	assert.True(t, cfg.Exceptions.Enabled)
	assert.True(t, cfg.Attributes.SanitizeSQLQueryText)
	got := cfg.AsOBI()
	assert.True(t, got.Exceptions.Enabled)
	assert.Equal(t, "http://env:4318/v1/logs", got.Logs.Endpoint)
	assert.Equal(t, otelcfg.ProtocolGRPC, got.Logs.Protocol)
	assert.Equal(t, "gzip", got.Logs.Compression)
	assert.Equal(t, 50, got.Logs.BatchMaxSize)
	assert.Equal(t, 200, got.Logs.QueueSize)
	assert.Equal(t, 3*time.Second, got.Logs.BatchTimeout)
	assert.True(t, got.Attributes.SanitizeSQLQueryText)
}

func TestV1ExceptionsRequireLogsExporter(t *testing.T) {
	defer unsetOBIEnv(t)
	cfg, err := LoadConfig(strings.NewReader(`
trace_printer: text
discovery:
  instrument:
    - open_ports: 8080
exceptions:
  enabled: true
`))
	require.NoError(t, err)
	require.ErrorContains(t, cfg.Validate(), "exception capture requires otel_logs_export or a logs consumer")
}

func TestLogsRuntimeHooksRoundTrip(t *testing.T) {
	src := obi.DefaultConfig
	src.Logs.Endpoint = "http://localhost:4318/v1/logs"
	src.Logs.Protocol = otelcfg.ProtocolHTTPProtobuf
	src.Logs.InjectHeaders = func(headers map[string]string) {
		headers["Authorization"] = "secret"
	}
	exported := false
	src.Logs.LogsExport = func(context.Context, plog.Logs) error {
		exported = true
		return nil
	}
	src.Exceptions.Enabled = true
	src.Attributes.SanitizeSQLQueryText = true

	cfg := FromOBI(&src)
	round := cfg.AsOBI()
	require.NotNil(t, round.Logs.InjectHeaders)
	require.NotNil(t, round.Logs.LogsExport)
	headers := map[string]string{}
	round.Logs.InjectHeaders(headers)
	assert.Equal(t, "secret", headers["Authorization"])
	require.NoError(t, round.Logs.LogsExport(t.Context(), plog.NewLogs()))
	assert.True(t, exported)
	assert.Equal(t, src.Logs.Endpoint, round.Logs.Endpoint)
	assert.True(t, round.Exceptions.Enabled)
	assert.True(t, round.Attributes.SanitizeSQLQueryText)
}
