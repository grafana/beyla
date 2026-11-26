package beyla

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/cmd/obi/configbridge"
)

func v2Doc(extra string) string {
	return "file_format: \"1.0\"\n" + extra
}

func v2Capture(body string) string {
	return v2Doc("extensions:\n  obi:\n    version: \"2.0\"\n" + body)
}

func src(name, data string) configbridge.Source {
	return configbridge.Source{Path: name, Data: []byte(data)}
}

func TestMergeSources_SingleFileIsUntouched(t *testing.T) {
	data := "log_level:   debug # keep my formatting\n"
	merged, err := configbridge.MergeSources([]configbridge.Source{src("a.yml", data)})
	require.NoError(t, err)
	assert.Equal(t, configbridge.VersionV1, merged.Version)
	assert.Equal(t, data, string(merged.Data))
	assert.Nil(t, merged.Shared)
}

func TestMergeSources_NoFiles(t *testing.T) {
	merged, err := configbridge.MergeSources(nil)
	require.NoError(t, err)
	assert.Equal(t, configbridge.VersionV1, merged.Version)
	assert.Empty(t, merged.Data)
}

func TestMergeSources_V1OverV1(t *testing.T) {
	merged, err := configbridge.MergeSources([]configbridge.Source{
		src("base.yml", "log_level: info\ndiscovery:\n  poll_interval: 1s\n  min_process_age: 2s\n  instrument:\n    - open_ports: 80\n    - open_ports: 81\n"),
		src("site.yml", "discovery:\n  poll_interval: 5s\n  instrument:\n    - open_ports: 90\n"),
	})
	require.NoError(t, err)
	require.Equal(t, configbridge.VersionV1, merged.Version)

	cfg, err := LoadConfig(bytes.NewReader(merged.Data))
	require.NoError(t, err)
	assert.Equal(t, "info", cfg.LogLevel)
	// mappings merge by key
	assert.Equal(t, 5*time.Second, cfg.Discovery.PollInterval)
	assert.Equal(t, 2*time.Second, cfg.Discovery.MinProcessAge)
	// sequences replace the previous value
	require.Len(t, cfg.Discovery.Instrument, 1)
	assert.True(t, hasOpenPort(cfg, 90))
	assert.False(t, hasOpenPort(cfg, 80))
}

func TestMergeSources_KeepsScalarSpelling(t *testing.T) {
	// an unquoted 001 must not become 1 after merging
	merged, err := configbridge.MergeSources([]configbridge.Source{
		src("base.yml", "log_level: info\n"),
		src("site.yml", "discovery:\n  instrument:\n    - name: 001\n      open_ports: 80\n"),
	})
	require.NoError(t, err)
	assert.Contains(t, string(merged.Data), "001")
}

func TestMergeSources_V2OverV2(t *testing.T) {
	merged, err := configbridge.MergeSources([]configbridge.Source{
		src("base.yml", v2Capture("    capture:\n      channels:\n        buffer_len: 10\n        send_timeout: 3s\n")),
		src("site.yml", v2Capture("    capture:\n      channels:\n        buffer_len: 20\n")),
	})
	require.NoError(t, err)
	require.Equal(t, configbridge.VersionV2, merged.Version)

	cfg, err := configbridge.LoadV2(merged.Data)
	require.NoError(t, err)
	assert.Equal(t, 20, cfg.ChannelBufferLen)
	assert.Equal(t, 3*time.Second, cfg.ChannelSendTimeout)
}

func TestMergeSources_V2BaseWithV1Override(t *testing.T) {
	merged, err := configbridge.MergeSources([]configbridge.Source{
		src("base.yml", v2Capture("    capture:\n      channels:\n        buffer_len: 10\n")+"log_level: info\n"),
		src("legacy.yml", "channel_buffer_len: 77\nshutdown_timeout: 9s\nlog_level: debug\n"),
	})
	require.NoError(t, err)
	require.Equal(t, configbridge.VersionV2, merged.Version)

	cfg, err := configbridge.LoadV2(merged.Data)
	require.NoError(t, err)
	assert.Equal(t, 77, cfg.ChannelBufferLen)
	assert.Equal(t, 9*time.Second, cfg.ShutdownTimeout)
	assert.True(t, strings.EqualFold("debug", string(cfg.LogLevel)), "log level: %s", cfg.LogLevel)
}

func TestMergeSources_V1BaseWithV2Override(t *testing.T) {
	merged, err := configbridge.MergeSources([]configbridge.Source{
		src("base.yml", "channel_buffer_len: 10\nlog_level: info\n"),
		src("new.yml", v2Capture("    capture:\n      channels:\n        buffer_len: 77\n")+"log_level: debug\n"),
	})
	require.NoError(t, err)
	require.Equal(t, configbridge.VersionV1, merged.Version)
	require.NotNil(t, merged.Shared)
	require.NotNil(t, merged.Shared.ChannelBufferLen)
	assert.Equal(t, 77, *merged.Shared.ChannelBufferLen)
	require.NotNil(t, merged.Shared.LogLevel)
	assert.True(t, strings.EqualFold("debug", *merged.Shared.LogLevel))
	// settings that the v2 file does not mention are left alone
	assert.Nil(t, merged.Shared.ShutdownTimeout)
	assert.Nil(t, merged.Shared.ChannelSendTimeout)
}

func TestMergeSources_BaseVersionWinsWhenLater(t *testing.T) {
	merged, err := configbridge.MergeSources([]configbridge.Source{
		src("base.yml", v2Capture("    capture:\n      channels:\n        buffer_len: 10\n")),
		src("legacy.yml", "channel_buffer_len: 77\n"),
		src("last.yml", v2Capture("    capture:\n      channels:\n        buffer_len: 20\n")),
	})
	require.NoError(t, err)
	cfg, err := configbridge.LoadV2(merged.Data)
	require.NoError(t, err)
	assert.Equal(t, 20, cfg.ChannelBufferLen)
}

func TestMergeSources_UnsupportedCrossVersionSetting(t *testing.T) {
	_, err := configbridge.MergeSources([]configbridge.Source{
		src("base.yml", v2Capture("    capture:\n      channels:\n        buffer_len: 10\n")),
		src("legacy.yml", "discovery:\n  poll_interval: 5s\n"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "legacy.yml")
	assert.Contains(t, err.Error(), "discovery.poll_interval")

	_, err = configbridge.MergeSources([]configbridge.Source{
		src("base.yml", "log_level: info\n"),
		src("new.yml", v2Capture("    capture:\n      policy:\n        poll_interval: 1s\n")),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "new.yml")
}

func TestMergeSources_InvalidFileNamesThePath(t *testing.T) {
	_, err := configbridge.MergeSources([]configbridge.Source{
		src("base.yml", "log_level: info\n"),
		src("broken.yml", "log_level: [unterminated\n"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "broken.yml")
}

func TestLoadConfigWithOverrides_AppliedBeforeEnv(t *testing.T) {
	t.Setenv("BEYLA_CHANNEL_BUFFER_LEN", "333")
	cfg, err := LoadConfigWithOverrides(strings.NewReader("channel_buffer_len: 10\nlog_level: info\n"), func(c *Config) {
		c.ChannelBufferLen = 77
		c.LogLevel = "debug"
	})
	require.NoError(t, err)
	// the file override beats the file, but not the environment
	assert.Equal(t, 333, cfg.ChannelBufferLen)
	assert.Equal(t, "debug", cfg.LogLevel)
}
