package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/cmd/obi/configbridge"
)

func TestConfigFilePaths(t *testing.T) {
	sep := string(filepath.ListSeparator)
	assert.Empty(t, configFilePaths(nil, ""))
	assert.Equal(t, []string{"a.yml"}, configFilePaths([]string{"a.yml"}, ""))
	assert.Equal(t, []string{"a.yml", "b.yml"}, configFilePaths(nil, "a.yml"+sep+"b.yml"))
	// flags go first (lowest priority), then the environment entries from left to right
	assert.Equal(t,
		[]string{"base.yml", "site.yml", "team.yml", "local.yml"},
		configFilePaths([]string{"base.yml", "site.yml"}, "team.yml"+sep+sep+"local.yml"))
}

func TestConfigPathsFlag(t *testing.T) {
	var paths configPaths
	require.NoError(t, paths.Set("a.yml"))
	require.NoError(t, paths.Set("b.yml"))
	assert.Equal(t, "a.yml,b.yml", paths.String())
}

func src(path, data string) configbridge.Source {
	return configbridge.Source{Path: path, Data: []byte(data)}
}

func TestLoadConfigSources_V1BaseWithV2Override(t *testing.T) {
	v2 := strings.Join([]string{
		`file_format: "1.0"`,
		`log_level: debug`,
		`extensions:`,
		`  obi:`,
		`    version: "2.0"`,
		`    capture:`,
		`      channels:`,
		`        buffer_len: 77`,
	}, "\n") + "\n"
	cfg, version, err := loadConfigSources([]configbridge.Source{
		src("base.yml", "log_level: info\nchannel_buffer_len: 10\nshutdown_timeout: 3s\n"),
		src("new.yml", v2),
	})
	require.NoError(t, err)
	assert.Equal(t, configVersionV1, version)
	assert.Equal(t, 77, cfg.ChannelBufferLen)
	assert.Equal(t, "debug", strings.ToLower(cfg.LogLevel))
	// untouched by the override
	assert.Equal(t, "3s", cfg.ShutdownTimeout.String())
}

func TestLoadConfigSources_V2BaseWithV1Override(t *testing.T) {
	v2 := strings.Join([]string{
		`file_format: "1.0"`,
		`log_level: info`,
		`extensions:`,
		`  obi:`,
		`    version: "2.0"`,
		`    capture:`,
		`      channels:`,
		`        buffer_len: 10`,
	}, "\n") + "\n"
	cfg, version, err := loadConfigSources([]configbridge.Source{
		src("base.yml", v2),
		src("legacy.yml", "channel_buffer_len: 77\nlog_level: debug\n"),
	})
	require.NoError(t, err)
	assert.Equal(t, configVersionV2, version)
	assert.Equal(t, 77, cfg.ChannelBufferLen)
	assert.Equal(t, "debug", strings.ToLower(cfg.LogLevel))
}

func TestLoadConfigSources_NoFiles(t *testing.T) {
	cfg, version, err := loadConfigSources(nil)
	require.NoError(t, err)
	assert.Equal(t, configVersionV1, version)
	assert.NotNil(t, cfg)
}

func TestLoadConfigSources_ErrorNamesTheFile(t *testing.T) {
	_, _, err := loadConfigSources([]configbridge.Source{
		src("base.yml", "log_level: info\n"),
		src("broken.yml", "log_level: [oops\n"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "broken.yml")
}
