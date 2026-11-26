package configbridge

// Layering of several configuration files. This is a port of the logic in
// https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pull/4229
// (cmd/obi/internal/configload/override.go and configwatch), adapted to Beyla:
// OBI's v1 base is *obi.Config, but Beyla's v1 base is its own beyla.Config, so
// this package only merges the documents and leaves loading them to the caller.
// Once that PR is merged upstream and Beyla bumps OBI, this can be reconciled.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"slices"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"go.opentelemetry.io/obi/internal/config/schema"
	obicfg "go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/obi"
)

const (
	VersionV1 = "v1"
	VersionV2 = "v2"
)

// Source is the contents of one configuration file.
type Source struct {
	Path string
	Data []byte
}

// V1Shared holds the settings that a v2 file can override in a v1 base.
// Nil fields were not overridden.
type V1Shared struct {
	LogLevel                *string
	LogFormat               *string
	ShutdownTimeout         *time.Duration
	ChannelBufferLen        *int
	ChannelSendTimeout      *time.Duration
	ChannelSendTimeoutPanic *bool
}

// Merged is the result of layering several files.
type Merged struct {
	// Version is the version of the first file, which sets the semantics and defaults.
	Version string
	// Data is the merged document, in the format of Version.
	Data []byte
	// Shared is only set for a v1 base that has v2 overrides.
	Shared *V1Shared
}

// MergeSources layers the files in increasing order of priority. With a single
// file, it returns its contents untouched.
//
// Within the same version, YAML mappings merge by key, and lists and scalars
// replace the earlier value. A file of the other version can only override
// the settings in sharedSettings.
func MergeSources(sources []Source) (*Merged, error) {
	if len(sources) == 0 {
		return &Merged{Version: VersionV1}, nil
	}
	if len(sources) == 1 {
		version, err := detectVersion(obicfg.ReplaceEnv(sources[0].Data))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", sources[0].Path, err)
		}
		return &Merged{Version: version, Data: sources[0].Data}, nil
	}

	var base string
	var paths []string
	document := map[string]any{}
	pending := mixedOverrides{fields: map[string]*sharedSetting{}, document: map[string]any{}}
	for i, source := range sources {
		data := obicfg.ReplaceEnv(source.Data)
		version, err := detectVersion(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", source.Path, err)
		}
		if i == 0 {
			base = version
		}
		values, err := readMapping(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", source.Path, err)
		}
		if version != base {
			if err := pending.add(base, version, values, source.Path); err != nil {
				return nil, fmt.Errorf("%s: %w", source.Path, err)
			}
			continue
		}
		// A later file in the base version wins over earlier overrides of the other version.
		for path := range pending.fields {
			if hasPath(values, path) {
				delete(pending.fields, path)
			}
		}
		mergeDocument(document, values)
		paths = append(paths, source.Path)
	}

	merged := &Merged{Version: base}
	switch {
	case base == VersionV2 && len(pending.fields) != 0:
		if err := pending.mergeLegacyFields(document); err != nil {
			return nil, fmt.Errorf("%s: %w", strings.Join(pending.paths, ", "), err)
		}
	case base == VersionV1 && len(pending.fields) != 0:
		shared, err := pending.v2Shared()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", strings.Join(pending.paths, ", "), err)
		}
		merged.Shared = shared
	}
	data, err := yaml.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", strings.Join(paths, ", "), err)
	}
	merged.Data = data
	return merged, nil
}

// LoadSources layers the files and loads the result when it's a v2 configuration.
// For a v1 result, it returns a nil config and the merged result, to be loaded by
// the caller.
func LoadSources(sources []Source) (*obi.Config, *Merged, error) {
	merged, err := MergeSources(sources)
	if err != nil {
		return nil, nil, err
	}
	if merged.Version != VersionV2 {
		return nil, merged, nil
	}
	cfg, err := LoadV2(merged.Data)
	if err != nil {
		return nil, nil, err
	}
	return cfg, merged, nil
}

func detectVersion(data []byte) (string, error) {
	_, _, err := schema.ParseStandaloneYAML(data)
	if err == nil {
		return VersionV2, nil
	}
	if IsNotV2(err) {
		return VersionV1, nil
	}
	return "", err
}

// mixedOverrides collects the settings of files whose version differs from the base.
type mixedOverrides struct {
	fields   map[string]*sharedSetting // by the setting's path in the base version
	document map[string]any
	paths    []string
}

func (p *mixedOverrides) add(base, version string, values map[string]any, source string) error {
	p.paths = append(p.paths, source)
	mergeDocument(p.document, values)
	if version == VersionV2 {
		delete(values, "file_format")
	}
	return p.addFields(base, version, values, "")
}

func (p *mixedOverrides) addFields(base, version string, m map[string]any, prefix string) error {
	for _, key := range slices.Sorted(maps.Keys(m)) {
		path := prefix + key
		if version == VersionV2 && path == extension+"version" {
			continue
		}
		if child, ok := m[key].(map[string]any); ok && len(child) != 0 {
			if err := p.addFields(base, version, child, path+"."); err != nil {
				return err
			}
			continue
		}
		found := false
		for i := range sharedSettings {
			setting := &sharedSettings[i]
			source, target := setting.v1, setting.v2
			if version == VersionV2 {
				source, target = target, source
			}
			if path == source {
				p.fields[target] = setting
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%s: cannot apply %s setting with %s semantics", path, version, base)
		}
	}
	return nil
}

// mergeLegacyFields puts the winning v1 scalars into the v2 document, so they get the
// same checks as native v2 settings. YAML null leaves a scalar at its legacy default.
func (p *mixedOverrides) mergeLegacyFields(document map[string]any) error {
	layer := obi.DefaultConfig
	for _, setting := range sharedSettings {
		if _, ok := p.fields[setting.v2]; !ok {
			continue
		}
		if raw := p.document[setting.v1]; raw != nil {
			node, ok := raw.(*yaml.Node)
			if !ok {
				return fmt.Errorf("%s: expected a scalar", setting.v1)
			}
			if err := node.Decode(setting.field(&layer)); err != nil {
				return fmt.Errorf("%s: %w", setting.v1, err)
			}
		}
		parts := strings.Split(setting.v2, ".")
		last := len(parts) - 1
		value := map[string]any{parts[last]: setting.field(&layer)}
		for _, key := range slices.Backward(parts[:last]) {
			value = map[string]any{key: value}
		}
		mergeDocument(document, value)
	}
	return nil
}

// v2Shared extracts the winning v2 settings, to be applied over a v1 base.
func (p *mixedOverrides) v2Shared() (*V1Shared, error) {
	data, err := yaml.Marshal(p.document)
	if err != nil {
		return nil, err
	}
	doc, _, err := schema.ParseStandaloneYAML(data)
	if err != nil {
		return nil, err
	}
	layer, err := loadDocument(doc)
	if err != nil {
		return nil, err
	}
	shared := &V1Shared{}
	for _, setting := range sharedSettings {
		if _, ok := p.fields[setting.v1]; !ok {
			continue
		}
		switch v := setting.field(layer).(type) {
		case *int:
			shared.ChannelBufferLen = ptr(*v)
		case *bool:
			shared.ChannelSendTimeoutPanic = ptr(*v)
		case *time.Duration:
			if setting.v1 == "shutdown_timeout" {
				shared.ShutdownTimeout = ptr(*v)
			} else {
				shared.ChannelSendTimeout = ptr(*v)
			}
		case *obi.LogLevel:
			shared.LogLevel = ptr(string(*v))
		case *obi.LogFormat:
			shared.LogFormat = ptr(string(*v))
		}
	}
	return shared, nil
}

func ptr[T any](v T) *T { return &v }

// Keep YAML scalar tags and spelling until the version-specific loader decodes
// them. For example, an unquoted service name of 001 must not become 1.
type yamlValue struct{ value any }

func (v *yamlValue) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.MappingNode:
		var entries map[string]yamlValue
		if err := n.Decode(&entries); err != nil {
			return err
		}
		v.value = mappingValues(entries)
	case yaml.SequenceNode:
		var entries []yamlValue
		if err := n.Decode(&entries); err != nil {
			return err
		}
		values := make([]any, len(entries))
		for i := range entries {
			values[i] = entries[i].value
		}
		v.value = values
	default:
		scalar := *n
		scalar.Anchor = ""
		v.value = &scalar
	}
	return nil
}

func readMapping(data []byte) (map[string]any, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	// Validate aliases across the whole document before decoding individual mappings.
	var checked map[string]any
	if err := root.Decode(&checked); err != nil {
		return nil, err
	}
	var entries map[string]yamlValue
	if err := root.Decode(&entries); err != nil {
		return nil, err
	}
	return mappingValues(entries), nil
}

func mappingValues(entries map[string]yamlValue) map[string]any {
	values := make(map[string]any, len(entries))
	for k, v := range entries {
		values[k] = v.value
	}
	return values
}

// mergeDocument merges non-empty mappings recursively. Anything else, including
// an empty mapping, replaces the previous value.
func mergeDocument(dst, src map[string]any) {
	for key, value := range src {
		child, mapping := value.(map[string]any)
		old, exists := dst[key].(map[string]any)
		if mapping && exists && len(child) > 0 {
			mergeDocument(old, child)
		} else {
			dst[key] = value
		}
	}
}

func hasPath(values map[string]any, path string) bool {
	key, rest, nested := strings.Cut(path, ".")
	value, ok := values[key]
	if !ok || !nested {
		return ok
	}
	child, ok := value.(map[string]any)
	return !ok || len(child) == 0 || hasPath(child, rest)
}

const extension = "extensions.obi."

type sharedSetting struct {
	v1, v2 string
	field  func(*obi.Config) any
}

func scalar[T any](v1, v2 string, field func(*obi.Config) *T) sharedSetting {
	return sharedSetting{v1: v1, v2: v2, field: func(cfg *obi.Config) any { return field(cfg) }}
}

var sharedSettings = []sharedSetting{
	scalar("channel_buffer_len", extension+"capture.channels.buffer_len", func(c *obi.Config) *int { return &c.ChannelBufferLen }),
	scalar("channel_send_timeout", extension+"capture.channels.send_timeout", func(c *obi.Config) *time.Duration { return &c.ChannelSendTimeout }),
	scalar("channel_send_timeout_panic", extension+"capture.channels.panic_on_send_timeout", func(c *obi.Config) *bool { return &c.ChannelSendTimeoutPanic }),
	scalar("shutdown_timeout", extension+"daemon.shutdown.timeout", func(c *obi.Config) *time.Duration { return &c.ShutdownTimeout }),
	scalar("log_level", "log_level", func(c *obi.Config) *obi.LogLevel { return &c.LogLevel }),
	scalar("log_format", extension+"daemon.logging.format", func(c *obi.Config) *obi.LogFormat { return &c.LogFormat }),
}

const configWatchInterval = time.Second

// WatchSources refreshes discovery criteria when any of the files changes from the
// contents loaded at startup. All the files are reloaded and layered again.
func WatchSources(ctx context.Context, initial []Source, refresh func(context.Context, *obi.Config) error) {
	ticker := time.NewTicker(configWatchInterval)
	defer ticker.Stop()
	watchConfigFiles(ctx, initial, refresh, slog.With("component", "config.Watcher"), ticker.C)
}

// Reading the paths on every poll also handles atomic file replacements and ConfigMap symlinks.
// nolint:cyclop // mirrors OBI's watchConfigFile
func watchConfigFiles(ctx context.Context, previous []Source, refresh func(context.Context, *obi.Config) error, log *slog.Logger, ticks <-chan time.Time) {
	paths := sourcePaths(previous)
	lastRead := previous
	var readError string
	var loaded *loadedContents
	var rejected []Source
	var refreshError string
	for {
		sources, err := readSources(paths)
		switch {
		case err != nil:
			if readError != err.Error() {
				log.Error("can't read configuration for refresh; continuing with the running configuration", "paths", paths, "error", err)
				readError = err.Error()
			}
		default:
			readError = ""
			unchangedSinceLastRead := equalContents(lastRead, sources)
			lastRead = sources
			if equalContents(previous, sources) {
				loaded, rejected, refreshError = nil, nil, ""
				break
			}
			// A poll can land in the middle of an in-place write, so contents apply
			// only once two consecutive polls read them unchanged.
			if !unchangedSinceLastRead {
				break
			}
			if loaded == nil || !equalContents(loaded.sources, sources) {
				cfg, err := loadRefresh(sources)
				loaded = &loadedContents{sources: sources, cfg: cfg, err: err}
			}
			if err := refreshConfig(ctx, loaded, refresh); err != nil {
				if ctx.Err() != nil {
					return
				}
				if !equalContents(rejected, sources) || refreshError != err.Error() {
					log.Error("can't refresh configuration; continuing with the running configuration and retrying", "paths", paths, "error", err)
					rejected = sources
					refreshError = err.Error()
				}
			} else {
				previous = sources
				loaded, rejected, refreshError = nil, nil, ""
				log.Info("discovery criteria refreshed", "paths", paths)
			}
		}
		select {
		case <-ctx.Done():
			return
		case _, ok := <-ticks:
			if !ok {
				return
			}
		}
	}
}

// loadedContents keeps the result of loading one version of the files, so validation
// and its warnings run once per change.
type loadedContents struct {
	sources []Source
	cfg     *obi.Config
	err     error
}

func refreshConfig(ctx context.Context, loaded *loadedContents, refresh func(context.Context, *obi.Config) error) error {
	if loaded.err != nil {
		return loaded.err
	}
	return refresh(ctx, loaded.cfg)
}

func loadRefresh(sources []Source) (*obi.Config, error) {
	cfg, _, err := LoadSources(sources)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, errors.New("configuration version changed; restart Beyla to apply this configuration")
	}
	if err := cfg.ValidateStaticForApplicationRefresh(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func readSources(paths []string) ([]Source, error) {
	sources := make([]Source, 0, len(paths))
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		sources = append(sources, Source{Path: path, Data: data})
	}
	return sources, nil
}

func sourcePaths(sources []Source) []string {
	paths := make([]string, 0, len(sources))
	for _, source := range sources {
		paths = append(paths, source.Path)
	}
	return paths
}

func equalContents(a, b []Source) bool {
	return slices.EqualFunc(a, b, func(x, y Source) bool {
		return x.Path == y.Path && bytes.Equal(x.Data, y.Data)
	})
}
