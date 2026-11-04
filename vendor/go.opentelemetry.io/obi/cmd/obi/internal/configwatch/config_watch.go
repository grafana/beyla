// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package configwatch // import "go.opentelemetry.io/obi/cmd/obi/internal/configwatch"

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"time"

	"go.opentelemetry.io/obi/cmd/obi/internal/configload"
	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/obi"
)

const configWatchInterval = time.Second

// Watch refreshes discovery criteria for an initialized application pipeline
// when the configuration file changes from the contents loaded at startup.
func Watch(ctx context.Context, path string, initial []byte, refresh func(context.Context, *obi.Config) error) {
	ticker := time.NewTicker(configWatchInterval)
	defer ticker.Stop()
	watchConfigFile(ctx, path, initial, refresh, slog.With("component", "config.Watcher"), ticker.C)
}

// Reading the path on every poll also handles atomic file replacements and ConfigMap symlinks.
func watchConfigFile(ctx context.Context, path string, previous []byte, refresh func(context.Context, *obi.Config) error, log *slog.Logger, ticks <-chan time.Time) {
	lastRead := previous
	var readError string
	var loaded *loadedContents
	var rejected []byte
	var refreshError string
	for {
		data, err := os.ReadFile(path)
		switch {
		case err != nil:
			if readError != err.Error() {
				log.Error("can't read configuration for refresh; continuing with the running configuration", "path", path, "error", err)
				readError = err.Error()
			}
		default:
			readError = ""
			unchangedSinceLastRead := bytes.Equal(lastRead, data)
			lastRead = data
			if bytes.Equal(previous, data) {
				loaded = nil
				rejected = nil
				refreshError = ""
				break
			}

			// A poll can land in the middle of an in-place write, so contents apply
			// only once two consecutive polls read them unchanged.
			if !unchangedSinceLastRead {
				break
			}

			if loaded == nil || !bytes.Equal(loaded.data, data) {
				cfg, err := loadConfig(data)
				loaded = &loadedContents{data: data, cfg: cfg, err: err}
			}
			if err := refreshConfig(ctx, loaded, refresh); err != nil {
				if ctx.Err() != nil {
					return
				}
				if !bytes.Equal(rejected, data) || refreshError != err.Error() {
					log.Error("can't refresh configuration; continuing with the running configuration and retrying", "path", path, "error", err)
					rejected = data
					refreshError = err.Error()
				}
			} else {
				previous = data
				loaded = nil
				rejected = nil
				refreshError = ""
				log.Info("discovery criteria refreshed", "path", path)
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

// loadedContents keeps the result of loading one version of the file. Retrying the same
// contents reuses it, so validation and its warnings run once per change. Environment
// variables are fixed for the process, so identical contents always load the same way.
type loadedContents struct {
	data []byte
	cfg  *obi.Config
	err  error
}

func refreshConfig(ctx context.Context, loaded *loadedContents, refresh func(context.Context, *obi.Config) error) error {
	if loaded.err != nil {
		return loaded.err
	}
	return refresh(ctx, loaded.cfg)
}

func loadConfig(data []byte) (*obi.Config, error) {
	cfg, err := configload.LoadV2(data)
	if err != nil {
		if _, ok := errors.AsType[*schema.NotV2Error](err); ok {
			return nil, errors.New("configuration version changed; restart OBI to apply this configuration")
		}
		return nil, err
	}
	if err := cfg.ValidateStaticForApplicationRefresh(); err != nil {
		return nil, err
	}
	return cfg, nil
}
