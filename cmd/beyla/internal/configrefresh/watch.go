package configrefresh

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/grafana/beyla/v3/pkg/beyla"
)

const configWatchInterval = time.Second

// Watch refreshes the discovery criteria of an initialized application pipeline when the
// configuration file changes from the contents loaded at startup.
// Mirrors .obi-src/cmd/obi/internal/configwatch, which watches Config v2 files only.
func Watch(ctx context.Context, path string, initial []byte, r *Refresher) {
	ticker := time.NewTicker(configWatchInterval)
	defer ticker.Stop()
	watchConfigFile(ctx, path, initial, r.Load, r.Apply, slog.With("component", "config.Watcher"), ticker.C)
}

// Reading the path on every poll also handles atomic file replacements and ConfigMap symlinks.
// nolint:cyclop // kept as OBI's watchConfigFile, so both can evolve together
func watchConfigFile(ctx context.Context, path string, previous []byte, load func([]byte) (*beyla.Config, error), refresh func(context.Context, *beyla.Config) error, log *slog.Logger, ticks <-chan time.Time) {
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
				cfg, err := load(data)
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
// contents reuses it, so validation and its warnings run once per change. The loader reads
// the environment snapshot taken at startup, so identical contents always load the same way.
type loadedContents struct {
	data []byte
	cfg  *beyla.Config
	err  error
}

func refreshConfig(ctx context.Context, loaded *loadedContents, refresh func(context.Context, *beyla.Config) error) error {
	if loaded.err != nil {
		return loaded.err
	}
	return refresh(ctx, loaded.cfg)
}
