package configrefresh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"

	obiDiscover "go.opentelemetry.io/obi/pkg/appolly/discover"

	"github.com/grafana/beyla/v3/pkg/beyla"
)

func loadFromProcessEnvironment(data []byte) (*beyla.Config, error) {
	return beyla.LoadRefreshConfig(data, nil)
}

func watcherConfig(port int) []byte {
	return testConfig(portSelection(port))
}

func openPortsCriterion(t *testing.T, cfg *beyla.Config, port int) bool {
	t.Helper()
	criteria := obiDiscover.FindingCriteria(cfg.AsOBI())
	require.NotEmpty(t, criteria)
	return criteria[0].GetOpenPorts().Matches(port)
}

type configWatchLog struct {
	records chan slog.Record
}

func (l configWatchLog) Enabled(context.Context, slog.Level) bool { return true }
func (l configWatchLog) Handle(_ context.Context, record slog.Record) error {
	l.records <- record.Clone()
	return nil
}
func (l configWatchLog) WithAttrs([]slog.Attr) slog.Handler { return l }
func (l configWatchLog) WithGroup(string) slog.Handler      { return l }

func TestConfigFileWatcherStartup(t *testing.T) {
	for _, tc := range []struct {
		name    string
		port    int
		refresh bool
	}{
		{name: "unchanged startup file", port: 8080},
		{name: "file changed before watcher starts", port: 9090, refresh: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "beyla.yml")
			initial := watcherConfig(8080)
			require.NoError(t, os.WriteFile(path, initial, 0o600))
			if tc.refresh {
				require.NoError(t, os.WriteFile(path, watcherConfig(tc.port), 0o600))
			}
			// A change applies once a second poll reads it unchanged.
			ticks := make(chan time.Time, 1)
			ticks <- time.Now()
			close(ticks)
			records := make(chan slog.Record, 10)
			logger := slog.New(configWatchLog{records: records})
			var refreshed []*beyla.Config
			watchConfigFile(t.Context(), path, initial, loadFromProcessEnvironment, func(_ context.Context, cfg *beyla.Config) error {
				refreshed = append(refreshed, cfg)
				return nil
			}, logger, ticks)

			if tc.refresh {
				require.Len(t, refreshed, 1)
				require.True(t, openPortsCriterion(t, refreshed[0], tc.port))
				require.Equal(t, slog.LevelInfo, readConfigLog(t, records).Level)
			} else {
				require.Empty(t, refreshed, "startup configuration must not trigger a refresh")
			}
			require.Empty(t, records)
		})
	}
}

func TestConfigFileWatcherRetriesRejectedUpdate(t *testing.T) {
	for _, tc := range []struct {
		name      string
		pids      []int
		errorLogs int
	}{
		{name: "same rejection", pids: []int{10, 10}, errorLogs: 1},
		{name: "different rejection", pids: []int{10, 20}, errorLogs: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "beyla.yml")
			initial := watcherConfig(8080)
			require.NoError(t, os.WriteFile(path, watcherConfig(9090), 0o600))
			// One poll waits for the change to settle and one confirms the accepted file is skipped.
			ticks := make(chan time.Time, len(tc.pids)+2)
			for range cap(ticks) {
				ticks <- time.Now()
			}
			close(ticks)
			records := make(chan slog.Record, 10)
			logger := slog.New(configWatchLog{records: records})
			attempts := 0
			var applied *beyla.Config
			watchConfigFile(t.Context(), path, initial, loadFromProcessEnvironment, func(_ context.Context, cfg *beyla.Config) error {
				attempts++
				require.True(t, openPortsCriterion(t, cfg, 9090))
				if attempts <= len(tc.pids) {
					return fmt.Errorf("service settings would change for PID %d; restart Beyla to apply this configuration", tc.pids[attempts-1])
				}
				// The blocking processes have exited; the unchanged file can now apply.
				applied = cfg
				return nil
			}, logger, ticks)

			require.Equal(t, len(tc.pids)+1, attempts, "retry until accepted, then skip the unchanged file")
			require.NotNil(t, applied)
			for range tc.errorLogs {
				require.Equal(t, slog.LevelError, readConfigLog(t, records).Level)
			}
			require.Equal(t, slog.LevelInfo, readConfigLog(t, records).Level)
			require.Empty(t, records)
		})
	}
}

func TestConfigFileWatcherRetriesWithoutRepeatingValidation(t *testing.T) {
	// Selecting both span metric formats through "all" makes validation warn about it.
	resolved := []byte(`
otel_metrics_export:
  endpoint: http://localhost:4318
prometheus_export:
  port: 9090
metrics:
  features: [all]
discovery:
  instrument:
    - open_ports: 9090
`)
	path := filepath.Join(t.TempDir(), "beyla.yml")
	require.NoError(t, os.WriteFile(path, resolved, 0o600))
	// Validation reports through the default logger. Replacing it also redirects the log
	// package, which restoring the original default logger does not undo.
	defaultLogger, logWriter, logFlags := slog.Default(), log.Writer(), log.Flags()
	t.Cleanup(func() {
		slog.SetDefault(defaultLogger)
		log.SetOutput(logWriter)
		log.SetFlags(logFlags)
	})
	validationLogs := make(chan slog.Record, 20)
	slog.SetDefault(slog.New(configWatchLog{records: validationLogs}))

	const retries = 3
	// The first poll waits for the change to settle.
	ticks := make(chan time.Time, retries)
	for range cap(ticks) {
		ticks <- time.Now()
	}
	close(ticks)
	records := make(chan slog.Record, 10)
	attempts := 0
	watchConfigFile(t.Context(), path, watcherConfig(8080), loadFromProcessEnvironment, func(context.Context, *beyla.Config) error {
		attempts++
		return errors.New("service settings would change for PID 10; restart Beyla to apply this configuration")
	}, slog.New(configWatchLog{records: records}), ticks)
	close(validationLogs)

	require.Equal(t, retries, attempts)
	resolutionWarnings := 0
	for record := range validationLogs {
		if strings.Contains(record.Message, "application_span_otel is selected automatically") {
			resolutionWarnings++
		}
	}
	require.Equal(t, 1, resolutionWarnings, "retrying unchanged contents must not repeat validation warnings")
	require.Equal(t, slog.LevelError, readConfigLog(t, records).Level)
	require.Empty(t, records)
}

func TestConfigFileWatcherSkipsPartialWrite(t *testing.T) {
	complete := testConfig(`
  instrument:
    - open_ports: 8080
    - open_ports: 9090
`)
	// The first definition alone is still a valid configuration.
	partial := complete[:bytes.LastIndex(complete, []byte("    - open_ports"))]
	_, err := loadFromProcessEnvironment(partial)
	require.NoError(t, err)

	synctest.Test(t, func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "beyla.yml")
		initial := watcherConfig(7070)
		require.NoError(t, os.WriteFile(path, initial, 0o600))
		ticks := make(chan time.Time)
		records := make(chan slog.Record, 10)
		logger := slog.New(configWatchLog{records: records})
		refreshed := make(chan *beyla.Config, 10)
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() {
			defer close(done)
			watchConfigFile(ctx, path, initial, loadFromProcessEnvironment, func(_ context.Context, cfg *beyla.Config) error {
				refreshed <- cfg
				return nil
			}, logger, ticks)
		}()

		// Waiting for the watcher to block between polls makes each write visible to exactly one poll.
		for _, contents := range [][]byte{partial, complete, complete} {
			synctest.Wait()
			require.NoError(t, os.WriteFile(path, contents, 0o600))
			ticks <- time.Now()
		}
		synctest.Wait()
		cancel()
		<-done

		require.Len(t, refreshed, 1)
		require.Len(t, obiDiscover.FindingCriteria((<-refreshed).AsOBI()), 2)
		require.Equal(t, slog.LevelInfo, readConfigLog(t, records).Level)
		require.Empty(t, records)
	})
}

func TestConfigFileWatcher(t *testing.T) {
	path := filepath.Join(t.TempDir(), "beyla.yml")
	initial := watcherConfig(8080)
	require.NoError(t, os.WriteFile(path, initial, 0o600))
	refresher, err := New(startupConfig(t, initial), initial)
	require.NoError(t, err)
	updates := refresher.Updater().Updates()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	// Matcher reconciliation is covered in OBI's discover package; acknowledge its boundary here.
	go func() {
		defer updates.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case update := <-updates.Requests():
				updates.Complete(update, nil)
			}
		}
	}()
	ticks := make(chan time.Time)
	records := make(chan slog.Record, 10)
	logger := slog.New(configWatchLog{records: records})
	done := make(chan struct{})
	go func() {
		defer close(done)
		watchConfigFile(ctx, path, initial, refresher.Load, refresher.Apply, logger, ticks)
	}()
	// A change applies once a second poll reads it unchanged.
	pollChange := func() {
		ticks <- time.Now()
		ticks <- time.Now()
	}
	for range 2 {
		select {
		case ticks <- time.Now():
		case <-time.After(time.Second):
			t.Fatal("config watcher did not finish the unchanged poll")
		}
		require.Empty(t, records)
		require.Empty(t, updates.Changed(), "unchanged configuration must not trigger a rescan")
	}

	replacement := path + ".new"
	require.NoError(t, os.WriteFile(replacement, watcherConfig(9090), 0o600))
	require.NoError(t, os.Rename(replacement, path))
	pollChange()
	require.Equal(t, slog.LevelInfo, readConfigLog(t, records).Level)
	criteria, _ := updates.Current()
	require.True(t, criteria[0].GetOpenPorts().Matches(9090))
	require.False(t, criteria[0].GetOpenPorts().Matches(8080))

	incompatible := bytes.Replace(watcherConfig(9090), []byte("localhost:4318"), []byte("collector:4318"), 1)
	require.NoError(t, os.WriteFile(path, incompatible, 0o600))
	pollChange()
	failure := readConfigLog(t, records)
	require.Equal(t, slog.LevelError, failure.Level)
	require.Contains(t, failure.Message, "can't refresh configuration")
	require.Contains(t, failure.Message, "retrying")
	criteria, _ = updates.Current()
	require.True(t, criteria[0].GetOpenPorts().Matches(9090))

	require.NoError(t, os.WriteFile(path, []byte("discovery: ["), 0o600))
	pollChange()
	require.Equal(t, slog.LevelError, readConfigLog(t, records).Level)

	// Removing the final definition must reach the updater even with no other active features.
	require.NoError(t, os.WriteFile(path, testConfig(""), 0o600))
	pollChange()
	result := readConfigLog(t, records)
	require.Equal(t, slog.LevelInfo, result.Level, "%v", result)
	criteria, _ = updates.Current()
	require.Empty(t, criteria)

	// Adding a definition resumes selection after the pipeline became idle.
	require.NoError(t, os.WriteFile(path, initial, 0o600))
	pollChange()
	require.Equal(t, slog.LevelInfo, readConfigLog(t, records).Level)
	criteria, _ = updates.Current()
	require.True(t, criteria[0].GetOpenPorts().Matches(8080))

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("config watcher did not stop")
	}
}

func readConfigLog(t *testing.T, records <-chan slog.Record) slog.Record {
	t.Helper()
	select {
	case record := <-records:
		return record
	case <-time.After(time.Second):
		t.Fatal("config watcher did not log a result")
		return slog.Record{}
	}
}
