// Package configrefresh applies discovery criteria changes to a running Beyla without restarting
// it, either from its watched configuration file or from a parent process such as Alloy.
package configrefresh

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	obiDiscover "go.opentelemetry.io/obi/pkg/appolly/discover"

	"github.com/grafana/beyla/v3/pkg/beyla"
)

// Refresher applies the discovery selection criteria of reloaded configurations to the running
// application pipeline. Any other configuration change requires a restart.
type Refresher struct {
	environment map[string]string
	startup     *beyla.Config
	updater     *obiDiscover.CriteriaUpdater
}

// New returns a Refresher for a Beyla running cfg, which was loaded from data, or an error
// explaining why its application pipeline cannot refresh the discovery criteria.
// It must be called before the pipeline starts, which modifies the process environment.
func New(cfg *beyla.Config, data []byte) (*Refresher, error) {
	if err := refreshable(cfg); err != nil {
		return nil, fmt.Errorf("discovery criteria can't be refreshed: %w; restart Beyla to apply configuration changes", err)
	}

	r := &Refresher{environment: environment()}

	// Loading again keeps the reference configuration apart from the running one, which
	// the pipeline is free to modify.
	startup, err := r.Load(data)
	if err != nil {
		return nil, fmt.Errorf("reloading the startup configuration: %w", err)
	}

	r.startup = startup
	r.updater = obiDiscover.NewCriteriaUpdater(startup.AsOBI())
	return r, nil
}

func refreshable(cfg *beyla.Config) error {
	switch {
	case cfg.Discovery.InstrumentAllLocal:
		return errors.New("discovery.instrument_all_local selects the instrumented processes by itself")
	case !cfg.InstrumentationEnabled():
		// This might be nice to fix in the future, but the whole app o11y pipeline is not started on the prior
		// config launch, so we need major changes.
		return errors.New("the application instrumentation was not enabled at startup")
	}

	return nil
}

func environment() map[string]string {
	variables := map[string]string{}
	for _, variable := range os.Environ() {
		if name, value, ok := strings.Cut(variable, "="); ok {
			variables[name] = value
		}
	}
	return variables
}

// Updater must be passed to the application pipeline, which then applies the refreshes.
func (r *Refresher) Updater() *obiDiscover.CriteriaUpdater { return r.updater }

// Load loads a complete configuration from data, with the environment that Beyla started with.
func (r *Refresher) Load(data []byte) (*beyla.Config, error) {
	return beyla.LoadRefreshConfig(data, r.environment)
}

// Apply waits until the running pipeline applies the discovery criteria of cfg, or rejects them.
// cfg must not be modified afterwards.
func (r *Refresher) Apply(ctx context.Context, cfg *beyla.Config) error {
	if changed := r.startup.ChangedSettings(cfg); len(changed) > 0 {
		return fmt.Errorf("only discovery selection criteria can be refreshed; restart Beyla to apply the changes to %s",
			strings.Join(changed, ", "))
	}

	return r.updater.Update(ctx, cfg.AsOBI())
}

// Refresh loads a complete configuration from data and applies its discovery criteria.
func (r *Refresher) Refresh(ctx context.Context, data []byte) error {
	cfg, err := r.Load(data)
	if err != nil {
		return err
	}

	return r.Apply(ctx, cfg)
}
