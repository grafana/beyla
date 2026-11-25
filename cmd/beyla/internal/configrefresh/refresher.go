// Package configrefresh applies discovery and trace sampling changes to a running Beyla without restarting
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

// Refresher applies compatible configuration edits to the running application pipeline.
type Refresher struct {
	environment map[string]string
	startup     *beyla.Config
	updater     *obiDiscover.CriteriaUpdater
}

// New returns a Refresher for a Beyla running cfg, which was loaded from data, or an error
// explaining why its application pipeline cannot refresh.
// It must be called before the pipeline starts, which modifies the process environment.
func New(cfg *beyla.Config, data []byte) (*Refresher, error) {
	if !cfg.InstrumentationEnabled() {
		return nil, errors.New("restart Beyla to apply configuration changes because application instrumentation was not enabled at startup")
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

// Apply waits until the running matcher accepts or rejects the discovery and sampling settings of cfg.
// cfg must not be modified afterwards.
func (r *Refresher) Apply(ctx context.Context, cfg *beyla.Config) error {
	if changed := r.startup.ChangedSettings(cfg); len(changed) > 0 {
		return fmt.Errorf("restart Beyla to apply changes to %s",
			strings.Join(changed, ", "))
	}

	return r.updater.Update(ctx, cfg.AsOBI())
}

// Refresh loads a complete configuration and applies its discovery and sampling settings.
func (r *Refresher) Refresh(ctx context.Context, data []byte) error {
	cfg, err := r.Load(data)
	if err != nil {
		return err
	}

	return r.Apply(ctx, cfg)
}
