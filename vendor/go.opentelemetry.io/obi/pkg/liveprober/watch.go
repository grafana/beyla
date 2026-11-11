// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package liveprober // import "go.opentelemetry.io/obi/pkg/liveprober"

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"reflect"
	"time"

	"gopkg.in/yaml.v3"

	"go.opentelemetry.io/obi/pkg/config"
)

func (m *Manager) Run(ctx context.Context, cfg config.DynamicInstrumentationConfig, path string) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	var server *http.Server
	if cfg.ListenAddress != "" {
		listener, err := net.Listen("tcp", cfg.ListenAddress)
		if err != nil {
			return fmt.Errorf("dynamic instrumentation listener: %w", err)
		}
		server = &http.Server{Handler: m.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: cfg.RequestTimeout + 5*time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: maxRequestBytes}
		go func() {
			if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.Error("dynamic instrumentation API stopped", "error", err)
			}
		}()
	}
	if err := m.SetConfigRules(cfg.Rules); err != nil {
		if server != nil {
			_ = server.Close()
		}
		return err
	}
	go func() {
		defer m.Close()
		if server != nil {
			defer server.Close()
		}
		m.watchConfig(ctx, cfg, path)
	}()
	return nil
}

func (m *Manager) watchConfig(ctx context.Context, cfg config.DynamicInstrumentationConfig, path string) {
	ticker := time.NewTicker(cfg.WatchInterval)
	defer ticker.Stop()
	var previous [sha256.Size]byte
	rules := cfg.Rules
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		m.RefreshMatches()
		if path == "" {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			slog.Warn("reading dynamic instrumentation config", "error", err)
			continue
		}
		sum := sha256.Sum256(data)
		if sum == previous {
			continue
		}
		previous = sum
		next, err := dynamicRules(data, cfg)
		if err != nil {
			slog.Warn("keeping dynamic instrumentation rules after invalid config reload", "error", err)
			continue
		}
		if reflect.DeepEqual(rules, next) {
			continue
		}
		if err := m.SetConfigRules(next); err != nil {
			slog.Warn("reconciling dynamic instrumentation config", "error", err)
			continue
		}
		rules = next
	}
}

func dynamicRules(data []byte, defaults config.DynamicInstrumentationConfig) ([]config.DynamicInstrumentationRule, error) {
	var document yaml.Node
	if err := decodeRuleJSON(config.ReplaceEnv(data), &document); err != nil {
		return nil, err
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("config must be a YAML mapping")
	}
	mapping := document.Content[0].Content
	keys := map[string]bool{}
	for i := 0; i < len(mapping); i += 2 {
		key := mapping[i].Value
		if keys[key] {
			return nil, fmt.Errorf("duplicate config key %q", key)
		}
		keys[key] = true
	}
	for i := 0; i < len(mapping); i += 2 {
		if mapping[i].Value != "dynamic_instrumentation" {
			continue
		}
		defaults.Rules = nil
		encoded, err := yaml.Marshal(mapping[i+1])
		if err != nil {
			return nil, err
		}
		decoder := yaml.NewDecoder(bytes.NewReader(encoded))
		decoder.KnownFields(true)
		if err := decoder.Decode(&defaults); err != nil {
			return nil, err
		}
		if err := defaults.Validate(); err != nil {
			return nil, err
		}
		return defaults.Rules, nil
	}
	return nil, nil
}
