// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package weavercheck holds the transport-agnostic parsing and validation of
// the OpenTelemetry weaver live-check report. Both the Docker-Compose
// integration suites (package integration) and the Kubernetes / kind suites
// (package kube) feed weaver the same OTLP stream and read back the same JSON
// report; this package owns the shared report schema, the ignore lists, and
// the advisory-accounting + assertion logic so the two transports stay in
// lockstep.
//
// The transports differ only in HOW they stop weaver and obtain the raw
// report bytes (docker exec + host bind mount vs. HTTP /stop on a kind host
// port + the shared testoutput mount); everything from "parse the bytes" on
// is here.
package weavercheck // import "go.opentelemetry.io/obi/internal/test/weavercheck"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestingT is the minimal test-reporter interface Validate needs. Both
// *testing.T (the Docker and Kubernetes suites) and ginkgo.GinkgoT() (the OATS
// suites) satisfy it, so the exact same enforce logic runs across every
// transport rather than being reimplemented per suite.
type TestingT interface {
	Helper()
	Logf(format string, args ...any)
	Errorf(format string, args ...any)
	FailNow()
}

// IgnoredSignals is an escape hatch for advice we explicitly suppress without
// declaring the underlying signal in the OBI registry. The harness fails on
// `violation`-level advice AND on `extends_namespace` advice (an attribute
// emitted under an existing semconv namespace but not declared in any
// registry). Most non-semconv emissions (Prometheus `target_info`,
// OTel-contrib spanmetrics / service-graph shape, OBI-internal markers) are
// declared in `schemas/obi/` and validated against by weaver, so this map is
// intended to stay small. Add entries here only as a short-lived bridge while
// OBI catches up to a semconv contract. Keys are "signal_type:signal_name".
var IgnoredSignals = map[string]struct{}{}

// IgnoredAdviceMessages suppresses specific advice messages that match known
// structural tensions weaver reports against the registry as a whole rather
// than against any one signal. Today this only covers the `server` / `client`
// namespace collision: the OTel collector-contrib `servicegraphconnector`
// emits bare `server` / `client` labels (matched in `service_graph.yaml`), but
// upstream semconv reserves `server.*` / `client.*` as namespace prefixes
// (`server.address`, `server.port`, …). Weaver's lint flags the registry-level
// collision on every signal that touches an upstream `server.*` / `client.*`
// attribute, even ones that don't use the bare label. The contract OBI emits
// is fixed by the connector convention; the ignore documents the tension.
var IgnoredAdviceMessages = map[string]struct{}{
	"Namespace 'server' collides with existing attribute 'server.address'": {},
	"Namespace 'server' collides with existing attribute 'server.port'":    {},
	"Namespace 'client' collides with existing attribute 'client.address'": {},
	"Namespace 'client' collides with existing attribute 'client.port'":    {},
	// OBI emits `iface` (interface name) alongside `iface.direction`, so
	// `iface` is both a leaf attribute *and* the namespace of another. The
	// emission contract is owned by netolly, mirrors the older network-flow
	// exporter convention, and is not negotiable for backward compatibility —
	// accept the structural warning.
	"Namespace 'iface' collides with existing attribute 'iface.direction'": {},
}

// actionableAdviceTypes lists the weaver finding-type values OBI treats as
// failures in addition to `violation`-level advice. Hoisted here (rather than
// matched as an inline string literal) so the coupling to weaver's advice-type
// vocabulary lives in one documented place and is easy to extend.
//
//   - "extends_namespace": an attribute emitted under an existing semconv
//     namespace but declared in no registry (upstream semconv or
//     `schemas/obi/`). Weaver classifies these as `information`-level, so
//     without this they would silently pass; OBI requires every emitted
//     attribute to be declared.
//
// NOTE: these strings come from weaver's rego policy output. If a weaver
// version bump renames them, enforcement silently weakens — re-verify when
// bumping the pinned weaver image.
var actionableAdviceTypes = map[string]struct{}{
	"extends_namespace": {},
}

// Report is the top-level JSON structure emitted by weaver with --format json.
type Report struct {
	Samples    []json.RawMessage `json:"samples"`
	Statistics Statistics        `json:"statistics"`
}

type Statistics struct {
	TotalEntities       int            `json:"total_entities"`
	TotalEntitiesByType map[string]int `json:"total_entities_by_type"`
	TotalAdvisories     int            `json:"total_advisories"`
	AdviceLevelCounts   map[string]int `json:"advice_level_counts"`
	AdviceTypeCounts    map[string]int `json:"advice_type_counts"`
	AdviceMessageCounts map[string]int `json:"advice_message_counts"`
	RegistryCoverage    float64        `json:"registry_coverage"`
}

// Advice represents a single advisory finding from the weaver report.
type Advice struct {
	Message    string `json:"message"`
	Level      string `json:"level"`
	AdviceType string `json:"id"`
	SignalType string `json:"signal_type"`
	SignalName string `json:"signal_name"`
}

type liveCheckResult struct {
	AllAdvice []Advice `json:"all_advice"`
}

type adviceInfo struct {
	Level      string
	AdviceType string
	Signals    map[string]struct{} // set of "signal_type:signal_name"
}

// Parse unmarshals a raw weaver JSON report.
func Parse(rawReport []byte) (*Report, error) {
	if len(rawReport) == 0 {
		return nil, errors.New("weaver report is empty")
	}
	var report Report
	if err := json.Unmarshal(rawReport, &report); err != nil {
		return nil, fmt.Errorf("parsing weaver JSON report: %w", err)
	}
	return &report, nil
}

// FetchReport stops the weaver live-check container via its admin /stop
// endpoint and returns the parsed report once weaver has flushed it to
// reportPath. It is transport-agnostic and logging-agnostic (returns an error
// rather than failing a test), so any transport that publishes weaver's admin
// port to the host and mounts its report file can reuse it.
func FetchReport(ctx context.Context, adminURL, reportPath string) (*Report, error) {
	// A previous test in the same process may have left an older report at
	// reportPath (weaver writes it as root, so we can't delete it here).
	// Snapshot its mtime so waitForReport only accepts a report written
	// after this /stop.
	var prevMod time.Time
	if fi, err := os.Stat(reportPath); err == nil {
		prevMod = fi.ModTime()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, adminURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building weaver /stop request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("stopping weaver (is it running and the admin port mapped?): %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("weaver /stop returned HTTP %d", resp.StatusCode)
	}
	raw, err := waitForReport(ctx, reportPath, prevMod)
	if err != nil {
		return nil, err
	}
	return Parse(raw)
}

// waitForReport polls reportPath until it holds a report newer than prevMod,
// is non-empty, and its size is stable across two ticks — so neither a stale
// report from an earlier test nor a still-flushing one is read — or ctx
// expires.
func waitForReport(ctx context.Context, reportPath string, prevMod time.Time) ([]byte, error) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var lastSize int64 = -1
	for {
		if fi, err := os.Stat(reportPath); err == nil && fi.Size() > 0 && fi.ModTime().After(prevMod) {
			if fi.Size() == lastSize {
				return os.ReadFile(reportPath)
			}
			lastSize = fi.Size()
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("weaver report %s not ready: %w", reportPath, ctx.Err())
		case <-ticker.C:
		}
	}
}

// Validate logs the full advisory breakdown and asserts that zero actionable
// advisories remain. An advisory is actionable when it is `violation`-level OR
// its advice_type is in actionableAdviceTypes, after applying the ignore lists.
// It always enforces: if weaver found actionable advisories, the test fails.
func Validate(t TestingT, report *Report) {
	t.Helper()

	stats := &report.Statistics

	// Weaver must have received telemetry data.
	require.NotEmptyf(t, report.Samples,
		"weaver received no samples — OTLP data did not reach weaver")

	violations := stats.AdviceLevelCounts["violation"]

	t.Logf("weaver statistics:")
	t.Logf("  total entities:   %d", stats.TotalEntities)
	for typ, count := range stats.TotalEntitiesByType {
		t.Logf("    %-15s %d", typ, count)
	}
	t.Logf("  total advisories: %d", stats.TotalAdvisories)
	for level, count := range stats.AdviceLevelCounts {
		t.Logf("    %-15s %d", level, count)
	}
	t.Logf("  registry coverage: %.1f%%", stats.RegistryCoverage*100)

	// Build message → {level, type, signals} lookup from the sample data.
	adviceByMsg := collectAdviceInfo(report.Samples)

	// Log all advisory messages grouped by level.
	t.Logf("  advisory details:")
	for _, level := range []string{"violation", "improvement", "information"} {
		for msg, count := range stats.AdviceMessageCounts {
			_, msgIgnored := IgnoredAdviceMessages[msg]
			info := adviceByMsg[msg]
			if info == nil {
				if level != "violation" {
					continue
				}

				suffix := ""
				if msgIgnored {
					suffix = " [ignored]"
				}
				t.Logf("    [%s] [%dx] %s (signals: unknown)%s", level, count, msg, suffix)
				continue
			}
			if info.Level != level {
				continue
			}
			signals := sortedSignals(info.Signals)
			ignored := msgIgnored || allSignalsIgnored(info.Signals)
			suffix := ""
			if ignored {
				suffix = " [ignored]"
			}
			t.Logf("    [%s] [%dx] %s (signals: %s)%s", level, count, msg, strings.Join(signals, ", "), suffix)
		}
	}

	actionableAdvisories := countActionableAdvisories(stats, adviceByMsg)
	t.Logf("  advisories: %d violation(s), %d actionable (violations + actionableAdviceTypes, after ignoring %v)",
		violations, actionableAdvisories, sortedSignals(IgnoredSignals))

	assert.Zero(t, actionableAdvisories,
		"weaver found %d actionable semantic convention advisory(ies) "+
			"(violations or undeclared attributes under existing semconv namespaces)", actionableAdvisories)
}

// isActionableAdvice reports whether an advisory at the given level and
// advice type must fail validation: `violation`-level advice always is, and
// so is any advice type listed in actionableAdviceTypes (e.g.
// `extends_namespace`, which weaver classifies as information-level).
func isActionableAdvice(level, adviceType string) bool {
	if level == "violation" {
		return true
	}

	_, actionable := actionableAdviceTypes[adviceType]
	return actionable
}

// countActionableAdvisories counts advisories that must fail validation,
// excluding signals listed in IgnoredSignals and messages listed in
// IgnoredAdviceMessages. Messages present in the statistics but absent from
// the sample data carry no level/type/signal attribution, so they are
// conservatively counted as actionable unless message-ignored.
func countActionableAdvisories(stats *Statistics, adviceByMsg map[string]*adviceInfo) int {
	var count int
	for msg, occurrences := range stats.AdviceMessageCounts {
		_, messageIgnored := IgnoredAdviceMessages[msg]
		info := adviceByMsg[msg]
		if info == nil {
			if !messageIgnored {
				count += occurrences
			}
			continue
		}
		ignored := messageIgnored || allSignalsIgnored(info.Signals)
		if isActionableAdvice(info.Level, info.AdviceType) && !ignored {
			count += occurrences
		}
	}
	return count
}

// collectAdviceInfo scans all weaver samples to build a complete map from
// advisory message to its severity level, advice type, and the set of signals
// that triggered it.
func collectAdviceInfo(samples []json.RawMessage) map[string]*adviceInfo {
	result := make(map[string]*adviceInfo)

	for _, raw := range samples {
		var generic map[string]json.RawMessage
		if json.Unmarshal(raw, &generic) != nil {
			continue
		}
		for _, v := range generic {
			extractAdviceInfo(v, result)
		}
	}

	return result
}

// extractAdviceInfo recursively walks JSON looking for all_advice arrays and
// records message → {level, type, signals} mappings.
func extractAdviceInfo(data json.RawMessage, result map[string]*adviceInfo) {
	// Try as object with live_check_result or nested fields.
	var obj map[string]json.RawMessage
	if json.Unmarshal(data, &obj) == nil {
		if lcr, ok := obj["live_check_result"]; ok {
			var checkResult liveCheckResult
			if json.Unmarshal(lcr, &checkResult) == nil {
				for i := range checkResult.AllAdvice {
					a := &checkResult.AllAdvice[i]
					info, exists := result[a.Message]
					if !exists {
						info = &adviceInfo{
							Level:      a.Level,
							AdviceType: a.AdviceType,
							Signals:    make(map[string]struct{}),
						}
						result[a.Message] = info
					}
					if a.SignalName != "" {
						sig := a.SignalType + ":" + a.SignalName
						info.Signals[sig] = struct{}{}
					}
				}
			}
		}
		// Recurse into all values.
		for _, v := range obj {
			extractAdviceInfo(v, result)
		}
		return
	}

	// Try as array.
	var arr []json.RawMessage
	if json.Unmarshal(data, &arr) == nil {
		for _, item := range arr {
			extractAdviceInfo(item, result)
		}
	}
}

// allSignalsIgnored returns true if every signal in the set is in IgnoredSignals.
func allSignalsIgnored(signals map[string]struct{}) bool {
	if len(signals) == 0 {
		return false
	}
	for sig := range signals {
		if _, ignored := IgnoredSignals[sig]; !ignored {
			return false
		}
	}
	return true
}

func sortedSignals(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
