// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package liveprober // import "go.opentelemetry.io/obi/pkg/liveprober"

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"

	"gopkg.in/yaml.v3"

	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/config"
)

const maxRequestBytes = 64 << 10

func decodeRuleJSON(data []byte, value any) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("expected one request object")
	}
	return nil
}

func readRequest(w http.ResponseWriter, r *http.Request, value any) error {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBytes))
	if err != nil {
		return err
	}
	return decodeRuleJSON(data, value)
}

func (m *Manager) dynamicRoutes(mux *http.ServeMux) {
	apply := func(w http.ResponseWriter, r *http.Request) {
		var rule config.DynamicInstrumentationRule
		if err := readRequest(w, r, &rule); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		id := r.PathValue("id")
		if id == "" {
			data, _ := yaml.Marshal(rule)
			sum := sha256.Sum256(data)
			id = hex.EncodeToString(sum[:16])
		}
		if _, err := m.ApplyRule(id, rule); err != nil {
			writeError(w, http.StatusUnprocessableEntity, err)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), m.requestTimeout)
		defer cancel()
		var results []ProbeResult
		for {
			var updated <-chan struct{}
			results, updated = m.RuleResults(id)
			pending := false
			for _, result := range results {
				pending = pending || result.Status == "pending"
			}
			if !pending {
				break
			}
			select {
			case <-updated:
				continue
			case <-ctx.Done():
			}
			break
		}
		status := http.StatusOK
		for _, result := range results {
			if result.Status == "pending" {
				status = http.StatusAccepted
				break
			}
			if result.Status == "error" {
				status = http.StatusMultiStatus
			}
		}
		writeJSON(w, status, map[string]any{"id": id, "probes": results})
	}
	mux.HandleFunc("POST /v1/dynamic-instrumentation/probes", apply)
	mux.HandleFunc("PUT /v1/dynamic-instrumentation/rules/{id}", apply)
	mux.HandleFunc("DELETE /v1/dynamic-instrumentation/rules/{id}", func(w http.ResponseWriter, r *http.Request) {
		if err := m.DeleteRule(r.PathValue("id")); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /v1/dynamic-instrumentation/probes", func(w http.ResponseWriter, r *http.Request) {
		criteria, err := queryServiceCriteria(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"probes": m.ListFunctions(criteria)})
	})
	mux.HandleFunc("GET /v1/dynamic-instrumentation/symbols", func(w http.ResponseWriter, r *http.Request) {
		criteria, err := queryServiceCriteria(r)
		if err == nil && len(criteria) == 0 {
			err = errors.New("service selector is required")
		}
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), m.requestTimeout)
		defer cancel()
		results := m.ListSymbols(ctx, criteria)
		status := http.StatusOK
		for _, result := range results {
			if result.Error != "" {
				status = http.StatusMultiStatus
				break
			}
		}
		writeJSON(w, status, map[string]any{"processes": results})
	})
	mux.HandleFunc("DELETE /v1/dynamic-instrumentation/probes", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Service  services.GlobDefinitionCriteria `yaml:"service"`
			Function string                          `yaml:"function"`
		}
		if err := readRequest(w, r, &request); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := m.DeleteFunctions(request.Service, request.Function); err != nil {
			writeError(w, http.StatusUnprocessableEntity, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

func queryServiceCriteria(r *http.Request) (services.GlobDefinitionCriteria, error) {
	var criteria services.GlobDefinitionCriteria
	if raw := r.URL.Query().Get("service"); raw != "" {
		if err := decodeRuleJSON([]byte(raw), &criteria); err != nil {
			return nil, err
		}
	}
	return criteria, criteria.Validate()
}
