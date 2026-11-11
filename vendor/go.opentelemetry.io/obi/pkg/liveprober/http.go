// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package liveprober // import "go.opentelemetry.io/obi/pkg/liveprober"

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

func (m *Manager) Handler() http.Handler {
	mux := http.NewServeMux()
	m.dynamicRoutes(mux)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /v1/probes", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"probes": m.Snapshot()})
	})
	mux.HandleFunc("PUT /v1/probes/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		var spec ProbeSpec
		dec := json.NewDecoder(io.LimitReader(r.Body, 65537))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&spec); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		var extra any
		if err := dec.Decode(&extra); err != io.EOF {
			writeError(w, http.StatusBadRequest, errors.New("expected one probe JSON object"))
			return
		}
		state, err := m.Apply(id, spec)
		if err != nil {
			status := http.StatusUnprocessableEntity
			switch {
			case errors.Is(err, ErrConflict):
				status = http.StatusConflict
			case errors.Is(err, ErrNotReady):
				status = http.StatusServiceUnavailable
			case errors.Is(err, ErrTargetGone):
				status = http.StatusConflict
			}
			writeError(w, status, err)
			return
		}
		writeJSON(w, http.StatusOK, state)
	})
	mux.HandleFunc("DELETE /v1/probes/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" || strings.ContainsAny(id, "/\\") {
			writeError(w, http.StatusBadRequest, errors.New("invalid probe ID"))
			return
		}
		if err := m.Delete(id); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
