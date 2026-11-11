// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package liveprober // import "go.opentelemetry.io/obi/pkg/liveprober"

import (
	"context"
	"errors"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/services"
)

type ProcessSymbols struct {
	PID              int      `json:"pid"`
	ServiceName      string   `json:"service_name"`
	ServiceNamespace string   `json:"service_namespace"`
	Symbols          []string `json:"symbols"`
	Error            string   `json:"error,omitempty"`
}

type symbolQuery struct {
	result   ProcessSymbols
	resolver SymbolResolver
	identity processIdentity
}

func (m *Manager) symbolQueries(criteria services.GlobDefinitionCriteria) []symbolQuery {
	m.mu.Lock()
	defer m.mu.Unlock()
	var queries []symbolQuery
	for _, pid := range m.matchingPIDsLocked(criteria) {
		service := m.services[pid]
		query := symbolQuery{
			result:   ProcessSymbols{PID: pid, ServiceName: service.Name, ServiceNamespace: service.Namespace, Symbols: []string{}},
			resolver: m.symbols,
		}
		if bound, ok := m.targets[pid]; ok {
			query.identity = bound.identity
			if resolver, ok := bound.tracer.(SymbolResolver); ok {
				query.resolver = resolver
			}
		} else {
			var err error
			query.identity, err = m.identity(pid)
			if err != nil {
				query.result.Error = err.Error()
			}
		}
		queries = append(queries, query)
	}
	return queries
}

func (m *Manager) resolveSymbols(ctx context.Context, query symbolQuery) ProcessSymbols {
	result := query.result
	if result.Error != "" {
		return result
	}
	checkIdentity := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		identity, err := m.identity(result.PID)
		if err != nil {
			return err
		}
		if identity != query.identity {
			return ErrTargetGone
		}
		return nil
	}
	err := checkIdentity()
	if err == nil {
		if query.resolver == nil {
			err = errors.New("target cannot resolve symbols")
		} else {
			result.Symbols, err = query.resolver.ResolveLiveSymbols(app.PID(result.PID), "*")
		}
	}
	if err == nil {
		err = checkIdentity()
	}
	if err != nil {
		result.Symbols = []string{}
		result.Error = err.Error()
	}
	return result
}

func (m *Manager) ListSymbols(ctx context.Context, criteria services.GlobDefinitionCriteria) []ProcessSymbols {
	queries := m.symbolQueries(criteria)
	results := make([]ProcessSymbols, 0, len(queries))
	for _, query := range queries {
		results = append(results, m.resolveSymbols(ctx, query))
	}
	return results
}
