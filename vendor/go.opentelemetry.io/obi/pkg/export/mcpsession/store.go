// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package mcpsession provides shared session tracking for MCP session-duration
// metrics used by both the OTel and Prometheus exporters.
package mcpsession // import "go.opentelemetry.io/obi/pkg/export/mcpsession"

import (
	"context"
	"sync"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
)

// Session captures the lifetime and error state of a single MCP session.
type Session struct {
	Start        time.Time
	LastSeen     time.Time
	Protocol     string
	Host         string
	Port         int
	ErrorStatus  int
	ErrorMCPCode int
	Client       bool
	Service      svc.Attrs
}

// Duration returns the session duration; the result is never negative.
func (s *Session) Duration() time.Duration {
	d := s.LastSeen.Sub(s.Start)
	if d < 0 {
		return 0
	}
	return d
}

// HasError reports whether the session ended with an error.
func (s *Session) HasError() bool {
	return s.ErrorStatus != 0 || s.ErrorMCPCode != 0
}

// SyntheticSpan builds a minimal request.Span that carries the attributes
// needed to record the session-duration histogram.
func (s *Session) SyntheticSpan() *request.Span {
	mcpCall := &request.MCPCall{ProtocolVer: s.Protocol}
	if s.HasError() {
		mcpCall.ErrorCode = s.ErrorMCPCode
	}

	spanType := request.EventTypeHTTP
	if s.Client {
		spanType = request.EventTypeHTTPClient
	}

	return &request.Span{
		Type:     spanType,
		SubType:  request.HTTPSubtypeMCP,
		Status:   s.ErrorStatus,
		Host:     s.Host,
		HostPort: s.Port,
		Service:  s.Service,
		GenAI: &request.GenAI{
			MCP: mcpCall,
		},
	}
}

// Store tracks open MCP client and server sessions and expires idle ones.
// Its methods are safe for concurrent use: sessions are recorded from the
// span-processing goroutine while the background expiry started by Start
// runs on its own.
type Store struct {
	mu             sync.Mutex
	clientSessions map[string]*Session
	serverSessions map[string]*Session
	lastGC         time.Time
	now            func() time.Time
}

// NewStore creates an empty session store.
func NewStore() *Store {
	return &Store{
		clientSessions: map[string]*Session{},
		serverSessions: map[string]*Session{},
		now:            time.Now,
	}
}

// SetNow overrides the clock used by Expire. It is intended for tests.
func (st *Store) SetNow(now func() time.Time) {
	st.now = now
}

// Record updates the session identified by key using the supplied span and
// timings. It is a no-op when the span is not an MCP session span.
func (st *Store) Record(key string, isClient bool, span *request.Span, t request.Timings) {
	mcp := span.MCP()
	if mcp == nil || mcp.SessionID == "" {
		return
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	sessions := st.serverSessions
	if isClient {
		sessions = st.clientSessions
	}

	sess, ok := sessions[key]
	if !ok {
		sess = &Session{
			Start:    t.RequestStart,
			LastSeen: t.End,
			Protocol: mcp.ProtocolVer,
			Host:     span.Host,
			Port:     span.HostPort,
			Client:   isClient,
			Service:  span.Service,
		}
		sessions[key] = sess
	} else {
		if t.RequestStart.Before(sess.Start) {
			sess.Start = t.RequestStart
		}
		if t.End.After(sess.LastSeen) {
			sess.LastSeen = t.End
		}
		sess.Service = span.Service
	}

	if request.SpanErrorType(span) != "" {
		sess.ErrorStatus = span.Status
		sess.ErrorMCPCode = mcp.ErrorCode
	} else {
		sess.ErrorStatus = 0
		sess.ErrorMCPCode = 0
	}
}

// Start periodically expires idle sessions until the context is canceled.
// It allows sessions to be closed and their duration histogram recorded
// even when no further MCP traffic arrives.
func (st *Store) Start(ctx context.Context, ttl time.Duration, closeFn func(*Session, bool)) {
	if ttl <= 0 {
		return
	}

	ticker := time.NewTicker(ttl)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			st.Expire(ttl, closeFn)
		}
	}
}

// Expire closes sessions that have been idle for at least ttl. The close
// callback receives the session and a boolean that is true for client sessions.
func (st *Store) Expire(ttl time.Duration, closeFn func(*Session, bool)) {
	st.mu.Lock()
	defer st.mu.Unlock()

	now := st.now()
	if now.Sub(st.lastGC) < ttl {
		return
	}
	st.lastGC = now

	for k, sess := range st.clientSessions {
		if now.Sub(sess.LastSeen) >= ttl {
			closeFn(sess, true)
			delete(st.clientSessions, k)
		}
	}
	for k, sess := range st.serverSessions {
		if now.Sub(sess.LastSeen) >= ttl {
			closeFn(sess, false)
			delete(st.serverSessions, k)
		}
	}
}

// CloseAll closes every tracked session and empties the store.
func (st *Store) CloseAll(closeFn func(*Session, bool)) {
	st.mu.Lock()
	defer st.mu.Unlock()

	for k, sess := range st.clientSessions {
		closeFn(sess, true)
		delete(st.clientSessions, k)
	}
	for k, sess := range st.serverSessions {
		closeFn(sess, false)
		delete(st.serverSessions, k)
	}
}
