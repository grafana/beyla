// Copyright Sam Xie
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package otelsql

import (
	"context"
	"database/sql/driver"

	"go.opentelemetry.io/otel/trace"
)

var (
	_ driver.Stmt              = (*otStmt)(nil)
	_ driver.StmtExecContext   = (*otStmt)(nil)
	_ driver.StmtQueryContext  = (*otStmt)(nil)
	_ driver.NamedValueChecker = (*otStmt)(nil)
)

type otStmt struct {
	driver.Stmt
	cfg config

	query  string
	otConn *otConn
}

func newStmt(stmt driver.Stmt, cfg config, query string, otConn *otConn) *otStmt {
	return &otStmt{
		Stmt:   stmt,
		cfg:    cfg,
		query:  query,
		otConn: otConn,
	}
}

func (s *otStmt) ExecContext(
	ctx context.Context, args []driver.NamedValue,
) (result driver.Result, err error) {
	method := MethodStmtExec
	onDefer := recordMetric(ctx, s.cfg.Instruments, s.cfg, method, s.query, args)

	defer func() {
		onDefer(err)
	}()

	var span trace.Span
	if filterSpan(ctx, s.cfg.SpanOptions, method, s.query, args) {
		ctx, span = createSpan(ctx, s.cfg, method, true, s.query, args)

		defer span.End()
		defer recordSpanErrorDeferred(span, s.cfg.SpanOptions, &err)
	}

	if execer, ok := s.Stmt.(driver.StmtExecContext); ok {
		return execer.ExecContext(ctx, args)
	}

	// StmtExecContext.ExecContext is not permitted to return ErrSkip. fall back to Exec.
	var dargs []driver.Value

	if dargs, err = namedValueToValue(args); err != nil {
		return nil, err
	}

	select {
	default:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	return s.Stmt.Exec(dargs) //nolint:staticcheck
}

func (s *otStmt) QueryContext(
	ctx context.Context, args []driver.NamedValue,
) (rows driver.Rows, err error) {
	method := MethodStmtQuery
	onDefer := recordMetric(ctx, s.cfg.Instruments, s.cfg, method, s.query, args)

	defer func() {
		onDefer(err)
	}()

	var span trace.Span

	var queryCtx context.Context
	if filterSpan(ctx, s.cfg.SpanOptions, method, s.query, args) {
		queryCtx, span = createSpan(ctx, s.cfg, method, true, s.query, args)
		defer span.End()
		defer recordSpanErrorDeferred(span, s.cfg.SpanOptions, &err)
	} else {
		queryCtx = ctx
	}

	if query, ok := s.Stmt.(driver.StmtQueryContext); ok {
		if rows, err = query.QueryContext(queryCtx, args); err != nil {
			return nil, err
		}
	} else {
		// StmtQueryContext.QueryContext is not permitted to return ErrSkip. fall back to Query.
		var dargs []driver.Value

		if dargs, err = namedValueToValue(args); err != nil {
			return nil, err
		}

		select {
		default:
		case <-ctx.Done():
			return nil, ctx.Err()
		}

		if rows, err = s.Stmt.Query(dargs); err != nil { //nolint:staticcheck
			return nil, err
		}
	}

	return newRows(ctx, rows, s.cfg), nil
}

func (s *otStmt) CheckNamedValue(namedValue *driver.NamedValue) error {
	namedValueChecker, ok := s.Stmt.(driver.NamedValueChecker)
	if !ok {
		// Fallback to the connection's named value checker.
		//
		// The [database/sql] package checks for value checkers in the following order,
		// stopping at the first found match: Stmt.NamedValueChecker, Conn.NamedValueChecker,
		// Stmt.ColumnConverter, [DefaultParameterConverter].
		//
		// Since otelsql implements the NamedValueChecker for both Stmt and Conn, the
		// fallback logic in the Go is not working.
		// Source: https://go.googlesource.com/go/+/refs/tags/go1.22.2/src/database/sql/convert.go#128
		//
		// This is a workaround to make sure the named value checker is checked on the connection level after
		// the statement level.
		return s.otConn.CheckNamedValue(namedValue)
	}

	return namedValueChecker.CheckNamedValue(namedValue)
}
