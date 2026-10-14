// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sqlprune // import "go.opentelemetry.io/obi/pkg/internal/sqlprune"

import (
	"strings"

	"github.com/xwb1989/sqlparser"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

var tokenIsDBOperation = map[int]bool{
	sqlparser.SELECT:   true,
	sqlparser.STREAM:   true,
	sqlparser.INSERT:   true,
	sqlparser.UPDATE:   true,
	sqlparser.DELETE:   true,
	sqlparser.SET:      true,
	sqlparser.CREATE:   true,
	sqlparser.ALTER:    true,
	sqlparser.DROP:     true,
	sqlparser.ANALYZE:  true,
	sqlparser.RENAME:   true,
	sqlparser.SHOW:     true,
	sqlparser.USE:      true,
	sqlparser.DESCRIBE: true,
	sqlparser.EXPLAIN:  true,
	sqlparser.TRUNCATE: true,
	sqlparser.REPAIR:   true,
	sqlparser.OPTIMIZE: true,
	sqlparser.BEGIN:    true,
	sqlparser.START:    true,
	sqlparser.COMMIT:   true,
	sqlparser.ROLLBACK: true,
	sqlparser.REPLACE:  true,
}

// SQLTargetCollection reduces the tables referenced by a statement to the
// semconv db.collection.name: multi-collection SELECTs carry no collection,
// while writes always target the first table (INSERT INTO t1 SELECT FROM t2)
// Rule [3] from the db metrics says don't put the collection name if there is more
// than one table mentioned in the SQL statement.
// https://opentelemetry.io/docs/specs/semconv/db/database-metrics/#metric-dbclientoperationduration
func SQLTargetCollection(op string, tables []string) string {
	if len(tables) == 0 || (op == "SELECT" && len(tables) > 1) {
		return ""
	}
	return tables[0]
}

func SQLParseOperationAndTable(query string) (string, string) {
	op, tables := SQLParseOperationAndTables(query)
	return op, SQLTargetCollection(op, tables)
}

const maxQuerySummaryLen = 255

// SQLQuerySummary builds the semconv db.query.summary: the operation followed
// by its space-separated targets, truncated at a target boundary; empty when
// there are no targets so span naming can fall back to {op} {namespace}
func SQLQuerySummary(op string, tables []string) string {
	if op == "" || len(tables) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(op)
	appended := false
	for _, t := range tables {
		if sb.Len()+1+len(t) > maxQuerySummaryLen {
			break
		}
		sb.WriteByte(' ')
		sb.WriteString(t)
		appended = true
	}
	if !appended {
		return ""
	}
	return sb.String()
}

// SQLParseOperationAndTables returns the operation and the distinct table
// names referenced by the statement, in order of appearance
//
//nolint:cyclop
func SQLParseOperationAndTables(query string) (string, []string) {
	var operation string
	var lastType int
	var tables []string

	tokens := sqlparser.NewTokenizer(strings.NewReader(query))
	addedTable := false
	addMoreTables := false
	for tokenType, data := tokens.Scan(); tokenType != 0; tokenType, data = tokens.Scan() {
		if tokenType == sqlparser.LEX_ERROR {
			break
		}
		if operation == "" && tokenIsDBOperation[tokenType] {
			operation = strings.ToUpper(string(data))
		}

		if tokenType == 44 && addedTable { // a comma
			addMoreTables = true
			continue
		}

		if tokenType == 46 && addedTable { // a dot
			tokenType, data = tokens.Scan()
			// quoted identifiers ("Users") tokenize as STRING under the MySQL dialect
			if tokenType == sqlparser.ID || tokenType == sqlparser.STRING {
				tables[len(tables)-1] = tables[len(tables)-1] + "." + string(data)
				continue
			}
		}

		if tokenType == sqlparser.ID || tokenType == sqlparser.VALUE_ARG || tokenType == sqlparser.STRING {
			if lastType == sqlparser.TABLE || lastType == sqlparser.FROM || lastType == sqlparser.INTO ||
				lastType == sqlparser.UPDATE || lastType == sqlparser.JOIN || addMoreTables {
				if tokenType == sqlparser.VALUE_ARG {
					tables = append(tables, "?")
				} else {
					tables = append(tables, string(data))
				}
				addedTable = true
				addMoreTables = false
			}
		} else {
			addedTable = false
		}
		if tokenType != sqlparser.COMMENT {
			lastType = tokenType
		}
	}

	if len(tables) > 1 {
		seen := make(map[string]struct{}, len(tables))
		distinct := tables[:0]
		for _, t := range tables {
			if _, ok := seen[t]; ok {
				continue
			}
			seen[t] = struct{}{}
			distinct = append(distinct, t)
		}
		tables = distinct
	}

	return operation, tables
}

func SQLParseError(kind request.SQLKind, buf []uint8) *request.SQLError {
	var sqlErr *request.SQLError

	switch kind {
	case request.DBMySQL:
		sqlErr = parseMySQLError(buf)
	case request.DBPostgres:
		sqlErr = parsePostgresError(buf)
	case request.DBMSSQL:
		sqlErr = parseMSSQLError(buf)
	default:
		return nil // unsupported SQL kind
	}

	return sqlErr
}

func SQLParseCommandID(kind request.SQLKind, buf []byte) string {
	switch kind {
	case request.DBMySQL:
		return mysqlCommandIDToString(parseMySQLCommandID(buf))
	case request.DBPostgres:
		return postgresMessageTypeToString(parsePostgresMessageType(buf))
	case request.DBMSSQL:
		return mssqlCommandIDToString(parseMSSQLCommandID(buf))
	default:
		return ""
	}
}

func SQLParseStatementID(kind request.SQLKind, buf []byte) uint32 {
	switch kind {
	case request.DBMySQL:
		return mysqlParseStatementID(buf)
	default:
		return 0
	}
}
