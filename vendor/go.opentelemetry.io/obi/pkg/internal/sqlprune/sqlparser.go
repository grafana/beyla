// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sqlprune // import "go.opentelemetry.io/obi/pkg/internal/sqlprune"

import (
	"strings"
	"unicode"
	"unicode/utf8"

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

// SQLParseUseDatabase returns the database named by a single-statement USE, and
// whether the query starts with USE at all.
func SQLParseUseDatabase(query string) (string, bool) {
	tokens := sqlparser.NewStringTokenizer(query)

	if scanSkippingComments(tokens) != sqlparser.USE {
		return "", false
	}

	db, rest := cutDatabaseName(query[nextTokenOffset(tokens, query):])
	if db == "" {
		return "", true
	}

	tokens = sqlparser.NewStringTokenizer(rest)
	tokenType := scanSkippingComments(tokens)
	if tokenType == ';' {
		tokenType = scanSkippingComments(tokens)
	}
	if tokenType != 0 {
		return "", true
	}

	return db, true
}

func nextTokenOffset(tokens *sqlparser.Tokenizer, query string) int {
	for {
		offset := min(tokens.Position-1, len(query))
		if tokenType, _ := tokens.Scan(); tokenType != sqlparser.COMMENT {
			return offset
		}
	}
}

func cutDatabaseName(s string) (string, string) {
	s = strings.TrimLeftFunc(s, unicode.IsSpace)

	if strings.HasPrefix(s, "`") {
		tokens := sqlparser.NewStringTokenizer(s)
		tokenType, db := tokens.Scan()
		if tokenType != sqlparser.ID {
			return "", ""
		}
		return string(db), s[min(tokens.Position-1, len(s)):]
	}

	n := unquotedIdentifierLen(s)
	return s[:n], s[n:]
}

const maxUnquotedIdentifierRune = 0xFFFF

func unquotedIdentifierLen(s string) int {
	n := 0
	hasNonDigit := false
	for n < len(s) {
		r, size := utf8.DecodeRuneInString(s[n:])
		if r >= '0' && r <= '9' {
			n += size
			continue
		}
		if !isUnquotedIdentifierRune(r, size) {
			break
		}
		hasNonDigit = true
		n += size
	}

	if !hasNonDigit {
		return 0
	}
	return n
}

func isUnquotedIdentifierRune(r rune, size int) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '_', r == '$':
		return true
	case r == utf8.RuneError && size == 1:
		return false
	default:
		return r >= utf8.RuneSelf && r <= maxUnquotedIdentifierRune
	}
}

func scanSkippingComments(tokens *sqlparser.Tokenizer) int {
	tokenType, _ := tokens.Scan()
	for tokenType == sqlparser.COMMENT {
		tokenType, _ = tokens.Scan()
	}
	return tokenType
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
