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

//nolint:cyclop
func SQLParseOperationAndTable(query string) (string, string) {
	var operation string
	var lastType int
	tables := []string{}

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
			if tokenType == sqlparser.ID {
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

	if len(tables) > 1 && operation != "SELECT" {
		tables = tables[:1]
	}

	return operation, strings.Join(tables, ",")
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
