// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sqlprune

import (
	"reflect"
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

func getTableNames(v reflect.Value, tables []string, level int, isTable bool) []string {
	switch v.Kind() {
	case reflect.Struct:
		if v.Type().Name() == "TableIdent" {
			// if this is a TableIdent struct, extract the table name
			tableName := v.FieldByName("v").String()
			if tableName != "" && isTable {
				tables = append(tables, tableName)
			}
		} else {
			// otherwise enumerate all fields of the struct and process further
			for i := 0; i < v.NumField(); i++ {
				tables = getTableNames(reflect.Indirect(v.Field(i)), tables, level+1, isTable)
			}
		}
	case reflect.Array, reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			// enumerate all elements of an array/slice and process further
			tables = getTableNames(reflect.Indirect(v.Index(i)), tables, level+1, isTable)
		}
	case reflect.Interface:
		if v.Type().Name() == "SimpleTableExpr" {
			isTable = true
		}
		// get the actual object that satisfies an interface and process further
		tables = getTableNames(reflect.Indirect(reflect.ValueOf(v.Interface())), tables, level+1, isTable)
	}

	return tables
}

func SQLParseOperationAndTableNEW(query string) (string, string) {
	stmt, err := sqlparser.Parse(query)
	if err != nil {
		return SQLParseOperationAndTable(query)
	}

	var tables []string
	tables = getTableNames(reflect.Indirect(reflect.ValueOf(stmt)), tables, 0, false)

	return "SELECT", tables[0]
}

func SQLParseError(kind request.SQLKind, buf []uint8) *request.SQLError {
	var sqlErr *request.SQLError

	switch kind {
	case request.DBMySQL:
		sqlErr = parseMySQLError(buf)
	case request.DBPostgres:
		sqlErr = parsePostgresError(buf)
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
