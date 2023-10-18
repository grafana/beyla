package sqlprune

import (
	"strings"

	"github.com/xwb1989/sqlparser"
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

func SQLParseOperationAndTable(query string) (string, string) {
	var operation, table string
	var lastType int
	tokens := sqlparser.NewTokenizer(strings.NewReader(query))
	for tokenType, data := tokens.Scan(); tokenType != 0; tokenType, data = tokens.Scan() {
		// Uncomment to run "go test -v" and print out token types and data:
		//debugSQLParseOperationAndTable(tokenType, data)
		if tokenType == sqlparser.LEX_ERROR {
			return operation, table
		}
		if operation == "" && tokenIsDBOperation[tokenType] {
			operation = strings.ToUpper(string(data[:]))
		}

		if tokenType == sqlparser.ID || tokenType == sqlparser.VALUE_ARG {
			switch lastType {
			case sqlparser.TABLE, sqlparser.FROM, sqlparser.INTO, sqlparser.UPDATE:
				if tokenType == sqlparser.VALUE_ARG {
					table = "?"
				} else {
					table = string(data[:])
				}
				return operation, table
			}
		}
		if tokenType != sqlparser.COMMENT {
			lastType = tokenType
		}
	}
	return operation, table
}
