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
	tokens := sqlparser.NewTokenizer(strings.NewReader(query))
	for tokenType, data := tokens.Scan(); tokenType != 0; tokenType, data = tokens.Scan() {
		if operation == "" && tokenIsDBOperation[tokenType] {
			operation = strings.ToUpper(string(data[:]))
		}
		if table == "" && tokenType == sqlparser.ID {
			table = string(data[:])
			break
		}
	}
	return operation, table
}
