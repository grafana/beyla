// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sqlprune // import "go.opentelemetry.io/obi/pkg/internal/sqlprune"

import (
	"strings"

	"github.com/DataDog/go-sqllexer"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

type sqlDialect struct {
	dbms                    sqllexer.DBMSType
	questionPlaceholders    bool
	dollarPlaceholders      bool
	namedDollarPlaceholders bool
	mysqlComments           bool
	executableComments      bool
	hashComments            bool
	doubleQuotedStrings     bool
	moneyLiterals           bool
	ambiguousQuoting        bool
}

var sqlppDialect = sqlDialect{
	dbms:                    sqllexer.DBMSMySQL,
	questionPlaceholders:    true,
	dollarPlaceholders:      true,
	namedDollarPlaceholders: true,
	mysqlComments:           true,
	executableComments:      true,
}

func dialectFor(kind request.SQLKind) sqlDialect {
	switch kind {
	case request.DBPostgres:
		return sqlDialect{dbms: sqllexer.DBMSPostgres, dollarPlaceholders: true}
	case request.DBMSSQL:
		return sqlDialect{dbms: sqllexer.DBMSSQLServer, doubleQuotedStrings: true, moneyLiterals: true}
	case request.DBMySQL:
		return sqlDialect{
			dbms:                 sqllexer.DBMSMySQL,
			questionPlaceholders: true,
			mysqlComments:        true,
			executableComments:   true,
			hashComments:         true,
		}
	default:
		return sqlDialect{
			dbms:                sqllexer.DBMSPostgres,
			dollarPlaceholders:  true,
			doubleQuotedStrings: true,
			executableComments:  true,
			ambiguousQuoting:    true,
		}
	}
}

var obfuscator = sqllexer.NewObfuscator(
	sqllexer.WithReplaceDigits(false),
	sqllexer.WithReplaceBoolean(true),
	sqllexer.WithReplaceNull(true),
)

var executableCommentMarkers = []string{"/*!", "/*M!", "/*+"}

func SanitizeSQL(query string, kind request.SQLKind) string {
	return sanitize(query, dialectFor(kind))
}

func SanitizeSQLPP(query string) string {
	return sanitize(query, sqlppDialect)
}

func sanitize(query string, d sqlDialect) string {
	tokens, ok := tokenize(query, d)
	if !ok || hasAmbiguousQuoting(tokens, d) {
		return ""
	}

	parameterized := hasPlaceholder(tokens, d)
	if parameterized && !hasStringLiteral(tokens, d) {
		return query
	}

	sanitized := replaceLiterals(tokens, d, parameterized)
	if hasLiteral(sanitized, d) {
		return ""
	}
	return sanitized
}

func replaceLiterals(tokens []sqllexer.Token, d sqlDialect, parameterized bool) string {
	var out strings.Builder
	for i := range tokens {
		tok := &tokens[i]
		switch {
		case isStringLiteral(tok, d):
			out.WriteString(sqllexer.StringPlaceholder)
			continue
		case parameterized:
		case isMoneyLiteral(tok, d):
			out.WriteString(sqllexer.NumberPlaceholder)
			continue
		default:
			obfuscator.ObfuscateTokenValue(tok, nil, sqllexer.WithDBMS(d.dbms))
		}
		out.WriteString(tok.Value)
	}
	return out.String()
}

func hasLiteral(query string, d sqlDialect) bool {
	tokens, ok := tokenize(query, d)
	return !ok || hasStringLiteral(tokens, d)
}

func tokenize(query string, d sqlDialect) ([]sqllexer.Token, bool) {
	var tokens []sqllexer.Token
	offset := 0
	lexer := sqllexer.New(query, sqllexer.WithDBMS(d.dbms))
	for {
		tok := lexer.Scan()
		if tok.Type == sqllexer.EOF {
			return mergeNumberSuffixes(tokens), true
		}

		if head, split := splitToken(query[offset:], tok, d); split {
			tokens = append(tokens, head)
			offset += len(head.Value)
			lexer = sqllexer.New(query[offset:], sqllexer.WithDBMS(d.dbms))
			continue
		}

		consumed, ok := sourceLength(query[offset:], tok.Value)
		if !ok {
			return nil, false
		}
		offset += consumed
		tokens = append(tokens, *tok)
	}
}

func splitToken(rest string, tok *sqllexer.Token, d sqlDialect) (sqllexer.Token, bool) {
	switch {
	case d.namedDollarPlaceholders && isDollarToken(tok):
		return dollarToken(rest), true
	case d.mysqlComments && isDashesWithoutSpace(tok):
		return sqllexer.Token{Type: sqllexer.OPERATOR, Value: "-"}, true
	case !d.hashComments && tok.Type == sqllexer.COMMENT && strings.HasPrefix(tok.Value, "#"):
		return sqllexer.Token{Type: sqllexer.OPERATOR, Value: "#"}, true
	case d.executableComments:
		if prefix, ok := executableCommentPrefix(tok); ok {
			return sqllexer.Token{Type: sqllexer.COMMENT, Value: prefix}, true
		}
	}
	return sqllexer.Token{}, false
}

func isDashesWithoutSpace(tok *sqllexer.Token) bool {
	const dashes = "--"
	if tok.Type != sqllexer.COMMENT || !strings.HasPrefix(tok.Value, dashes) || len(tok.Value) == len(dashes) {
		return false
	}
	next := tok.Value[len(dashes)]
	return next > ' ' && next != '\x7f'
}

func executableCommentPrefix(tok *sqllexer.Token) (string, bool) {
	if tok.Type != sqllexer.MULTILINE_COMMENT && tok.Type != sqllexer.ERROR {
		return "", false
	}
	for _, marker := range executableCommentMarkers {
		if strings.HasPrefix(tok.Value, marker) {
			version := strings.TrimLeft(tok.Value[len(marker):], "0123456789")
			return tok.Value[:len(tok.Value)-len(version)], true
		}
	}
	return "", false
}

func sourceLength(rest, value string) (int, bool) {
	if strings.HasPrefix(rest, value) {
		return len(value), true
	}

	i, j := 0, 0
	for j < len(value) {
		switch {
		case i >= len(rest):
			return 0, false
		case rest[i] == value[j]:
			i++
			j++
		case isSpace(rest[i]):
			i++
		default:
			return 0, false
		}
	}
	return i, true
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

func mergeNumberSuffixes(tokens []sqllexer.Token) []sqllexer.Token {
	merged := tokens[:0]
	for _, tok := range tokens {
		if last := len(merged) - 1; last >= 0 && merged[last].Type == sqllexer.NUMBER &&
			tok.Value != "" && isNameChar(tok.Value[0], false) {
			merged[last].Value += tok.Value
			continue
		}
		merged = append(merged, tok)
	}
	return merged
}

func isDollarToken(tok *sqllexer.Token) bool {
	return tok.Type != sqllexer.POSITIONAL_PARAMETER && strings.HasPrefix(tok.Value, "$")
}

func dollarToken(rest string) sqllexer.Token {
	end := len("$")
	for end < len(rest) && isNameChar(rest[end], end == len("$")) {
		end++
	}
	if end == len("$") {
		return sqllexer.Token{Type: sqllexer.UNKNOWN, Value: rest[:end]}
	}
	return sqllexer.Token{Type: sqllexer.BIND_PARAMETER, Value: rest[:end]}
}

func isNameChar(c byte, first bool) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || c == '_' || (!first && '0' <= c && c <= '9')
}

func hasPlaceholder(tokens []sqllexer.Token, d sqlDialect) bool {
	bracketDepth := 0
	for i := range tokens {
		tok := &tokens[i]
		switch tok.Type {
		case sqllexer.POSITIONAL_PARAMETER:
			if d.dollarPlaceholders {
				return true
			}
		case sqllexer.BIND_PARAMETER:
			if !strings.HasPrefix(tok.Value, "@") {
				return true
			}
		case sqllexer.PUNCTUATION:
			bracketDepth += bracketDelta(tok.Value)
		case sqllexer.OPERATOR:
			if d.questionPlaceholders && strings.HasSuffix(tok.Value, "?") {
				return true
			}
			if bracketDepth <= 0 && isNamedColonParameter(tokens, i) {
				return true
			}
		}
	}
	return false
}

func bracketDelta(punctuation string) int {
	switch punctuation {
	case "[":
		return 1
	case "]":
		return -1
	}
	return 0
}

func isNamedColonParameter(tokens []sqllexer.Token, i int) bool {
	value := tokens[i].Value
	if !strings.HasSuffix(value, ":") || strings.HasSuffix(value, "::") || i+1 >= len(tokens) {
		return false
	}
	return tokens[i+1].Type == sqllexer.IDENT
}

func hasStringLiteral(tokens []sqllexer.Token, d sqlDialect) bool {
	for i := range tokens {
		if isStringLiteral(&tokens[i], d) {
			return true
		}
	}
	return false
}

func isStringLiteral(tok *sqllexer.Token, d sqlDialect) bool {
	switch tok.Type {
	case sqllexer.STRING, sqllexer.INCOMPLETE_STRING, sqllexer.DOLLAR_QUOTED_STRING, sqllexer.DOLLAR_QUOTED_FUNCTION:
		return true
	case sqllexer.ERROR:
		return strings.HasPrefix(tok.Value, "$") || d.doubleQuotedStrings && strings.HasPrefix(tok.Value, `"`)
	case sqllexer.QUOTED_IDENT:
		return d.doubleQuotedStrings && strings.HasPrefix(tok.Value, `"`)
	}
	return false
}

func isMoneyLiteral(tok *sqllexer.Token, d sqlDialect) bool {
	return d.moneyLiterals && tok.Type == sqllexer.POSITIONAL_PARAMETER
}

func hasAmbiguousQuoting(tokens []sqllexer.Token, d sqlDialect) bool {
	if !d.ambiguousQuoting {
		return false
	}
	for i := range tokens {
		tok := &tokens[i]
		if !isStringLiteral(tok, d) || !startsWithQuote(tok.Value) {
			continue
		}
		if hasBackslashEscapedQuote(tok.Value) || i > 0 && isOracleQuotePrefix(tokens[i-1].Value) {
			return true
		}
	}
	return false
}

func startsWithQuote(literal string) bool {
	return strings.HasPrefix(literal, "'") || strings.HasPrefix(literal, `"`)
}

func hasBackslashEscapedQuote(literal string) bool {
	backslashes := 0
	for i := range len(literal) {
		switch literal[i] {
		case '\\':
			backslashes++
			continue
		case '\'', '"':
			if backslashes%2 == 1 {
				return true
			}
		}
		backslashes = 0
	}
	return false
}

func isOracleQuotePrefix(value string) bool {
	return strings.EqualFold(value, "q") || strings.EqualFold(value, "nq")
}
