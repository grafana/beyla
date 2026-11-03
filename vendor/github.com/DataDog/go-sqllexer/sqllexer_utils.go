package sqllexer

import (
	"strings"
	"unicode"
)

type DBMSType string

const (
	// DBMSSQLServer is a MS SQL
	DBMSSQLServer       DBMSType = "mssql"
	DBMSSQLServerAlias1 DBMSType = "sql-server" // .Net tracer
	DBMSSQLServerAlias2 DBMSType = "sqlserver"  // Java tracer
	// DBMSPostgres is a PostgreSQL Server
	DBMSPostgres       DBMSType = "postgresql"
	DBMSPostgresAlias1 DBMSType = "postgres" // Ruby, JavaScript tracers
	// DBMSMySQL is a MySQL Server
	DBMSMySQL DBMSType = "mysql"
	// DBMSOracle is a Oracle Server
	DBMSOracle DBMSType = "oracle"
	// DBMSSnowflake is a Snowflake Server
	DBMSSnowflake DBMSType = "snowflake"
)

var dbmsAliases = map[DBMSType]DBMSType{
	DBMSSQLServerAlias1: DBMSSQLServer,
	DBMSSQLServerAlias2: DBMSSQLServer,
	DBMSPostgresAlias1:  DBMSPostgres,
}

func getDBMSFromAlias(alias DBMSType) DBMSType {
	if canonical, exists := dbmsAliases[alias]; exists {
		return canonical
	}
	return alias
}

var commands = []string{
	"SELECT",
	"INSERT",
	"UPDATE",
	"DELETE",
	"CREATE",
	"ALTER",
	"DROP",
	"JOIN",
	"GRANT",
	"REVOKE",
	"COMMIT",
	"BEGIN",
	"TRUNCATE",
	"MERGE",
	"EXECUTE",
	"EXEC",
	"EXPLAIN",
	"STRAIGHT_JOIN",
	"USE",
	"CLONE",
	"VACUUM",
}

var tableIndicatorCommands = []string{
	"JOIN",
	"UPDATE",
	"STRAIGHT_JOIN", // MySQL
	"CLONE",         // Snowflake
}

var tableIndicatorKeywords = []string{
	"FROM",
	"INTO",
	"TABLE",
	"EXISTS", // Drop Table If Exists
	"ONLY",   // PostgreSQL
}

var keywords = []string{
	"ADD",
	"ALL",
	"AND",
	"ANY",
	"ASC",
	"BETWEEN",
	"BY",
	"CASE",
	"CHECK",
	"COLUMN",
	"CONSTRAINT",
	"DATABASE",
	"DECLARE",
	"DEFAULT",
	"DESC",
	"DISTINCT",
	"ELSE",
	"END",
	"ESCAPE",
	"EXISTS",
	"FOREIGN",
	"FROM",
	"GROUP",
	"HAVING",
	"IN",
	"INDEX",
	"INNER",
	"INTO",
	"IS",
	"KEY",
	"LATERAL",
	"LEFT",
	"LIKE",
	"LIMIT",
	"NOT",
	"ON",
	"OR",
	"ORDER",
	"OUT",
	"OUTER",
	"PRIMARY",
	"PROCEDURE",
	"REPLACE",
	"RETURNS",
	"RIGHT",
	"ROLLBACK",
	"ROWNUM",
	"SET",
	"SOME",
	"TABLE",
	"TOP",
	"UNION",
	"UNIQUE",
	"VALUES",
	"VIEW",
	"WHERE",
	"CUBE",
	"ROLLUP",
	"LITERAL",
	"WINDOW",
	"ANALYZE",
	"ILIKE",
	"USING",
	"ASSERTION",
	"DOMAIN",
	"CLUSTER",
	"COPY",
	"PLPGSQL",
	"TRIGGER",
	"TEMPORARY",
	"UNLOGGED",
	"RECURSIVE",
	"RETURNING",
	"OFFSET",
	"OF",
	"SKIP",
	"IF",
	"ONLY",
}

var (
	// Pre-defined constants for common values
	booleanValues = []string{
		"TRUE",
		"FALSE",
	}

	nullValues = []string{
		"NULL",
	}

	procedureNames = []string{
		"PROCEDURE",
		"PROC",
	}

	ctes = []string{
		"WITH",
	}

	alias = []string{
		"AS",
	}

	// extractFieldKeywords is the set of PostgreSQL EXTRACT field names
	// (https://www.postgresql.org/docs/current/functions-datetime.html#FUNCTIONS-DATETIME-EXTRACT).
	// They appear as unquoted identifiers in `EXTRACT(field FROM source)` and must be
	// obfuscated to a placeholder so signatures match the pg_stat_statements form
	// `EXTRACT($1 FROM source)`. Stored as a flat slice so isExtractFieldKeyword can
	// use strings.EqualFold without allocating a folded copy of the input.
	extractFieldKeywords = [...]string{
		"CENTURY",
		"DAY",
		"DECADE",
		"DOW",
		"DOY",
		"EPOCH",
		"HOUR",
		"ISODOW",
		"ISOYEAR",
		"JULIAN",
		"MICROSECONDS",
		"MILLENNIUM",
		"MILLISECONDS",
		"MINUTE",
		"MONTH",
		"QUARTER",
		"SECOND",
		"TIMEZONE",
		"TIMEZONE_HOUR",
		"TIMEZONE_MINUTE",
		"WEEK",
		"YEAR",
	}
)

// isExtractFieldKeyword reports whether value is a known PostgreSQL EXTRACT field
// keyword (case-insensitive).
func isExtractFieldKeyword(value string) bool {
	for _, kw := range extractFieldKeywords {
		if strings.EqualFold(value, kw) {
			return true
		}
	}
	return false
}

// extractContext tracks the two most recent non-whitespace, non-comment tokens
// so callers can detect when the current token is the field argument of an
// `EXTRACT(field FROM ...)` call. The zero value is ready to use.
type extractContext struct {
	prevType   TokenType
	prevValue  string
	prev2Type  TokenType
	prev2Value string
}

// maybeReplaceExtractField rewrites token.Value to StringPlaceholder when the
// token is the field argument of an EXTRACT(...) call (i.e. preceded by
// FUNCTION "EXTRACT" then PUNCTUATION "(") and matches a known field name.
// This converges the obfuscated form of `EXTRACT(epoch FROM x)` with the
// pg_stat_statements form `EXTRACT($1 FROM x)`.
func (c *extractContext) maybeReplaceExtractField(token *Token) {
	if token.Type != IDENT && token.Type != KEYWORD {
		return
	}
	if c.prevType != PUNCTUATION || c.prevValue != "(" {
		return
	}
	if c.prev2Type != FUNCTION || !strings.EqualFold(c.prev2Value, "EXTRACT") {
		return
	}
	if !isExtractFieldKeyword(token.Value) {
		return
	}
	token.Value = StringPlaceholder
}

// update advances the rolling window of recent tokens, ignoring whitespace and
// comments so they don't break the EXTRACT( ... ) adjacency check.
func (c *extractContext) update(token *Token) {
	if token.Type == SPACE || token.Type == COMMENT || token.Type == MULTILINE_COMMENT {
		return
	}
	c.prev2Type, c.prev2Value = c.prevType, c.prevValue
	c.prevType, c.prevValue = token.Type, token.Value
}

// trieNode represents a node in the keyword trie.
type trieNode struct {
	children         [27]*trieNode // 0-25 for A-Z, 26 for underscore
	isEnd            bool
	tokenType        TokenType
	isTableIndicator bool
}

// trieIndex returns the array index for a character (0-25 for A-Z, 26 for underscore).
// Returns -1 for invalid characters.
func trieIndex(ch rune) int {
	if ch >= 'A' && ch <= 'Z' {
		return int(ch - 'A')
	}
	if ch == '_' {
		return 26
	}
	return -1
}

// buildCombinedTrie combines all types of SQL keywords into a single trie
// This trie is used for efficient case-insensitive keyword matching during lexing
func buildCombinedTrie() *trieNode {
	root := &trieNode{}

	// Add all types of keywords
	addToTrie(root, commands, COMMAND, false)
	addToTrie(root, keywords, KEYWORD, false)
	addToTrie(root, tableIndicatorCommands, COMMAND, true)
	addToTrie(root, tableIndicatorKeywords, KEYWORD, true)
	addToTrie(root, booleanValues, BOOLEAN, false)
	addToTrie(root, nullValues, NULL, false)
	addToTrie(root, procedureNames, PROC_INDICATOR, false)
	addToTrie(root, ctes, CTE_INDICATOR, false)
	addToTrie(root, alias, ALIAS_INDICATOR, false)

	return root
}

func addToTrie(root *trieNode, words []string, tokenType TokenType, isTableIndicator bool) {
	for _, word := range words {
		node := root
		// Convert to uppercase for case-insensitive matching
		for _, ch := range strings.ToUpper(word) {
			idx := trieIndex(ch)
			if idx < 0 {
				// Skip characters that aren't valid trie indices
				continue
			}
			if next := node.children[idx]; next != nil {
				node = next
			} else {
				next := &trieNode{}
				node.children[idx] = next
				node = next
			}
		}
		node.isEnd = true
		node.tokenType = tokenType
		node.isTableIndicator = isTableIndicator
	}
}

var keywordRoot = buildCombinedTrie()

// TODO: Optimize these functions to work with rune positions instead of string operations
// They are currently used by obfuscator and normalizer, which we'll optimize later
func replaceDigits(token *Token, placeholder string) string {
	var replacedToken strings.Builder
	replacedToken.Grow(len(token.Value))

	var lastWasDigit bool
	for _, r := range token.Value {
		if isDigit(r) {
			if !lastWasDigit {
				replacedToken.WriteString(placeholder)
				lastWasDigit = true
			}
		} else {
			replacedToken.WriteRune(r)
			lastWasDigit = false
		}
	}

	return replacedToken.String()
}

func trimQuotes(token *Token) string {
	var trimmedToken strings.Builder
	trimmedToken.Grow(len(token.Value))

	for _, r := range token.Value {
		if isDoubleQuote(r) || r == '[' || r == ']' || r == '`' {
			// trimmedToken.WriteString(placeholder)
		} else {
			trimmedToken.WriteRune(r)
		}
	}
	token.hasQuotes = false
	return trimmedToken.String()
}

// isDigit checks if a rune is a digit (0-9)
func isDigit(ch rune) bool {
	return ch >= '0' && ch <= '9'
}

// isLeadingDigit checks if a rune is + or -
func isLeadingSign(ch rune) bool {
	return ch == '+' || ch == '-'
}

// isExponent checks if a rune is an exponent (e or E)
func isExpontent(ch rune) bool {
	return ch == 'e' || ch == 'E'
}

// isSpace checks if a rune is a space or newline
func isSpace(ch rune) bool {
	return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r'
}

// isAsciiLetter checks if a rune is an ASCII letter (a-z or A-Z)
func isAsciiLetter(ch rune) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
}

// isLetter checks if a rune is an ASCII letter (a-z or A-Z) or unicode letter
func isLetter(ch rune) bool {
	return isAsciiLetter(ch) || ch == '_' ||
		(ch > 127 && unicode.IsLetter(ch))
}

// isAlphaNumeric checks if a rune is an ASCII letter (a-z or A-Z), digit (0-9), or unicode number
func isAlphaNumeric(ch rune) bool {
	return isLetter(ch) || isDigit(ch) ||
		(ch > 127 && unicode.IsNumber(ch))
}

// isDoubleQuote checks if a rune is a double quote (")
func isDoubleQuote(ch rune) bool {
	return ch == '"'
}

// isSingleQuote checks if a rune is a single quote (')
func isSingleQuote(ch rune) bool {
	return ch == '\''
}

// isOperator checks if a rune is an operator
func isOperator(ch rune) bool {
	return ch == '+' || ch == '-' || ch == '*' || ch == '/' || ch == '=' || ch == '<' || ch == '>' ||
		ch == '!' || ch == '&' || ch == '|' || ch == '^' || ch == '%' || ch == '~' || ch == '?' ||
		ch == '@' || ch == ':' || ch == '#'
}

// isWildcard checks if a rune is a wildcard (*)
func isWildcard(ch rune) bool {
	return ch == '*'
}

// isSinglelineComment checks if two runes are a single line comment (--)
func isSingleLineComment(ch rune, nextCh rune) bool {
	return ch == '-' && nextCh == '-'
}

// isMultiLineComment checks if two runes are a multi line comment (/*)
func isMultiLineComment(ch rune, nextCh rune) bool {
	return ch == '/' && nextCh == '*'
}

// isPunctuation checks if a rune is a punctuation character
func isPunctuation(ch rune) bool {
	return ch == '(' || ch == ')' || ch == ',' || ch == ';' || ch == '.' || ch == ':' ||
		ch == '[' || ch == ']' || ch == '{' || ch == '}'
}

// isEOF checks if a rune is EOF (end of file)
func isEOF(ch rune) bool {
	return ch == 0
}

// isIdentifier checks if a rune is an identifier
func isIdentifier(ch rune) bool {
	return ch == '"' || ch == '.' || ch == '?' || ch == '$' || ch == '#' || ch == '/' || ch == '@' || ch == '!' || isLetter(ch) || isDigit(ch)
}

// isValueToken checks if a token is a value token
// A value token is a token that is not a space, comment, or EOF
func isValueToken(token *Token) bool {
	return token.Type != EOF && token.Type != SPACE && token.Type != COMMENT && token.Type != MULTILINE_COMMENT
}
