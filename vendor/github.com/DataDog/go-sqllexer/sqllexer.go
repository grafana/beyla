package sqllexer

import (
	"strings"
	"unicode/utf8"
)

type TokenType int

const (
	ERROR TokenType = iota
	EOF
	SPACE                  // space or newline
	STRING                 // string literal
	INCOMPLETE_STRING      // incomplete string literal so that we can obfuscate it, e.g. 'abc
	NUMBER                 // number literal
	IDENT                  // identifier
	QUOTED_IDENT           // quoted identifier
	OPERATOR               // operator
	WILDCARD               // wildcard *
	COMMENT                // comment
	MULTILINE_COMMENT      // multiline comment
	PUNCTUATION            // punctuation
	DOLLAR_QUOTED_FUNCTION // dollar quoted function
	DOLLAR_QUOTED_STRING   // dollar quoted string
	POSITIONAL_PARAMETER   // numbered parameter
	BIND_PARAMETER         // bind parameter
	FUNCTION               // function
	SYSTEM_VARIABLE        // system variable
	UNKNOWN                // unknown token
	COMMAND                // SQL commands like SELECT, INSERT
	KEYWORD                // Other SQL keywords
	JSON_OP                // JSON operators
	BOOLEAN                // boolean literal
	NULL                   // null literal
	PROC_INDICATOR         // procedure indicator
	CTE_INDICATOR          // CTE indicator
	ALIAS_INDICATOR        // alias indicator
)

// Token represents a SQL token with its type and value.
type Token struct {
	Type               TokenType
	Value              string
	isTableIndicator   bool // true if the token is a table indicator
	hasDigits          bool
	hasQuotes          bool           // private - only used by trimQuotes
	isSimpleIdentifier bool           // true if quoted ident started with a letter and only used alphanumerics afterwards
	lastValueToken     LastValueToken // private - internal state
}

type LastValueToken struct {
	Type               TokenType
	Value              string
	isTableIndicator   bool
	isSimpleIdentifier bool
}

// getLastValueToken can be private since it's only used internally
func (t *Token) getLastValueToken() *LastValueToken {
	t.lastValueToken.Type = t.Type
	t.lastValueToken.Value = t.Value
	t.lastValueToken.isTableIndicator = t.isTableIndicator
	t.lastValueToken.isSimpleIdentifier = t.isSimpleIdentifier
	return &t.lastValueToken
}

type LexerConfig struct {
	DBMS DBMSType `json:"dbms,omitempty"`
}

type lexerOption func(*LexerConfig)

func WithDBMS(dbms DBMSType) lexerOption {
	dbms = getDBMSFromAlias(dbms)
	return func(c *LexerConfig) {
		c.DBMS = dbms
	}
}

// SQL Lexer inspired from Rob Pike's talk on Lexical Scanning in Go
type Lexer struct {
	src                string // the input src string
	cursor             int    // the current position of the cursor
	start              int    // the start position of the current token
	config             *LexerConfig
	token              *Token
	hasQuotes          bool // true if any quotes in token
	hasDigits          bool // true if the token has digits
	isTableIndicator   bool // true if the token is a table indicator
	isSimpleIdentifier bool // true if current quoted ident started with a letter and only used alphanumerics afterwards
}

func New(input string, opts ...lexerOption) *Lexer {
	lexer := &Lexer{
		src:    input,
		config: &LexerConfig{},
		token:  &Token{},
	}
	for _, opt := range opts {
		opt(lexer.config)
	}
	return lexer
}

// Scan scans the next token and returns it.
func (s *Lexer) Scan() *Token {
	ch := s.peek()
	switch {
	case isSpace(ch):
		return s.scanWhitespace()
	case isLetter(ch):
		return s.scanIdentifier(ch)
	case isDoubleQuote(ch):
		// MySQL by default (without ANSI_QUOTES mode) treats double quotes as string literals
		if s.config.DBMS == DBMSMySQL {
			return s.scanStringWithDelimiter('"')
		}
		return s.scanDoubleQuotedIdentifier('"')
	case isSingleQuote(ch):
		return s.scanStringWithDelimiter('\'')
	case isSingleLineComment(ch, s.lookAhead(1)):
		return s.scanSingleLineComment(ch)
	case isMultiLineComment(ch, s.lookAhead(1)):
		return s.scanMultiLineComment()
	case isLeadingSign(ch):
		// if the leading sign is followed by a digit, then it's a number
		// although this is not strictly true, it's good enough for our purposes
		nextCh := s.lookAhead(1)
		if isDigit(nextCh) || nextCh == '.' {
			return s.scanNumberWithLeadingSign()
		}
		return s.scanOperator(ch)
	case isDigit(ch):
		return s.scanNumber(ch)
	case isWildcard(ch):
		return s.scanWildcard()
	case ch == '$':
		if isDigit(s.lookAhead(1)) {
			// if the dollar sign is followed by a digit, then it's a numbered parameter
			return s.scanPositionalParameter()
		}
		if s.config.DBMS == DBMSSQLServer && isLetter(s.lookAhead(1)) {
			return s.scanIdentifier(ch)
		}
		return s.scanDollarQuotedString()
	case ch == ':':
		if s.config.DBMS == DBMSOracle && isAlphaNumeric(s.lookAhead(1)) {
			return s.scanBindParameter()
		}
		return s.scanOperator(ch)
	case ch == '`':
		if s.config.DBMS == DBMSMySQL {
			return s.scanDoubleQuotedIdentifier('`')
		}
		return s.scanUnknown() // backtick is only valid in mysql
	case ch == '#':
		if s.config.DBMS == DBMSSQLServer {
			return s.scanIdentifier(ch)
		} else if s.config.DBMS == DBMSMySQL {
			// MySQL treats # as a comment
			return s.scanSingleLineComment(ch)
		}
		return s.scanOperator(ch)
	case ch == '@':
		if s.lookAhead(1) == '@' {
			if isAlphaNumeric(s.lookAhead(2)) {
				return s.scanSystemVariable()
			}
			s.start = s.cursor
			s.nextBy(2) // consume @@
			return s.emit(JSON_OP)
		}
		if isAlphaNumeric(s.lookAhead(1)) {
			if s.config.DBMS == DBMSSnowflake {
				return s.scanIdentifier(ch)
			}
			return s.scanBindParameter()
		}
		if s.lookAhead(1) == '?' || s.lookAhead(1) == '>' {
			s.start = s.cursor
			s.nextBy(2) // consume @? or @>
			return s.emit(JSON_OP)
		}
		fallthrough
	case isOperator(ch):
		return s.scanOperator(ch)
	case isPunctuation(ch):
		if ch == '[' && s.config.DBMS == DBMSSQLServer {
			return s.scanDoubleQuotedIdentifier('[')
		}
		return s.scanPunctuation()
	case isEOF(ch):
		return s.emit(EOF)
	default:
		return s.scanUnknown()
	}
}

// lookAhead returns the rune n positions ahead of the cursor.
func (s *Lexer) lookAhead(n int) rune {
	pos := s.cursor + n
	if pos >= len(s.src) || pos < 0 {
		return 0
	}
	// Fast path for ASCII
	b := s.src[pos]
	if b < utf8.RuneSelf {
		return rune(b)
	}
	// Slow path for non-ASCII
	r, _ := utf8.DecodeRuneInString(s.src[pos:])
	return r
}

// peek returns the rune at the cursor position.
func (s *Lexer) peek() rune {
	return s.lookAhead(0)
}

// nextBy advances the cursor by n positions and returns the rune at the cursor position.
func (s *Lexer) nextBy(n int) rune {
	// advance the cursor by n and return the rune at the cursor position
	if s.cursor+n > len(s.src) {
		return 0
	}
	s.cursor += n
	if s.cursor >= len(s.src) {
		return 0
	}
	// Fast path for ASCII
	b := s.src[s.cursor]
	if b < utf8.RuneSelf {
		return rune(b)
	}
	// Slow path for non-ASCII
	r, _ := utf8.DecodeRuneInString(s.src[s.cursor:])
	return r
}

// next advances the cursor by 1 position and returns the rune at the cursor position.
func (s *Lexer) next() rune {
	return s.nextBy(1)
}

func (s *Lexer) matchAt(match []rune) bool {
	if s.cursor+len(match) > len(s.src) {
		return false
	}
	for i, ch := range match {
		if s.src[s.cursor+i] != byte(ch) {
			return false
		}
	}
	return true
}

func (s *Lexer) scanNumberWithLeadingSign() *Token {
	s.start = s.cursor
	ch := s.next() // consume the leading sign
	return s.scanDecimalNumber(ch)
}

func (s *Lexer) scanNumber(ch rune) *Token {
	s.start = s.cursor
	return s.scanNumberic(ch)
}

func (s *Lexer) scanNumberic(ch rune) *Token {
	s.start = s.cursor
	if ch == '0' {
		nextCh := s.lookAhead(1)
		if nextCh == 'x' || nextCh == 'X' {
			return s.scanHexNumber()
		} else if nextCh >= '0' && nextCh <= '7' {
			return s.scanOctalNumber()
		}
	}

	ch = s.next() // consume first digit
	return s.scanDecimalNumber(ch)
}

func (s *Lexer) scanDecimalNumber(ch rune) *Token {
	// scan digits
	for isDigit(ch) || ch == '.' || isExpontent(ch) {
		if isExpontent(ch) {
			ch = s.next()
			if isLeadingSign(ch) {
				ch = s.next()
			}
		} else {
			ch = s.next()
		}
	}
	return s.emit(NUMBER)
}

func (s *Lexer) scanHexNumber() *Token {
	ch := s.nextBy(2) // consume 0x or 0X

	for isDigit(ch) || ('a' <= ch && ch <= 'f') || ('A' <= ch && ch <= 'F') {
		ch = s.next()
	}
	return s.emit(NUMBER)
}

func (s *Lexer) scanOctalNumber() *Token {
	ch := s.nextBy(2) // consume the leading 0 and number

	for '0' <= ch && ch <= '7' {
		ch = s.next()
	}
	return s.emit(NUMBER)
}

func (s *Lexer) scanStringWithDelimiter(delimiter rune) *Token {
	s.start = s.cursor
	escaped := false
	escapedQuote := false
	backslashEscapes := s.stringBackslashEscapes()

	ch := s.next() // consume opening quote

	for ; !isEOF(ch); ch = s.next() {
		if escaped {
			escaped = false
			escapedQuote = ch == delimiter
			continue
		}

		if backslashEscapes && ch == '\\' {
			escaped = true
			continue
		}

		if ch == delimiter {
			// '' (and "" for MySQL string literals) is one escaped quote in
			// standard SQL, including dialects that also accept \'.
			if s.lookAhead(1) == delimiter {
				s.next()
				continue
			}
			s.next() // consume the closing quote
			return s.emit(STRING)
		}
	}
	// Special case: if we ended with an escaped quote (e.g. ESCAPE '\')
	if escapedQuote {
		return s.emit(STRING)
	}
	// If we get here, we hit EOF before finding closing quote
	return s.emit(INCOMPLETE_STRING)
}

// stringBackslashEscapes reports whether a backslash inside the literal that
// starts at s.start escapes the following character.
//
// SQL Server and Oracle never treat backslash as an escape. PostgreSQL does
// so only for escape strings (E'...' / e'...'). Ordinary PostgreSQL strings
// follow standard_conforming_strings: a quote is escaped by doubling it.
func (s *Lexer) stringBackslashEscapes() bool {
	switch s.config.DBMS {
	case DBMSSQLServer, DBMSOracle:
		return false
	case DBMSPostgres:
		return s.hasPostgresEscapeStringPrefix()
	default:
		return true
	}
}

// hasPostgresEscapeStringPrefix reports whether the quote at s.start is the
// opening quote of an escape string, E'...' or e'...'. The marker has to be
// its own token, so an identifier that merely ends in E (someValue'...') does
// not count.
func (s *Lexer) hasPostgresEscapeStringPrefix() bool {
	if s.start == 0 {
		return false
	}
	marker, size := utf8.DecodeLastRuneInString(s.src[:s.start])
	if marker != 'E' && marker != 'e' {
		return false
	}
	if s.start == size {
		return true
	}
	prev, _ := utf8.DecodeLastRuneInString(s.src[:s.start-size])
	return !isLetter(prev) && !isDigit(prev)
}

func (s *Lexer) scanIdentifier(ch rune) *Token {
	s.start = s.cursor
	node := keywordRoot
	pos := s.cursor

	// If first character is Unicode, skip trie lookup
	if ch > 127 {
		for isIdentifier(ch) {
			s.hasDigits = s.hasDigits || isDigit(ch)
			ch = s.nextBy(utf8.RuneLen(ch))
		}
		if s.start == s.cursor {
			return s.scanUnknown()
		}
		if s.config.DBMS == DBMSMySQL {
			return s.checkForSpacesInIdentifier(IDENT)
		}
		return s.emit(IDENT)
	}

	// ASCII characters - try keyword matching
	for isAsciiLetter(ch) || ch == '_' {
		// Convert to uppercase for case-insensitive matching
		upperCh := ch
		if ch >= 'a' && ch <= 'z' {
			upperCh -= 32
		}

		// Get array index for this character
		idx := trieIndex(upperCh)
		if idx < 0 {
			// Invalid character for trie, break out
			node = keywordRoot
			ch = s.next()
			break
		}

		// Try to follow trie path using direct array access
		if next := node.children[idx]; next != nil {
			node = next
			pos = s.cursor
			ch = s.next()
		} else {
			// No more matches possible in trie
			// Reset node for next potential keyword
			// and continue scanning identifier
			node = keywordRoot
			ch = s.next()
			break
		}
	}

	// If we found a complete keyword and next char is whitespace
	if node.isEnd && (isPunctuation(ch) || isSpace(ch) || isMultiLineComment(ch, s.lookAhead(1)) || isEOF(ch)) {
		s.cursor = pos + 1 // Include the last matched character
		s.isTableIndicator = node.isTableIndicator
		return s.emit(node.tokenType)
	}

	// Continue scanning identifier if no keyword match
	for isIdentifier(ch) {
		s.hasDigits = s.hasDigits || isDigit(ch)
		ch = s.nextBy(utf8.RuneLen(ch))
	}

	if s.start == s.cursor {
		return s.scanUnknown()
	}

	if ch == '(' {
		return s.emit(FUNCTION)
	}
	if s.config.DBMS == DBMSMySQL {
		return s.checkForSpacesInIdentifier(IDENT)
	}
	return s.emit(IDENT)
}

func (s *Lexer) scanDoubleQuotedIdentifier(delimiter rune) *Token {
	return s.scanDoubleQuotedIdentifierComponent(delimiter, true)
}

func (s *Lexer) scanDoubleQuotedIdentifierComponent(delimiter rune, joinQualified bool) *Token {
	closingDelimiter := delimiter
	if delimiter == '[' {
		closingDelimiter = ']'
	}

	s.start = s.cursor
	s.hasQuotes = true
	s.isSimpleIdentifier = true
	firstRune := true
	ch := s.next() // consume the opening quote
	specialCase := []rune{closingDelimiter, '.', delimiter}
	for {
		// encountered the closing quote
		// BUT if it's followed by .", then we should keep going
		// e.g. postgres "foo"."bar"
		// e.g. sqlserver [foo].[bar]
		if ch == closingDelimiter {
			if s.matchAt(specialCase) {
				s.isSimpleIdentifier = false
				ch = s.nextBy(3) // consume the "."
				continue
			}
			if firstRune {
				s.isSimpleIdentifier = false
			}
			break
		}
		if isEOF(ch) {
			s.hasQuotes = false // if we hit EOF, we clear the quotes
			s.isSimpleIdentifier = false
			return s.emit(ERROR)
		}
		s.hasDigits = s.hasDigits || isDigit(ch)
		if s.isSimpleIdentifier {
			if firstRune {
				if !isLetter(ch) {
					s.isSimpleIdentifier = false
				}
				firstRune = false
			} else if !isAlphaNumeric(ch) {
				s.isSimpleIdentifier = false
			}
		}
		// Advance by actual decoded rune size.
		// This handles truncated UTF-8 sequences correctly.
		_, size := utf8.DecodeRuneInString(s.src[s.cursor:])
		ch = s.nextBy(size)
	}
	s.next() // consume the closing quote (ASCII)
	if joinQualified && s.config.DBMS == DBMSMySQL {
		return s.checkForSpacesInIdentifier(QUOTED_IDENT)
	}
	return s.emit(QUOTED_IDENT)
}

// scanMySQLQualifiedIdentifierComponent scans an unquoted identifier after a
// qualifier dot. Keywords are valid identifier components in this position,
// so this deliberately skips the keyword trie used by scanIdentifier.
func (s *Lexer) scanMySQLQualifiedIdentifierComponent(ch rune) *Token {
	s.start = s.cursor
	for isIdentifier(ch) {
		s.hasDigits = s.hasDigits || isDigit(ch)
		ch = s.nextBy(utf8.RuneLen(ch))
	}
	if ch == '(' {
		return s.emit(FUNCTION)
	}
	return s.emit(IDENT)
}

// checkForSpacesInIdentifier joins MySQL qualified identifiers whose
// components have been separated by whitespace around a dot. MySQL emits this
// form in normalized performance_schema statements, for example:
// `schema` . `table` . `column`.
func (s *Lexer) checkForSpacesInIdentifier(tokenType TokenType) *Token {
	token := s.emit(tokenType)
	identifierStart := s.cursor - len(token.Value)
	identifierEnd := s.cursor
	resultType := token.Type
	hasDigits := token.hasDigits
	hasQuotes := token.hasQuotes
	hasSeparatorSpaces := false
	joined := false

	for {
		ch := s.peek()
		componentEnd := s.cursor
		separatorHasSpaces := false

		// Unquoted identifiers already consume an adjacent dot. Continue from
		// that dot as well as from a dot separated by whitespace.
		dotConsumed := identifierEnd > identifierStart && s.src[identifierEnd-1] == '.'
		if dotConsumed {
			for isSpace(ch) {
				separatorHasSpaces = true
				ch = s.next()
			}
		} else {
			for isSpace(ch) {
				separatorHasSpaces = true
				ch = s.next()
			}
			if ch != '.' {
				s.cursor = componentEnd
				break
			}
			ch = s.next()
			for isSpace(ch) {
				separatorHasSpaces = true
				ch = s.next()
			}
		}

		// Match the characters scanMySQLQualifiedIdentifierComponent can
		// actually consume. isAlphaNumeric also accepts Unicode numbers, while
		// isIdentifier does not; accepting one here would make no progress.
		if !isLetter(ch) && !isDigit(ch) && ch != '$' && ch != '`' {
			if ch == '*' {
				// Preserve the qualifier dot on the identifier and let the next
				// scan emit the wildcard, matching the adjacent-token behavior.
				joined = true
				hasSeparatorSpaces = hasSeparatorSpaces || separatorHasSpaces
				identifierEnd = s.cursor
				break
			}
			s.cursor = componentEnd
			break
		}

		if ch == '`' {
			token = s.scanDoubleQuotedIdentifierComponent('`', false) // sadscan:disable np.hashicorp.1 -- lexer token, not a Vault token
		} else {
			token = s.scanMySQLQualifiedIdentifierComponent(ch) // sadscan:disable np.hashicorp.1 -- lexer token, not a Vault token
		}

		joined = true
		hasSeparatorSpaces = hasSeparatorSpaces || separatorHasSpaces
		identifierEnd = s.cursor
		hasDigits = hasDigits || token.hasDigits
		hasQuotes = hasQuotes || token.hasQuotes

		if token.Type == ERROR {
			resultType = ERROR
			break
		}
		if token.Type == FUNCTION {
			// Match the existing token type for an adjacent unquoted name such
			// as db.func(. Quoted or partially quoted names retain their quoted
			// identifier type; recognizing those as routines needs SQL context.
			if resultType != QUOTED_IDENT {
				resultType = FUNCTION
			}
			break
		}
		if resultType == QUOTED_IDENT || token.Type == QUOTED_IDENT {
			resultType = QUOTED_IDENT
		}
	}

	if !joined {
		return token
	}

	token.Type = resultType
	token.hasDigits = hasDigits
	token.hasQuotes = hasQuotes
	token.isSimpleIdentifier = false
	if !hasSeparatorSpaces {
		token.Value = s.src[identifierStart:identifierEnd]
		return token
	}
	token.Value = compactMySQLQualifiedIdentifier(s.src[identifierStart:identifierEnd])
	return token
}

func compactMySQLQualifiedIdentifier(value string) string {
	compactLength := len(value)
	inQuotes := false
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if ch == '`' {
			inQuotes = !inQuotes
		} else if !inQuotes && isSpace(rune(ch)) {
			compactLength--
		}
	}

	var compact strings.Builder
	compact.Grow(compactLength)
	inQuotes = false
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if ch == '`' {
			inQuotes = !inQuotes
		} else if !inQuotes && isSpace(rune(ch)) {
			continue
		}
		compact.WriteByte(ch)
	}
	return compact.String()
}

func (s *Lexer) scanWhitespace() *Token {
	// scan whitespace, tab, newline, carriage return
	s.start = s.cursor
	ch := s.next()
	for isSpace(ch) {
		ch = s.next()
	}
	return s.emit(SPACE)
}

func (s *Lexer) scanOperator(lastCh rune) *Token {
	s.start = s.cursor
	ch := s.next() // consume the first character

	// Check for json operators
	switch lastCh {
	case '-':
		if ch == '>' {
			ch = s.next()
			if ch == '>' {
				s.next()
				return s.emit(JSON_OP) // ->>
			}
			return s.emit(JSON_OP) // ->
		}
	case '#':
		if ch == '>' {
			ch = s.next()
			if ch == '>' {
				s.next()
				return s.emit(JSON_OP) // #>>
			}
			return s.emit(JSON_OP) // #>
		} else if ch == '-' {
			s.next()
			return s.emit(JSON_OP) // #-
		}
	case '?':
		if ch == '|' {
			s.next()
			return s.emit(JSON_OP) // ?|
		} else if ch == '&' {
			s.next()
			return s.emit(JSON_OP) // ?&
		}
	case '<':
		if ch == '@' {
			s.next()
			return s.emit(JSON_OP) // <@
		}
	}

	for isOperator(ch) && !(lastCh == '=' && (ch == '?' || ch == '@')) {
		// hack: we don't want to treat "=?" as an single operator
		lastCh = ch
		ch = s.next()
	}

	return s.emit(OPERATOR)
}

func (s *Lexer) scanWildcard() *Token {
	s.start = s.cursor
	s.next()
	return s.emit(WILDCARD)
}

func (s *Lexer) scanSingleLineComment(ch rune) *Token {
	s.start = s.cursor
	if ch == '#' {
		ch = s.next() // consume the opening #
	} else {
		ch = s.nextBy(2) // consume the opening dashes
	}
	for ch != '\n' && !isEOF(ch) {
		ch = s.next()
	}
	return s.emit(COMMENT)
}

func (s *Lexer) scanMultiLineComment() *Token {
	s.start = s.cursor
	ch := s.nextBy(2) // consume the opening slash and asterisk
	for {
		if ch == '*' && s.lookAhead(1) == '/' {
			s.nextBy(2) // consume the closing asterisk and slash
			break
		}
		if isEOF(ch) {
			// encountered EOF before closing comment
			// this usually happens when the comment is truncated
			return s.emit(ERROR)
		}
		ch = s.next()
	}
	return s.emit(MULTILINE_COMMENT)
}

func (s *Lexer) scanPunctuation() *Token {
	s.start = s.cursor
	s.next()
	return s.emit(PUNCTUATION)
}

func (s *Lexer) scanDollarQuotedString() *Token {
	s.start = s.cursor
	ch := s.next() // consume the dollar sign
	tagStart := s.cursor

	for s.cursor < len(s.src) && ch != '$' {
		ch = s.next()
	}
	s.next()                            // consume the closing dollar sign of the tag
	tag := s.src[tagStart-1 : s.cursor] // include the opening and closing dollar sign e.g. $tag$
	tagRune := []rune(tag)
	tagLen := len(tagRune)

	for s.cursor < len(s.src) {
		if s.matchAt(tagRune) {
			s.nextBy(tagLen) // consume the closing tag
			if tag == "$func$" {
				return s.emit(DOLLAR_QUOTED_FUNCTION)
			}
			return s.emit(DOLLAR_QUOTED_STRING)
		}
		s.next()
	}
	return s.emit(ERROR)
}

func (s *Lexer) scanPositionalParameter() *Token {
	s.start = s.cursor
	ch := s.nextBy(2) // consume the dollar sign and the number
	for {
		if !isDigit(ch) {
			break
		}
		ch = s.next()
	}
	return s.emit(POSITIONAL_PARAMETER)
}

func (s *Lexer) scanBindParameter() *Token {
	s.start = s.cursor
	ch := s.nextBy(2) // consume the (colon|at sign) and the char
	for {
		if !isAlphaNumeric(ch) {
			break
		}
		ch = s.next()
	}
	return s.emit(BIND_PARAMETER)
}

func (s *Lexer) scanSystemVariable() *Token {
	s.start = s.cursor
	ch := s.nextBy(2) // consume @@
	// Must be followed by at least one alphanumeric character
	if !isAlphaNumeric(ch) {
		return s.emit(ERROR)
	}
	for isAlphaNumeric(ch) {
		ch = s.next()
	}
	return s.emit(SYSTEM_VARIABLE)
}

func (s *Lexer) scanUnknown() *Token {
	// When we see an unknown token, we advance the cursor by the full rune length.
	// This is important for multi-byte UTF-8 characters (e.g., full-width punctuation)
	// to avoid splitting them into separate byte tokens.
	s.start = s.cursor
	_, size := utf8.DecodeRuneInString(s.src[s.cursor:])
	s.cursor += size
	return s.emit(UNKNOWN)
}

// Modify emit function to use positions and maintain links
func (s *Lexer) emit(t TokenType) *Token {
	tok := s.token
	lastValueToken := tok.lastValueToken

	// Zero other fields
	*tok = Token{
		Type:             t,
		Value:            s.src[s.start:s.cursor],
		isTableIndicator: s.isTableIndicator,
		lastValueToken:   lastValueToken,
	}

	tok.hasDigits = s.hasDigits
	tok.hasQuotes = s.hasQuotes
	tok.isSimpleIdentifier = s.isSimpleIdentifier

	// Reset lexer state
	s.start = s.cursor
	s.isTableIndicator = false
	s.hasDigits = false
	s.isSimpleIdentifier = false

	return tok
}
