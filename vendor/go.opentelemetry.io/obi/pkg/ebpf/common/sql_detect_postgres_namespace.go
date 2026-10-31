// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"bytes"
	"strings"
	"unicode/utf8"
)

const (
	pgSearchPathParam = "search_path"
	pgOptionsParam    = "options"
	pgUserSchema      = "$user"
)

type postgresNamespace struct {
	db            string
	startupSchema string
	schema        string
}

func (n postgresNamespace) String() string {
	if n.db != "" && n.schema != "" {
		return n.db + "|" + n.schema
	}
	if n.db != "" {
		return n.db
	}
	return n.schema
}

type postgresSearchPathAction uint8

const (
	postgresSearchPathNone postgresSearchPathAction = iota
	postgresSearchPathSet
	postgresSearchPathReset
)

type postgresSearchPathChange struct {
	action postgresSearchPathAction
	schema string
}

func (c postgresSearchPathChange) apply(n postgresNamespace) postgresNamespace {
	switch c.action {
	case postgresSearchPathSet:
		n.schema = c.schema
	case postgresSearchPathReset:
		n.schema = n.startupSchema
	}
	return n
}

func postgresNamespaceForConn(parseCtx *EBPFParseContext, connInfo BpfConnectionInfoT) string {
	if parseCtx.postgresNamespaces == nil {
		return ""
	}
	if ns, ok := parseCtx.postgresNamespaces.Get(connInfo); ok {
		return ns.String()
	}
	return ""
}

func applyPostgresSearchPathChange(parseCtx *EBPFParseContext, connInfo BpfConnectionInfoT, change postgresSearchPathChange) {
	if parseCtx.postgresNamespaces == nil || change.action == postgresSearchPathNone {
		return
	}
	ns, _ := parseCtx.postgresNamespaces.Get(connInfo)
	parseCtx.postgresNamespaces.Add(connInfo, change.apply(ns))
}

func firstSearchPathSchema(searchPath string) string {
	rest := searchPath
	for rest != "" {
		var entry string
		entry, rest = nextSearchPathEntry(rest)
		if entry != "" && entry != pgUserSchema {
			return entry
		}
	}
	return ""
}

func nextSearchPathEntry(list string) (string, string) {
	list = strings.TrimLeft(list, " \t\r\n")
	if !strings.HasPrefix(list, `"`) {
		entry, rest, _ := strings.Cut(list, ",")
		return lowerASCII(strings.TrimSpace(entry)), rest
	}

	entry, rest, ok := cutPostgresQuoted(list)
	if !ok {
		return "", ""
	}
	_, rest, _ = strings.Cut(rest, ",")
	return entry, rest
}

func cutPostgresQuoted(s string) (string, string, bool) {
	quote := s[0]
	var sb strings.Builder
	for i := 1; i < len(s); i++ {
		if s[i] != quote {
			sb.WriteByte(s[i])
			continue
		}
		if i+1 < len(s) && s[i+1] == quote {
			sb.WriteByte(quote)
			i++
			continue
		}
		return sb.String(), s[i+1:], true
	}
	return "", "", false
}

func lowerASCII(s string) string {
	lowered := []byte(s)
	for i := range lowered {
		lowered[i] = toLowerASCII(lowered[i])
	}
	return string(lowered)
}

func isPostgresIdentifierStart(c byte) bool {
	return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || c == '_' || c >= utf8.RuneSelf
}

func isPostgresIdentifierPart(c byte) bool {
	return isPostgresIdentifierStart(c) || ('0' <= c && c <= '9') || c == '$'
}

func searchPathFromStartupOptions(options string) (string, bool) {
	const (
		shortFlag = "-c"
		longFlag  = "--"
		prefix    = pgSearchPathParam + "="
	)
	fields := splitPostgresOptions(options)
	found := ""
	ok := false
	for i := 0; i < len(fields); i++ {
		setting := ""
		switch {
		case fields[i] == shortFlag && i+1 < len(fields):
			i++
			setting = fields[i]
		case strings.HasPrefix(fields[i], shortFlag):
			setting = fields[i][len(shortFlag):]
		case strings.HasPrefix(fields[i], longFlag):
			setting = fields[i][len(longFlag):]
		}
		if value, has := strings.CutPrefix(setting, prefix); has {
			found, ok = value, true
		}
	}
	return found, ok
}

func splitPostgresOptions(options string) []string {
	var (
		args    []string
		arg     strings.Builder
		inArg   bool
		escaped bool
	)
	for i := 0; i < len(options); i++ {
		c := options[i]
		switch {
		case escaped:
			arg.WriteByte(c)
			escaped = false
		case c == '\\':
			escaped, inArg = true, true
		case isPostgresOptionsSpace(c):
			if inArg {
				args = append(args, arg.String())
				arg.Reset()
				inArg = false
			}
		default:
			arg.WriteByte(c)
			inArg = true
		}
	}
	if inArg {
		args = append(args, arg.String())
	}
	return args
}

func isPostgresOptionsSpace(c byte) bool {
	return c == ' ' || ('\t' <= c && c <= '\r')
}

type postgresTokenKind uint8

const (
	postgresTokenEnd postgresTokenKind = iota
	postgresTokenWord
	postgresTokenQuoted
	postgresTokenSymbol
	postgresTokenInvalid
)

type postgresToken struct {
	kind postgresTokenKind
	text string
}

func (t postgresToken) isWord(word string) bool {
	return t.kind == postgresTokenWord && t.text == word
}

func (t postgresToken) isSymbol(symbol string) bool {
	return t.kind == postgresTokenSymbol && t.text == symbol
}

type postgresStatementTokens struct {
	rest string
}

func (t *postgresStatementTokens) next() postgresToken {
	if !t.skipSpaceAndComments() {
		return postgresToken{kind: postgresTokenInvalid}
	}
	if t.rest == "" {
		return postgresToken{kind: postgresTokenEnd}
	}

	c := t.rest[0]
	switch {
	case c == '\'' || c == '"':
		value, rest, ok := cutPostgresQuoted(t.rest)
		if !ok {
			return postgresToken{kind: postgresTokenInvalid}
		}
		t.rest = rest
		return postgresToken{kind: postgresTokenQuoted, text: value}
	case isPostgresIdentifierStart(c):
		end := 1
		for end < len(t.rest) && isPostgresIdentifierPart(t.rest[end]) {
			end++
		}
		word := t.rest[:end]
		t.rest = t.rest[end:]
		return postgresToken{kind: postgresTokenWord, text: lowerASCII(word)}
	case c == ',' || c == ';' || c == '=':
		t.rest = t.rest[1:]
		return postgresToken{kind: postgresTokenSymbol, text: string(c)}
	}
	return postgresToken{kind: postgresTokenInvalid}
}

func (t *postgresStatementTokens) skipSpaceAndComments() bool {
	for {
		t.rest = strings.TrimLeft(t.rest, " \t\r\n\f")
		switch {
		case strings.HasPrefix(t.rest, "--"):
			_, t.rest, _ = strings.Cut(t.rest, "\n")
		case strings.HasPrefix(t.rest, "/*"):
			var closed bool
			_, t.rest, closed = strings.Cut(t.rest, "*/")
			if !closed {
				return false
			}
		default:
			return true
		}
	}
}

func (t *postgresStatementTokens) atEnd() bool {
	return t.endsWith(t.next())
}

func (t *postgresStatementTokens) endsWith(tok postgresToken) bool {
	if tok.isSymbol(";") {
		tok = t.next()
	}
	return tok.kind == postgresTokenEnd
}

func endOfStatement(tokens *postgresStatementTokens, change postgresSearchPathChange) postgresSearchPathChange {
	if !tokens.atEnd() {
		return postgresSearchPathChange{}
	}
	return change
}

var postgresSearchPathStatementPrefixes = [][]byte{
	[]byte("SET"), []byte("RESET"), []byte("DISCARD"), []byte("/*"), []byte("--"),
}

func mayChangePostgresSearchPath(query []byte) bool {
	query = bytes.TrimLeft(query, " \t\r\n")
	for _, prefix := range postgresSearchPathStatementPrefixes {
		if len(query) >= len(prefix) && equalFoldASCII(query[:len(prefix)], prefix) {
			return true
		}
	}
	return false
}

func parsePostgresSearchPathChange(query []byte) postgresSearchPathChange {
	if !mayChangePostgresSearchPath(query) {
		return postgresSearchPathChange{}
	}
	tokens := &postgresStatementTokens{rest: cstr(query)}

	switch tok := tokens.next(); {
	case tok.isWord("set"):
		return parsePostgresSetSearchPath(tokens)
	case tok.isWord("reset"):
		return parsePostgresResetSearchPath(tokens)
	case tok.isWord("discard"):
		return parsePostgresDiscardAll(tokens)
	}
	return postgresSearchPathChange{}
}

func parsePostgresSetSearchPath(tokens *postgresStatementTokens) postgresSearchPathChange {
	tok := tokens.next()
	if tok.isWord("local") {
		return postgresSearchPathChange{}
	}
	if tok.isWord("session") {
		tok = tokens.next()
	}

	switch {
	case tok.isWord("schema"):
		return parsePostgresSearchPathValues(tokens, false)
	case tok.isWord(pgSearchPathParam):
		if sep := tokens.next(); !sep.isWord("to") && !sep.isSymbol("=") {
			return postgresSearchPathChange{}
		}
		return parsePostgresSearchPathValues(tokens, true)
	}
	return postgresSearchPathChange{}
}

func parsePostgresSearchPathValues(tokens *postgresStatementTokens, allowList bool) postgresSearchPathChange {
	tok := tokens.next()
	if tok.isWord("default") {
		return endOfStatement(tokens, postgresSearchPathChange{action: postgresSearchPathReset})
	}

	schema := ""
	for {
		if tok.kind != postgresTokenWord && tok.kind != postgresTokenQuoted {
			return postgresSearchPathChange{}
		}
		if schema == "" && tok.text != "" && tok.text != pgUserSchema {
			schema = tok.text
		}

		sep := tokens.next()
		if !sep.isSymbol(",") || !allowList {
			if !tokens.endsWith(sep) {
				return postgresSearchPathChange{}
			}
			return postgresSearchPathChange{action: postgresSearchPathSet, schema: schema}
		}
		tok = tokens.next()
	}
}

func parsePostgresResetSearchPath(tokens *postgresStatementTokens) postgresSearchPathChange {
	if tok := tokens.next(); tok.isWord("all") || tok.isWord(pgSearchPathParam) {
		return endOfStatement(tokens, postgresSearchPathChange{action: postgresSearchPathReset})
	}
	return postgresSearchPathChange{}
}

func parsePostgresDiscardAll(tokens *postgresStatementTokens) postgresSearchPathChange {
	if tokens.next().isWord("all") {
		return endOfStatement(tokens, postgresSearchPathChange{action: postgresSearchPathReset})
	}
	return postgresSearchPathChange{}
}
