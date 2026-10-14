// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest/php"

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

type tokenKind uint8

const (
	tokenName tokenKind = iota + 1
	tokenVariable
	tokenString
	tokenSymbol
	tokenDocComment
)

type token struct {
	kind  tokenKind
	value string
}

// lexPHP recognizes only the PHP constructs needed to find static routes
// it does not validate PHP syntax.
func lexPHP(source []byte) []token {
	tokens := make([]token, 0, len(source)/4)

	for pos := 0; pos < len(source); {
		switch {
		case isSpace(source[pos]):
			pos++
		case hasPrefixAt(source, pos, "//"):
			pos = skipLine(source, pos+2)
		case source[pos] == '#' && !hasPrefixAt(source, pos, "#["):
			// PHP uses # for comments and #[ for attributes.
			pos = skipLine(source, pos+1)
		case hasPrefixAt(source, pos, "/*"):
			value, nextPosition, isDocComment := readBlockComment(source, pos)
			if isDocComment {
				tokens = append(tokens, token{kind: tokenDocComment, value: value})
			}
			pos = nextPosition
		case source[pos] == '\'' || source[pos] == '"':
			value, nextPosition, isStatic := readPHPString(source, pos)
			if isStatic {
				tokens = append(tokens, token{kind: tokenString, value: value})
			}
			pos = nextPosition
		case source[pos] == '$':
			value, nextPosition := readVariable(source, pos)
			if value != "" {
				tokens = append(tokens, token{kind: tokenVariable, value: value})
			}
			pos = nextPosition
		case isNameStart(source[pos]) || source[pos] == '\\':
			value, nextPosition := readName(source, pos)
			tokens = append(tokens, token{kind: tokenName, value: value})
			pos = nextPosition
		default:
			value, nextPosition := readSymbol(source, pos)
			tokens = append(tokens, token{kind: tokenSymbol, value: value})
			pos = nextPosition
		}
	}

	return tokens
}

func readPHPString(source []byte, start int) (string, int, bool) {
	quote := source[start]
	var value strings.Builder
	isStatic := true

	for pos := start + 1; pos < len(source); pos++ {
		c := source[pos]
		if c == quote {
			return value.String(), pos + 1, isStatic
		}

		if quote == '"' && startsPHPInterpolation(source, pos) {
			isStatic = false
		}

		if c != '\\' || pos+1 >= len(source) {
			value.WriteByte(c)
			continue
		}

		escaped, nextPosition := decodePHPStringEscape(source, pos, quote)
		value.WriteString(escaped)
		pos = nextPosition - 1
	}

	return "", len(source), false
}

func decodePHPStringEscape(source []byte, start int, quote byte) (string, int) {
	escaped := source[start+1]
	if escaped == quote || escaped == '\\' || quote == '"' && escaped == '$' {
		return string(escaped), start + 2
	}

	if quote == '\'' {
		return string(source[start : start+2]), start + 2
	}

	switch escaped {
	case 'n':
		return "\n", start + 2
	case 'r':
		return "\r", start + 2
	case 't':
		return "\t", start + 2
	case 'v':
		return "\v", start + 2
	case 'e':
		return "\x1b", start + 2
	case 'f':
		return "\f", start + 2
	case 'x':
		if value, next, ok := decodePHPHexEscape(source, start); ok {
			return value, next
		}
	case 'u':
		if value, next, ok := decodePHPUnicodeEscape(source, start); ok {
			return value, next
		}
	default:
		if isOctalDigit(escaped) {
			return decodePHPOctalEscape(source, start)
		}
	}

	// PHP preserves unknown escapes, including common regex escapes such as \d.
	return string(source[start : start+2]), start + 2
}

func decodePHPOctalEscape(source []byte, start int) (string, int) {
	end := start + 1
	limit := min(start+4, len(source))
	for end < limit && isOctalDigit(source[end]) {
		end++
	}

	value, _ := strconv.ParseUint(string(source[start+1:end]), 8, 16)
	// PHP silently truncates overflowing octal escapes to one byte.
	return string([]byte{byte(value)}), end
}

func decodePHPHexEscape(source []byte, start int) (string, int, bool) {
	digits := start + 2
	if digits >= len(source) || !isHexDigit(source[digits]) {
		return "", start, false
	}

	end := digits + 1
	if end < len(source) && isHexDigit(source[end]) {
		end++
	}

	value, _ := strconv.ParseUint(string(source[digits:end]), 16, 8)
	return string([]byte{byte(value)}), end, true
}

func decodePHPUnicodeEscape(source []byte, start int) (string, int, bool) {
	digits := start + 3
	if digits > len(source) || source[start+2] != '{' {
		return "", start, false
	}

	end := digits
	for end < len(source) && isHexDigit(source[end]) {
		end++
	}
	if end == digits || end >= len(source) || source[end] != '}' {
		return "", start, false
	}

	value, err := strconv.ParseUint(string(source[digits:end]), 16, 32)
	character := rune(value)
	if err != nil || !utf8.ValidRune(character) {
		return "", start, false
	}

	return string(character), end + 1, true
}

func isOctalDigit(char byte) bool {
	return char >= '0' && char <= '7'
}

func isHexDigit(char byte) bool {
	return char >= '0' && char <= '9' ||
		char >= 'a' && char <= 'f' ||
		char >= 'A' && char <= 'F'
}

func startsPHPInterpolation(source []byte, position int) bool {
	nextPosition := position + 1
	return source[position] == '$' &&
		nextPosition < len(source) &&
		(isNameStart(source[nextPosition]) || source[nextPosition] == '{')
}

func readBlockComment(source []byte, start int) (string, int, bool) {
	isDocComment := start+2 < len(source) && source[start+2] == '*'

	for pos := start + 2; pos+1 < len(source); pos++ {
		if source[pos] == '*' && source[pos+1] == '/' {
			return string(source[start : pos+2]), pos + 2, isDocComment
		}
	}

	return string(source[start:]), len(source), isDocComment
}

func readVariable(source []byte, start int) (string, int) {
	end := start + 1

	if end >= len(source) || !isNameStart(source[end]) {
		return "", end
	}

	for end < len(source) && isNameContinue(source[end]) {
		end++
	}

	return string(source[start:end]), end
}

func readName(source []byte, start int) (string, int) {
	end := start

	for end < len(source) && (isNameContinue(source[end]) || source[end] == '\\') {
		end++
	}

	return string(source[start:end]), end
}

func readSymbol(source []byte, position int) (string, int) {
	if hasPrefixAt(source, position, "?->") {
		return "?->", position + 3
	}

	if position+1 < len(source) {
		pair := string(source[position : position+2])

		switch pair {
		case "::", "->", "=>", "#[", "??":
			return pair, position + 2
		}
	}

	return string(source[position]), position + 1
}

func hasPrefixAt(source []byte, position int, prefix string) bool {
	end := position + len(prefix)
	return position >= 0 && end <= len(source) && string(source[position:end]) == prefix
}

func skipLine(source []byte, position int) int {
	for position < len(source) && source[position] != '\n' {
		position++
	}

	return position
}

func isSpace(char byte) bool {
	return char == ' ' || char == '\t' || char == '\r' || char == '\n'
}

func isNameStart(char byte) bool {
	// PHP permits bytes from 0x80 through 0xff in identifiers.
	return char == '_' ||
		(char >= 'a' && char <= 'z') ||
		(char >= 'A' && char <= 'Z') ||
		char >= 0x80
}

func isNameContinue(char byte) bool {
	return isNameStart(char) || char >= '0' && char <= '9'
}
