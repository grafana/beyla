// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest/php"

func callArguments(tokens []token, openingParenthesis int) [][]token {
	closingParenthesis := matchingClosingToken(tokens, openingParenthesis, "(", ")")

	if closingParenthesis < 0 {
		return nil
	}

	return splitOnTopLevelCommas(tokens[openingParenthesis+1 : closingParenthesis])
}

func matchingClosingToken(tokens []token, openingIndex int, openingSymbol, closingSymbol string) int {
	if openingIndex < 0 || openingIndex >= len(tokens) {
		return -1
	}

	openingToken := tokens[openingIndex]
	if openingToken.kind != tokenSymbol || openingToken.value != openingSymbol {
		return -1
	}

	nestingDepth := 0

	for position := openingIndex; position < len(tokens); position++ {
		current := tokens[position]
		if current.kind != tokenSymbol {
			continue
		}

		switch current.value {
		case openingSymbol:
			nestingDepth++
		case closingSymbol:
			nestingDepth--
			if nestingDepth == 0 {
				return position
			}
		}
	}

	return -1
}

func splitOnTopLevelCommas(tokens []token) [][]token {
	if len(tokens) == 0 {
		return nil
	}

	var groups [][]token
	groupStart := 0
	parenthesisDepth := 0
	bracketDepth := 0
	braceDepth := 0

	for position, current := range tokens {
		if current.kind != tokenSymbol {
			continue
		}

		switch current.value {
		case "(":
			parenthesisDepth++
		case ")":
			parenthesisDepth--
		case "[", "#[":
			bracketDepth++
		case "]":
			bracketDepth--
		case "{":
			braceDepth++
		case "}":
			braceDepth--
		case ",":
			atTopLevel := parenthesisDepth == 0 && bracketDepth == 0 && braceDepth == 0
			if atTopLevel {
				groups = append(groups, tokens[groupStart:position])
				groupStart = position + 1
			}
		}
	}

	// PHP permits a trailing comma in calls, arrays, and attribute groups
	if groupStart == len(tokens) {
		return groups
	}

	return append(groups, tokens[groupStart:])
}

func staticStringArgument(arguments [][]token, index int) (string, bool) {
	if index < 0 || index >= len(arguments) {
		return "", false
	}

	argument := arguments[index]
	if len(argument) != 1 || argument[0].kind != tokenString {
		return "", false
	}

	return argument[0].value, true
}
