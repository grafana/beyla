package sqllexer

import (
	"strings"
)

type obfuscatorConfig struct {
	DollarQuotedFunc           bool `json:"dollar_quoted_func"`
	ReplaceDigits              bool `json:"replace_digits"`
	ReplacePositionalParameter bool `json:"replace_positional_parameter"`
	ReplaceBoolean             bool `json:"replace_boolean"`
	ReplaceNull                bool `json:"replace_null"`
	KeepJsonPath               bool `json:"keep_json_path"` // by default, we replace json path with placeholder
	ReplaceBindParameter       bool `json:"replace_bind_parameter"`
}

type obfuscatorOption func(*obfuscatorConfig)

func WithReplaceDigits(replaceDigits bool) obfuscatorOption {
	return func(c *obfuscatorConfig) {
		c.ReplaceDigits = replaceDigits
	}
}

func WithReplacePositionalParameter(replacePositionalParameter bool) obfuscatorOption {
	return func(c *obfuscatorConfig) {
		c.ReplacePositionalParameter = replacePositionalParameter
	}
}

func WithReplaceBoolean(replaceBoolean bool) obfuscatorOption {
	return func(c *obfuscatorConfig) {
		c.ReplaceBoolean = replaceBoolean
	}
}

func WithReplaceNull(replaceNull bool) obfuscatorOption {
	return func(c *obfuscatorConfig) {
		c.ReplaceNull = replaceNull
	}
}

func WithDollarQuotedFunc(dollarQuotedFunc bool) obfuscatorOption {
	return func(c *obfuscatorConfig) {
		c.DollarQuotedFunc = dollarQuotedFunc
	}
}

func WithKeepJsonPath(keepJsonPath bool) obfuscatorOption {
	return func(c *obfuscatorConfig) {
		c.KeepJsonPath = keepJsonPath
	}
}

func WithReplaceBindParameter(replaceBindParameter bool) obfuscatorOption {
	return func(c *obfuscatorConfig) {
		c.ReplaceBindParameter = replaceBindParameter
	}
}

type Obfuscator struct {
	config *obfuscatorConfig
}

func NewObfuscator(opts ...obfuscatorOption) *Obfuscator {
	obfuscator := &Obfuscator{
		config: &obfuscatorConfig{},
	}

	for _, opt := range opts {
		opt(obfuscator.config)
	}

	return obfuscator
}

const (
	StringPlaceholder = "?"
	NumberPlaceholder = "?"
)

// Obfuscate takes an input SQL string and returns an obfuscated SQL string.
// The obfuscator replaces all literal values with a single placeholder
func (o *Obfuscator) Obfuscate(input string, lexerOpts ...lexerOption) string {
	var obfuscatedSQL strings.Builder
	obfuscatedSQL.Grow(len(input))

	lexer := New(
		input,
		lexerOpts...,
	)

	var lastValueToken *LastValueToken
	var ec extractContext

	for {
		token := lexer.Scan()
		if token.Type == EOF {
			break
		}
		o.ObfuscateTokenValue(token, lastValueToken, lexerOpts...)
		ec.maybeReplaceExtractField(token)

		obfuscatedSQL.WriteString(token.Value)
		if isValueToken(token) {
			lastValueToken = token.getLastValueToken()
		}
		ec.update(token)
	}

	return strings.Clone(strings.TrimSpace(obfuscatedSQL.String()))
}

func (o *Obfuscator) ObfuscateTokenValue(token *Token, lastValueToken *LastValueToken, lexerOpts ...lexerOption) {
	switch token.Type {
	case NUMBER:
		if o.config.KeepJsonPath && lastValueToken != nil && lastValueToken.Type == JSON_OP {
			break
		}
		token.Value = NumberPlaceholder
	case DOLLAR_QUOTED_FUNCTION:
		if o.config.DollarQuotedFunc {
			// obfuscate the content of dollar quoted function
			quotedFunc := token.Value[6 : len(token.Value)-6] // remove the $func$ prefix and suffix
			var obfuscatedDollarQuotedFunc strings.Builder
			obfuscatedDollarQuotedFunc.Grow(len(quotedFunc) + 12)
			obfuscatedDollarQuotedFunc.WriteString("$func$")
			obfuscatedDollarQuotedFunc.WriteString(o.Obfuscate(quotedFunc, lexerOpts...))
			obfuscatedDollarQuotedFunc.WriteString("$func$")
			token.Value = obfuscatedDollarQuotedFunc.String()
			break
		}
		token.Value = StringPlaceholder
	case STRING, INCOMPLETE_STRING, DOLLAR_QUOTED_STRING:
		if o.config.KeepJsonPath && lastValueToken != nil && lastValueToken.Type == JSON_OP {
			break
		}
		token.Value = StringPlaceholder
	case POSITIONAL_PARAMETER:
		if o.config.ReplacePositionalParameter {
			token.Value = StringPlaceholder
		}
	case BIND_PARAMETER:
		if o.config.ReplaceBindParameter {
			token.Value = StringPlaceholder
		}
	case BOOLEAN:
		if o.config.ReplaceBoolean {
			token.Value = StringPlaceholder
		}
	case NULL:
		if o.config.ReplaceNull {
			token.Value = StringPlaceholder
		}
	case IDENT, QUOTED_IDENT:
		if o.config.ReplaceDigits && token.hasDigits {
			token.Value = replaceDigits(token, NumberPlaceholder)
		}
	}
}
