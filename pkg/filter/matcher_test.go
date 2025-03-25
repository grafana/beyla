package filter

import (
	"strings"
	"testing"

	"github.com/gobwas/glob"
	"github.com/stretchr/testify/assert"
)

func TestMatches(t *testing.T) {
	matcher := Matcher[string]{
		Glob:   glob.MustCompile("hello_*"),
		Getter: strings.Clone, // pseudo-identity function
	}

	assert.True(t, matcher.Matches("hello_my_friend"))
	assert.False(t, matcher.Matches("my_friend_hello"))
}

func TestMatches_Negated(t *testing.T) {
	matcher := Matcher[string]{
		Glob:   glob.MustCompile("hello_*"),
		Negate: true,
		Getter: strings.Clone, // pseudo-identity function
	}

	assert.False(t, matcher.Matches("hello_my_friend"))
	assert.True(t, matcher.Matches("my_friend_hello"))
}

func TestMatchDefinition_Validate(t *testing.T) {
	assert.NoError(t, (&MatchDefinition{Match: "foo"}).Validate())
	assert.NoError(t, (&MatchDefinition{NotMatch: "foo"}).Validate())
	assert.Error(t, (&MatchDefinition{Match: "foo", NotMatch: "foo"}).Validate())
	assert.Error(t, (&MatchDefinition{}).Validate())
}
