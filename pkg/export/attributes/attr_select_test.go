package attributes

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSelectorMatch(t *testing.T) {
	fbb := InclusionLists{Include: []string{"foo_bar_baz"}}
	f := InclusionLists{Include: []string{"foo"}}
	fbt := InclusionLists{Include: []string{"foo_bar_traca"}}
	pp := InclusionLists{Include: []string{"pim_pam"}}
	selection := Selection{
		"foo.bar.baz":   fbb,
		"foo.*":         f,
		"foo.bar.traca": fbt,
		"pim.pam":       pp,
	}
	assert.Equal(t,
		[]InclusionLists{f, fbb},
		selection.Matching(Name{Section: "foo.bar.baz"}))
	assert.Equal(t,
		[]InclusionLists{f, fbt},
		selection.Matching(Name{Section: "foo.bar.traca"}))
	assert.Equal(t,
		[]InclusionLists{pp},
		selection.Matching(Name{Section: "pim.pam"}))
	assert.Empty(t, selection.Matching(Name{Section: "pam.pum"}))
}
