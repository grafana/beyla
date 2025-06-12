package attributes

import (
	"testing"

	"github.com/stretchr/testify/assert"

	attrobi "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/attributes"
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
		selection.Matching(attrobi.Name{Section: "foo.bar.baz"}))
	assert.Equal(t,
		[]InclusionLists{f, fbt},
		selection.Matching(attrobi.Name{Section: "foo.bar.traca"}))
	assert.Equal(t,
		[]InclusionLists{pp},
		selection.Matching(attrobi.Name{Section: "pim.pam"}))
	assert.Empty(t, selection.Matching(attrobi.Name{Section: "pam.pum"}))
}
