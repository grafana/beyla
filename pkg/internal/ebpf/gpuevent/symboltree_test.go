package gpuevent

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSymbolTree(t *testing.T) {
	tr := &SymbolTree{}

	tr.Insert(Symbol{Low: 100, High: 200, Symbol: "test"})
	tr.Insert(Symbol{Low: 200, High: 300, Symbol: "test2"})

	r := tr.Search(200)
	assert.Equal(t, 1, len(r))
	assert.Equal(t, "test2", r[0].Symbol)
}
