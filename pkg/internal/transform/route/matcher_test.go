package route

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFind(t *testing.T) {
	m := NewMatcher([]string{
		"/foo/bar/bae/",
		"/foo/:id",
		"/foo/{id}/push",
		"/ski/*",
		"/snow/mobile/*",
		"/"})

	assert.Equal(t, "/", m.Find("/"))
	assert.Equal(t, "/foo/bar/bae/", m.Find("/foo/bar/bae"))
	assert.Equal(t, "/foo/:id", m.Find("/foo/1234"))
	assert.Equal(t, "/foo/:id", m.Find("/foo/someId"))
	assert.Equal(t, "/foo/{id}/push", m.Find("/foo/5678/push"))

	assert.Empty(t, m.Find("/foo"))
	assert.Empty(t, m.Find("/foo/bar"))
	assert.Empty(t, m.Find("/foo/bar/bae/baz"))
	assert.Empty(t, m.Find("/traca"))
	assert.Empty(t, m.Find("/foo/1234/down"))
	assert.Empty(t, m.Find("/foo/5678/push/up"))

	assert.Equal(t, "/ski/*", m.Find("/ski"))
	assert.Equal(t, "/ski/*", m.Find("/ski/doo"))
	assert.Equal(t, "/ski/*", m.Find("/ski/doo/new/"))

	assert.Equal(t, "", m.Find("/snow/man"))
	assert.Equal(t, "/snow/mobile/*", m.Find("/snow/mobile"))
	assert.Equal(t, "/snow/mobile/*", m.Find("/snow/mobile/long"))
}
