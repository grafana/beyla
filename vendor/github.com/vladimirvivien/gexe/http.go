package gexe

import (
	"strings"

	"github.com/vladimirvivien/gexe/http"
)

// Get creates a *http.ResourceReader to read resource content from HTTP server
func (e *Echo) Get(url string, paths ...string) *http.ResourceReader {
	var exapandedUrl strings.Builder
	exapandedUrl.WriteString(e.vars.Eval(url))
	for _, path := range paths {
		exapandedUrl.WriteString(e.vars.Eval(path))
	}
	return http.GetWithVars(exapandedUrl.String(), e.vars)
}

// Post creates a *http.ResourceWriter to write content to an HTTP server
func (e *Echo) Post(url string, paths ...string) *http.ResourceWriter {
	var exapandedUrl strings.Builder
	exapandedUrl.WriteString(e.vars.Eval(url))
	for _, path := range paths {
		exapandedUrl.WriteString(e.vars.Eval(path))
	}
	return http.PostWithVars(exapandedUrl.String(), e.vars)
}
