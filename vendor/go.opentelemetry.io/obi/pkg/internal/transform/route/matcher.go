// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package route // import "go.opentelemetry.io/obi/pkg/internal/transform/route"

import (
	"regexp"
	"strings"
)

// wildcard format. By now, we will suppport wildcards in the form:
// - /user/:userId/details (Gin)
// - /user/{userId}/details (Gorilla)
// More formats will be appended at some point
var wildcard = regexp.MustCompile(`^((:\w*)|(\{\w*}))$`)

type Matcher interface {
	Find(string) string
}

// Matcher allows matching a given URL path towards a set of framework-like provided
// patterns.
type CompleteRouteMatcher struct {
	root *node
}

// node allows searching, folder by folder, a given path towards a registered route
type node struct {
	// FullRoute that this node matches to, even if it's not a tree leave. If empty, this node
	// does not match any route.
	FullRoute string

	// Child nodes for a given path folder
	Child map[string]*node

	// Patterns are child subtrees matching a single path folder. A pattern with an
	// empty prefix (e.g. ":id" or "{id}") matches any folder; a pattern with a literal
	// prefix (e.g. "@:username", common in Rails or Sinatra) matches folders starting
	// with that text, since the placeholder always runs to the end of the folder.
	// As multiple partial patterns can be defined in the same path position, we store
	// them as a slice and evaluate them in definition order, e.g.:
	// /users/admin:userid/info
	// /users/:userid/info
	// It is up to the user to declare the more specific patterns first, since a
	// catch-all (empty prefix) would otherwise shadow any pattern defined after it.
	Patterns []*partialPattern

	// AnyPath node is a node identified by '*', which terminates the search matching what's found
	AnyPath *node
}

// partialPattern matches a single path folder against a placeholder that runs to
// the end of the folder. When prefix is empty it is a catch-all wildcard
// (":id"/"{id}") matching any folder; otherwise it matches folders starting with
// the literal prefix (e.g. "@:username"), which must hold at least one extra
// character for the placeholder.
type partialPattern struct {
	// prefix is the literal text before the placeholder (empty for a catch-all)
	prefix string
	// node is the child subtree reached when the folder matches
	node *node
}

// matches reports whether the given path folder satisfies the pattern. A catch-all
// (empty prefix) matches any folder. Otherwise the folder must start with the literal
// prefix and hold at least one more character for the placeholder value. Additionally,
// the prefix must not be merely a sub-prefix of a longer word in the folder (e.g. the
// prefix "prefix" matches "prefix:1234" but not "prefixbutlonger:1234"): a colon boundary
// is required between the end of the prefix and the start of the placeholder value, so
// the match is rejected when both are word characters.
func (w *partialPattern) matches(folder string) bool {
	if w.prefix == "" {
		return true
	}
	return len(folder) > len(w.prefix) && strings.HasPrefix(folder, w.prefix)
}

// NewMatcher creates a new Matcher that would allow validating given URL paths towards
// the provided set of routes
func NewMatcher(routes []string) *CompleteRouteMatcher {
	m := CompleteRouteMatcher{root: &node{Child: map[string]*node{}}}
	for _, route := range routes {
		appendRoute(route, tokenize(route), m.root)
	}
	return &m
}

// Find the router pattern that would match a given URL path, or empty if no pattern
// matches it.
func (rm *CompleteRouteMatcher) Find(path string) string {
	return find(tokenize(path), rm.root)
}

func find(path []string, pathNode *node) string {
	// if we walked all the path tokens and this node resolves to a full route, it matched a path
	// (if FullRoute is empty, it means it didn't match)
	if len(path) == 0 {
		return pathNode.FullRoute
	}
	// if the current path resolved to an explicit path folder, keep searching through the
	// child node
	if child, ok := pathNode.Child[path[0]]; ok {
		return find(path[1:], child)
	}
	// otherwise, try the pattern children in definition order; the first match wins,
	// so more specific patterns (e.g. "@:username") must be declared before a catch-all
	for _, w := range pathNode.Patterns {
		if w.matches(path[0]) {
			if fullRoute := find(path[1:], w.node); fullRoute != "" {
				return fullRoute
			}
		}
	}
	if pathNode.AnyPath != nil {
		return pathNode.FullRoute
	}
	return ""
}

func appendRoute(fullRoute string, path []string, pathNode *node) {
	// if we walked all the path tokens, the current node resolves to the full route
	if len(path) == 0 {
		pathNode.FullRoute = fullRoute
		return
	}
	currentName := path[0]
	// if the current token is a full-folder wildcard (":id"/"{id}"), register it as a
	// catch-all pattern (empty prefix)
	if wildcard.MatchString(currentName) {
		appendRoute(fullRoute, path[1:], pathNode.pattern(""))
		return
	}

	if currentName == "*" {
		pathNode.FullRoute = fullRoute
		pathNode.AnyPath = &node{Child: map[string]*node{}}
		return
	}

	// if the current token has a literal prefix before a colon placeholder (e.g. "@:username"),
	// register it as a pattern matching any folder starting with that prefix
	if prefix, ok := colonPrefix(currentName); ok {
		appendRoute(fullRoute, path[1:], pathNode.pattern(prefix))
		return
	}

	// keep processing the child node belonging to the current path token, adding it
	// if it does not yet exist
	child, ok := pathNode.Child[currentName]
	if !ok {
		child = &node{Child: map[string]*node{}}
		pathNode.Child[currentName] = child
	}
	appendRoute(fullRoute, path[1:], child)
}

// pattern returns the child subtree for a pattern with the given literal prefix,
// creating it if necessary. Patterns sharing the same prefix (e.g. ":id" and
// ":userId", or "@:user" and "@:name") are merged into one node so their subtrees
// combine. New prefixes are appended, preserving definition order for matching.
func (n *node) pattern(prefix string) *node {
	for _, w := range n.Patterns {
		if w.prefix == prefix {
			return w.node
		}
	}
	w := &partialPattern{prefix: prefix, node: &node{Child: map[string]*node{}}}
	n.Patterns = append(n.Patterns, w)
	return w.node
}

// colonPrefix detects a path folder that has literal text before a ":var"
// placeholder (e.g. "@:username") and returns that literal prefix. The placeholder
// is assumed to run to the end of the folder, so any text after the colon is
// ignored. It returns false when the folder has no colon, or when the colon is at
// the start (a full wildcard like ":id", handled elsewhere).
func colonPrefix(segment string) (prefix string, ok bool) {
	colon := strings.IndexByte(segment, ':')
	if colon <= 0 {
		return "", false
	}
	return segment[:colon], true
}

// tokenizes and normalizes the resulting slice, so we make sure
// that neither the first nor last tokens are empty tokens
func tokenize(path string) []string {
	folders := strings.Split(path, "/")
	if len(folders) > 0 && folders[0] == "" {
		folders = folders[1:]
	}
	if len(folders) > 0 && folders[len(folders)-1] == "" {
		folders = folders[:len(folders)-1]
	}
	return folders
}
