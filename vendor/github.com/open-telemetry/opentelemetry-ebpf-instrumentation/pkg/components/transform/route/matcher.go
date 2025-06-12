package route

import (
	"regexp"
	"strings"
)

// wildcard format. By now, we will suppport wildcards in the form:
// - /user/:userId/details (Gin)
// - /user/{userId}/details (Gorilla)
// More formats will be appended at some point
var wildcard = regexp.MustCompile(`^((:\w*)|(\{\w*}))$`)

// Matcher allows matching a given URL path towards a set of framework-like provided
// patterns.
type Matcher struct {
	root *node
}

// node allows searching, folder by folder, a given path towards a registered route
type node struct {
	// FullRoute that this node matches to, even if it's not a tree leave. If empty, this node
	// does not match any route.
	FullRoute string

	// Child nodes for a given path folder
	Child map[string]*node

	// Wildcard is a child subtree that, if not nil, matches any path folder
	Wildcard *node

	// AnyPath node is a node identified by '*', which terminates the search matching what's found
	AnyPath *node
}

// NewMatcher creates a new Matcher that would allow validating given URL paths towards
// the provided set of routes
func NewMatcher(routes []string) Matcher {
	m := Matcher{root: &node{Child: map[string]*node{}}}
	for _, route := range routes {
		appendRoute(route, tokenize(route), m.root)
	}
	return m
}

// Find the router pattern that would match a given URL path, or empty if no pattern
// matches it.
func (rm *Matcher) Find(path string) string {
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
	if pathNode.AnyPath != nil {
		return pathNode.FullRoute
	}
	// otherwise, keep searching through the wildcard child, if any
	if pathNode.Wildcard != nil {
		return find(path[1:], pathNode.Wildcard)
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
	// if the current token is a wildcard, add it as a child and keep processing the
	// wildcard node
	if wildcard.MatchString(currentName) {
		if pathNode.Wildcard == nil {
			pathNode.Wildcard = &node{Child: map[string]*node{}}
		}
		appendRoute(fullRoute, path[1:], pathNode.Wildcard)
		return
	}

	if currentName == "*" {
		pathNode.FullRoute = fullRoute
		pathNode.AnyPath = &node{Child: map[string]*node{}}
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
