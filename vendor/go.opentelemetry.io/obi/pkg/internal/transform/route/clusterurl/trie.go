// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package clusterurl // import "go.opentelemetry.io/obi/pkg/internal/transform/route/clusterurl"

import (
	"strings"
	"sync"
)

// PathNode represents a node in the path trie
type PathNode struct {
	// segment is the path component (e.g., "test", "files")
	segment string

	// children maps segment values to their nodes
	// e.g., children["bar/attach/generic-product-apjkmyp"] = &PathNode{...}
	children map[string]*PathNode

	// collapsed indicates if this node has been collapsed to "*"
	collapsed bool

	// cardinality tracks how many unique children this node has
	cardinality int

	// isWildcard indicates if this represents a "*" wildcard
	isWildcard bool
}

// PathTrie manages the dynamic collapsing trie structure
type PathTrie struct {
	root           *PathNode
	maxCardinality int
	mu             sync.RWMutex
	replaceWith    string
}

// NewPathTrie creates a new path trie with the given max cardinality
func NewPathTrie(maxCardinality int, replacement byte) *PathTrie {
	return &PathTrie{
		root: &PathNode{
			segment:  "",
			children: make(map[string]*PathNode),
		},
		maxCardinality: maxCardinality,
		replaceWith:    string(replacement),
	}
}

func isHTTPOp(op string) bool {
	return op == "GET" || op == "POST" || op == "PATCH" || op == "DELETE" || op == "OPTIONS" || op == "HEAD"
}

func (pt *PathTrie) cleanup(path string) string {
	i := strings.Index(path, "?")
	if i >= 0 {
		path = path[:i]
	}

	if path == "" || path[0] == '/' {
		return path
	}

	i = strings.Index(path, " ")
	if i > 0 {
		op := path[:i]
		if isHTTPOp(op) && i < len(path) {
			return path[i+1:]
		}
	}

	return path
}

// Insert adds a path to the trie and returns the normalized path
// If a segment exceeds maxCardinality, it collapses to "*"
func (pt *PathTrie) Insert(path string) string {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	path = pt.cleanup(path)

	segments := strings.Split(strings.Trim(path, "/"), "/")
	if len(segments) == 0 || (len(segments) == 1 && segments[0] == "") {
		return path
	}

	return pt.insertSegments(segments)
}

func (pt *PathTrie) insertSegments(segments []string) string {
	current := pt.root
	result := make([]string, 0, len(segments))

	for _, segment := range segments {
		if segment == "" {
			result = append(result, segment)
			continue
		}

		// If current node is already collapsed, all children become wildcards
		if current.collapsed {
			result = append(result, pt.replaceWith)
			// Continue with the wildcard child
			if current.children[pt.replaceWith] == nil {
				current.children[pt.replaceWith] = &PathNode{
					segment:    pt.replaceWith,
					children:   make(map[string]*PathNode),
					isWildcard: true,
				}
			}
			current = current.children[pt.replaceWith]
			continue
		}

		// Check if this segment already exists
		child, exists := current.children[segment]

		if !exists {
			// New segment - check if we need to collapse
			if current.cardinality >= pt.maxCardinality {
				// Collapse this level
				pt.collapseNode(current)
				result = append(result, pt.replaceWith)
				current = current.children[pt.replaceWith]
				continue
			}

			// Create new child
			child = &PathNode{
				segment:  segment,
				children: make(map[string]*PathNode),
			}
			current.children[segment] = child
			current.cardinality++

			// Check if we just hit the threshold
			if current.cardinality > pt.maxCardinality {
				pt.collapseNode(current)
				result = append(result, pt.replaceWith)
				current = current.children[pt.replaceWith]
				continue
			}
		}

		result = append(result, segment)
		current = child
	}

	return "/" + strings.Join(result, "/")
}

// collapseNode collapses a node by replacing all children with a single wildcard
// and merging their children into the wildcard node
func (pt *PathTrie) collapseNode(node *PathNode) {
	if node.collapsed {
		return
	}

	node.collapsed = true

	// Create or get wildcard node
	wildcardNode, hasWildcard := node.children[pt.replaceWith]
	if !hasWildcard {
		wildcardNode = &PathNode{
			segment:    pt.replaceWith,
			children:   make(map[string]*PathNode),
			isWildcard: true,
		}
	}

	// Merge all children into the wildcard node
	for segment, child := range node.children {
		if segment == pt.replaceWith {
			continue // Skip the wildcard itself
		}
		pt.mergeChildren(wildcardNode, child)
	}

	// Replace all children with just the wildcard
	node.children = map[string]*PathNode{
		pt.replaceWith: wildcardNode,
	}
	node.cardinality = 1

	// Recursively check if wildcard node needs collapsing
	if wildcardNode.cardinality > pt.maxCardinality {
		pt.collapseNode(wildcardNode)
	}
}

// mergeChildren merges children from source into target
// This is called during collapse to combine all child paths
func (pt *PathTrie) mergeChildren(target, source *PathNode) {
	for segment, child := range source.children {
		if existing, exists := target.children[segment]; exists {
			// Child already exists, recursively merge their children
			pt.mergeChildren(existing, child)
		} else {
			// New child, add it
			target.children[segment] = child
			target.cardinality++
		}
	}
}
