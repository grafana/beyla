// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package clusterurl // import "go.opentelemetry.io/obi/pkg/internal/transform/route/clusterurl"

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"

	"github.com/AlessandroPomponio/go-gibberish/gibberish"
	"github.com/AlessandroPomponio/go-gibberish/structs"
	lru "github.com/hashicorp/golang-lru/v2"
)

type ClusterURLClassifier struct {
	classifier     *structs.GibberishData
	cache          *lru.Cache[string, bool]
	cfg            *Config
	validCharTable [256]bool
}

func NewClusterURLClassifier(config *Config) (*ClusterURLClassifier, error) {
	if config == nil {
		config = DefaultConfig()
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("NewClusterURLClassifier: invalid configuration: %w", err)
	}

	classifier, err := loadKnowledgeBase(config.ModelPath)
	if err != nil {
		return nil, fmt.Errorf("NewClusterURLClassifier: unable to load knowledge base: %w", err)
	}

	cache, err := lru.New[string, bool](config.CacheSize)
	if err != nil {
		return nil, fmt.Errorf("NewClusterURLClassifier: unable to create cache: %w", err)
	}

	// Initialize lookup table for valid characters
	var validCharTable [256]bool
	for c := byte('a'); c <= 'z'; c++ {
		validCharTable[c] = true
	}
	for c := byte('A'); c <= 'Z'; c++ {
		validCharTable[c] = true
	}
	for _, c := range []byte{'-', '_', '.', ' '} {
		validCharTable[c] = true
	}

	return &ClusterURLClassifier{
		classifier:     classifier,
		cache:          cache,
		cfg:            config,
		validCharTable: validCharTable,
	}, nil
}

// This function takes a path and returns a "clustered" path, where
// all the "IDs" in the path are replaced by a single "*" character.
// For example, the path "/foo/42/baz" would be replaced with "/foo/*/baz".
// The purpose of this function is to allow for a large number of paths
// to be grouped into a smaller number of paths.

//nolint:cyclop
func (csf *ClusterURLClassifier) ClusterURL(path string) string {
	if path == "" {
		return path
	}

	p := []byte(path)
	sPos := 0
	sFwd := 0

	skip := false
	skipGrace := true
	nSegments := 0
	for _, c := range p {
		char := c

		// Strip query string and fragment identifiers
		if c == '?' || c == '&' || c == '#' {
			if skip && sPos < len(p) {
				// no other chars, just use ReplaceWith
				p[sPos] = csf.cfg.ReplaceWith
				sPos++
			} else if !skip && sFwd > sPos {
				// preserve chars
				sPos = sFwd
			}

			p = p[:sPos]
			break
		}

		if c == csf.cfg.Separator {
			nSegments++
			if skip {
				p[sPos] = csf.cfg.ReplaceWith
				sPos++
			} else if sFwd > sPos {
				if !csf.okWord(string(p[sPos:sFwd])) {
					p[sPos] = csf.cfg.ReplaceWith
					sPos++
				} else {
					sPos = sFwd
				}
			}

			if nSegments >= csf.cfg.MaxSegments {
				break
			}

			p[sPos] = char
			sPos++
			sFwd = sPos
			skip = false
			skipGrace = true
		} else if !skip {
			p[sFwd] = c
			sFwd++
			if !csf.validCharTable[c] {
				if skipGrace && (sFwd-sPos) == 2 {
					skipGrace = false
					continue
				}
				skip = true
			}
		}
	}

	// this can happen if we have path with ?, & or # and all invalid chars, but no /
	if len(p) == 0 {
		return ""
	}

	if skip {
		if sPos < len(p) {
			p[sPos] = csf.cfg.ReplaceWith
			sPos++
		}
	} else if sFwd > sPos {
		if !csf.okWord(string(p[sPos:sFwd])) {
			if sPos < len(p) {
				p[sPos] = csf.cfg.ReplaceWith
				sPos++
			}
		} else {
			sPos = sFwd
		}
	}

	return string(p[:sPos])
}

func (csf *ClusterURLClassifier) okWord(w string) bool {
	_, ok := csf.cache.Get(w)
	if ok {
		return ok
	}

	start := 0
	for i, c := range w {
		if c == '-' || c == '_' || c == '.' {
			if i == start {
				return false
			}

			if gibberish.IsGibberish(w[start:i], csf.classifier) {
				return false
			}

			start = i + 1
		}
	}

	if start < len(w) {
		if gibberish.IsGibberish(w[start:], csf.classifier) {
			return false
		}
	}

	csf.cache.Add(w, true)
	return true
}

//go:embed model.json
var dataFile embed.FS

func loadKnowledgeBase(path string) (*structs.GibberishData, error) {
	var content []byte
	var err error
	if path != "" {
		content, err = os.ReadFile(path)
	} else {
		content, err = dataFile.ReadFile("model.json")
	}

	if err != nil {
		return nil, fmt.Errorf("loadKnowledgeBase: unable to read knowledge base content: %w", err)
	}

	var data structs.GibberishData
	err = json.Unmarshal(content, &data)
	if err != nil {
		return nil, fmt.Errorf("loadKnowledgeBase: unable to unmarshal knowledge base content: %w", err)
	}

	return &data, nil
}
