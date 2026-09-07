// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package runtime // import "go.opentelemetry.io/obi/pkg/internal/cpython/runtime"

import (
	"errors"

	lru "github.com/hashicorp/golang-lru/v2"
)

const resolverAnalysisCacheSize = 100

type mappedObjectKey struct {
	device uint64
	inode  uint64
}

type elfAnalysisResult struct {
	analysis *elfAnalysis
	err      error
}

type resolverAnalysisCache struct {
	entries *lru.Cache[mappedObjectKey, elfAnalysisResult]
}

func newResolverAnalysisCache() resolverAnalysisCache {
	entries, _ := lru.New[mappedObjectKey, elfAnalysisResult](resolverAnalysisCacheSize)
	return resolverAnalysisCache{entries: entries}
}

// getOrAnalyze caches image-intrinsic results. It leaves transient process and I/O errors retryable.
func (c *resolverAnalysisCache) getOrAnalyze(
	key mappedObjectKey,
	analyze func() (*elfAnalysis, error),
) (*elfAnalysis, error) {
	if c.entries != nil {
		if result, ok := c.entries.Get(key); ok {
			return result.analysis, result.err
		}
	}

	analysis, err := analyze()
	if c.entries != nil && cacheableAnalysisError(err) {
		c.entries.Add(key, elfAnalysisResult{analysis: analysis, err: err})
	}
	return analysis, err
}

func cacheableAnalysisError(err error) bool {
	return err == nil || errors.Is(err, errRuntimeNotFound) || errors.Is(err, errUnsupportedLayout)
}
