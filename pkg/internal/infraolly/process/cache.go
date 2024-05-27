// Copyright 2020 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//go:build linux

package process

import (
	"github.com/hashicorp/golang-lru/v2/simplelru"
)

type cacheEntry struct {
	process    *linuxProcess
	lastSample *Sample // The last event we generated for this process, so we can re-use metadata that doesn't change
}

// removeUntilLen removes the oldest entries until the cache reaches the given length.
func removeUntilLen(c *simplelru.LRU[int32, *cacheEntry], newLength int) {
	for c.Len() > newLength {
		c.RemoveOldest()
	}
}
