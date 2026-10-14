// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package phptools // import "go.opentelemetry.io/obi/pkg/internal/phptools"

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

const maxProjectScanCacheEntries = 128

// scanTTL bounds how long any scan result, found or not, is reused before the next lookup.
// Without a TTL a stale positive result would never pick up the new release and a stale negative
// result would never notice the deploy complete. This is needed because some PHP frameworks seems
// to support overwriting the actual contents of a running app and then restarting.
var scanTTL = 30 * time.Second

var processRootScanCache = newProjectScanCache(maxProjectScanCacheEntries)

type projectScanner func(root, boundary string) (ProjectMetadata, bool)

type projectScanCache struct {
	mu      sync.Mutex
	entries *lru.Cache[string, cachedProjectScan]
}

type cachedProjectScan struct {
	found        bool
	relativeRoot string
	name         string
	version      string
	fallbackName string
	cachedAt     time.Time
}

// stale reports whether a cached result is old enough to be treated as a miss.
func (c cachedProjectScan) stale() bool {
	return time.Since(c.cachedAt) > scanTTL
}

func newProjectScanCache(capacity int) *projectScanCache {
	entries, err := lru.New[string, cachedProjectScan](capacity)
	if err != nil {
		panic(err)
	}
	return &projectScanCache{entries: entries}
}

func (c *projectScanCache) scan(root, boundary string, scanner projectScanner) (ProjectMetadata, bool) {
	rootID, ok := processRootIdentity(root)
	if !ok {
		return scanner(root, boundary)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if result, found := c.entries.Get(rootID); found && !result.stale() {
		return result.resolve(root)
	}

	project, found := scanner(root, boundary)

	// Re-derive the identity after the scan. The root can be reassigned to a different
	// process (PID reuse) while the scan is in flight, and caching under the pre-scan
	// rootID would then attribute this result to whatever process holds that identity now.
	currentRootID, current := processRootIdentity(root)
	if !current || currentRootID != rootID {
		return project, found
	}

	result, ok := newCachedProjectScan(root, project, found)
	if ok {
		c.entries.Add(rootID, result)
	}
	return project, found
}

func processRootIdentity(root string) (string, bool) {
	if _, err := os.Stat(root); err != nil {
		return "", false
	}

	// The PID portion changes between FPM workers, while the namespace and root target do not.
	processDir := filepath.Dir(root)
	mountNamespace, namespaceErr := os.Readlink(filepath.Join(processDir, "ns", "mnt"))
	rootTarget, rootErr := os.Readlink(root)
	if namespaceErr == nil && rootErr == nil {
		return mountNamespace + "\x00" + rootTarget, true
	}

	return filepath.Clean(root), true
}

func newCachedProjectScan(root string, project ProjectMetadata, found bool) (cachedProjectScan, bool) {
	if !found {
		return cachedProjectScan{cachedAt: time.Now()}, true
	}

	relativeRoot, err := filepath.Rel(root, project.Root)
	if err != nil || relativeRoot == ".." || strings.HasPrefix(relativeRoot, ".."+string(filepath.Separator)) {
		return cachedProjectScan{}, false
	}

	return cachedProjectScan{
		found:        true,
		relativeRoot: relativeRoot,
		name:         project.Name,
		version:      project.Version,
		fallbackName: project.FallbackName,
		cachedAt:     time.Now(),
	}, true
}

func (c cachedProjectScan) resolve(root string) (ProjectMetadata, bool) {
	if !c.found {
		return ProjectMetadata{}, false
	}
	return ProjectMetadata{
		Root:         filepath.Join(root, c.relativeRoot),
		Name:         c.name,
		Version:      c.version,
		FallbackName: c.fallbackName,
	}, true
}
