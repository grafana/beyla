package regexpcache

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sync/atomic"

	"github.com/alitto/pond/v2"
	lru "github.com/hashicorp/golang-lru/v2"
)

var (
	errNegativeParallelMatches = errors.New("parallel matches cannot be negative")
	errInvalidCacheSize        = errors.New("cache size must be positive")
)

// Config defines the settings for the regexpcache matcher
type Config struct {
	// ParallelMatches defines the number of parallel checks on passed patterns
	ParallelMatches int `yaml:"parallel_matches"`
	// CacheSize determines the LRU size of the cache of argument responses passed to the Match function.
	// The larger the parameter, the faster the matcher runs
	CacheSize int `yaml:"cache_size"`
}

func (cfg Config) validate() error {
	if cfg.ParallelMatches < 0 {
		return errNegativeParallelMatches
	}

	if cfg.CacheSize <= 0 {
		return errInvalidCacheSize
	}

	return nil
}

type matcher struct {
	config        Config
	pool          pond.Pool
	patternRegexp map[string]*regexp.Regexp
	cache         *lru.Cache[string, bool]
}

// NewMatcher constructor for matcher structure
func NewMatcher(config Config, patterns []string) (*matcher, error) {
	if err := config.validate(); err != nil {
		return nil, fmt.Errorf("config validation error: %w", err)
	}

	patternRegexp := make(map[string]*regexp.Regexp)

	for _, pattern := range patterns {
		if _, ok := patternRegexp[pattern]; !ok {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("failed to compile pattern %s: %w", pattern, err)
			}
			patternRegexp[pattern] = re
		}
	}

	cache, err := lru.New[string, bool](config.CacheSize)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize LRU cache: %w", err)
	}

	pool := pond.NewPool(config.ParallelMatches)

	return &matcher{
		config:        config,
		pool:          pool,
		patternRegexp: patternRegexp,
		cache:         cache,
	}, nil
}

// Match checks the incoming input for matching at least one pattern
func (m *matcher) Match(ctx context.Context, input string) bool {
	if cachedRes, ok := m.cache.Get(input); ok {
		return cachedRes
	}

	var matched atomic.Bool

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Concurrently checks patterns, cancels on first match via atomic flag and contex
	for _, re := range m.patternRegexp {
		m.pool.Submit(func() {
			select {
			case <-ctx.Done():
				return
			default:
				if matched.Load() {
					return
				}

				if re.MatchString(input) {
					matched.Store(true)
					cancel()
				}
			}
		})
	}

	m.pool.StopAndWait()

	m.cache.Add(input, matched.Load())
	return matched.Load()
}
