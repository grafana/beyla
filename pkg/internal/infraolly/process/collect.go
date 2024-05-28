// Copyright 2020 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//go:build linux

package process

import (
	"log/slog"
	"math"
	"time"

	"github.com/hashicorp/golang-lru/v2/simplelru"
	"github.com/mariomac/pipes/pipe"
)

// Collector returns runtime information about the currently running processes
type Collector struct {
	harvest  Harvester
	interval time.Duration
	cache    *simplelru.LRU[int32, *cacheEntry]
	log      *slog.Logger
}

// NewCollector creates and returns a new process Collector, given an agent context.
func NewCollector(cfg Config) pipe.StartFunc[[]Status] {
	// we purge entries explicitly so size is unbounded
	cache, _ := simplelru.NewLRU[int32, *cacheEntry](math.MaxInt, nil)
	harvest := newHarvester(cfg, cache)

	return (&Collector{
		harvest:  harvest,
		cache:    cache,
		interval: cfg.Rate,
		log:      pslog(),
	}).Run
}

func (ps *Collector) Run(out chan<- []Status) {
	_ = out
}

// Collect returns the status for all the running processes, decorated with Docker runtime information, if applies.
func (ps *Collector) Collect() ([]*Status, error) {
	pids, err := ps.harvest.Pids()
	if err != nil {
		return nil, err
	}
	results := make([]*Status, 0, len(pids))

	for _, pid := range pids {
		status, err := ps.harvest.Do(pid)
		if err != nil {
			ps.log.Debug("skipping process", "pid", pid, "error", err)
			continue
		}

		results = append(results, status)
	}

	removeUntilLen(ps.cache, len(pids))

	return results, nil
}
