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

// processSampler returns runtime information about the currently running processes
type processSampler struct {
	harvest  Harvester
	interval time.Duration
	cache    *simplelru.LRU[int32, *cacheEntry]
	log      *slog.Logger
}

// NewProcessSampler creates and returns a new process Sampler, given an agent context.
func NewProcessSampler(cfg Config) pipe.StartFunc[[]Sample] {
	// we purge entries explicitly so size is unbounded
	cache, _ := simplelru.NewLRU[int32, *cacheEntry](math.MaxInt, nil)
	harvest := newHarvester(cfg, cache)

	return (&processSampler{
		harvest:  harvest,
		cache:    cache,
		interval: cfg.Rate,
		log:      pslog(),
	}).Run
}

func (ps *processSampler) Run(out chan<- []Sample) {
	_ = out
}

// Sample returns samples for all the running processes, decorated with Docker runtime information, if applies.
func (ps *processSampler) Sample() ([]*Sample, error) {
	pids, err := ps.harvest.Pids()
	if err != nil {
		return nil, err
	}
	results := make([]*Sample, 0, len(pids))

	for _, pid := range pids {
		processSample, err := ps.harvest.Do(pid)
		if err != nil {
			ps.log.Debug("skipping process", "pid", pid, "error", err)
			continue
		}

		results = append(results, processSample)
	}

	removeUntilLen(ps.cache, len(pids))

	return results, nil
}
