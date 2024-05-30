// Copyright 2020 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//go:build linux

package process

import (
	"context"
	"log/slog"
	"math"
	"time"

	"github.com/hashicorp/golang-lru/v2/simplelru"
	"github.com/mariomac/pipes/pipe"

	"github.com/grafana/beyla/pkg/internal/request"
)

// Collector returns runtime information about the currently running processes
type Collector struct {
	ctx     context.Context
	cfg     *Config
	harvest Harvester
	cache   *simplelru.LRU[int32, *cacheEntry]
	log     *slog.Logger
	newPids *<-chan []request.Span
}

// NewCollectorProvider creates and returns a new process Collector, given an agent context.
func NewCollectorProvider(ctx context.Context, input *<-chan []request.Span, cfg *Config) pipe.StartProvider[[]*Status] {
	return func() (pipe.StartFunc[[]*Status], error) {
		// we purge entries explicitly so size is unbounded
		cache, _ := simplelru.NewLRU[int32, *cacheEntry](math.MaxInt, nil)
		harvest := newHarvester(cfg, cache)

		return (&Collector{
			ctx:     ctx,
			cfg:     cfg,
			harvest: harvest,
			cache:   cache,
			log:     pslog(),
			newPids: input,
		}).Run, nil
	}
}

func (ps *Collector) Run(out chan<- []*Status) {
	// TODO: set app metadata as key for later decoration? (e.g. K8s metadata, svc.ID)
	pids := map[int32]struct{}{}
	collectTicker := time.NewTicker(ps.cfg.Rate)
	newPids := *ps.newPids
	for {
		select {
		case <-ps.ctx.Done():
			ps.log.Debug("exiting")
		case spans := <-newPids:
			// updating PIDs map with spans information
			for i := range spans {
				pids[int32(spans[i].Pid.UserPID)] = struct{}{}
			}
		case <-collectTicker.C:
			ps.log.Debug("start process collection")
			procs, removed := ps.Collect(pids)
			for _, rp := range removed {
				pids[rp] = struct{}{}
			}
			out <- procs
		}
	}
}

// Collect returns the status for all the running processes, decorated with Docker runtime information, if applies.
// It also returns the PIDs that have to be removed from the map, as they do not exist anymore
func (ps *Collector) Collect(pids map[int32]struct{}) ([]*Status, []int32) {
	results := make([]*Status, 0, len(pids))

	var removed []int32
	for pid := range pids {
		status, err := ps.harvest.Do(pid)
		if err != nil {
			ps.log.Debug("skipping process", "pid", pid, "error", err)
			removed = append(removed, pid)
			continue
		}

		results = append(results, status)
	}

	removeUntilLen(ps.cache, len(pids))

	return results, removed
}
