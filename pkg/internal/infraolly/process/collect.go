// Copyright 2020 New Relic Corporation
// Copyright 2024 Grafana Labs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// This implementation was inspired by the code in https://github.com/newrelic/infrastructure-agent

package process

import (
	"context"
	"log/slog"
	"math"
	"time"

	"github.com/hashicorp/golang-lru/v2/simplelru"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

type CollectConfig struct {
	// RunMode defaults to "privileged". A non-privileged harvester will omit some information like open FDs.
	// TODO: move to an upper layer
	RunMode RunMode

	// Interval between harvests
	// nolint:undoc
	Interval time.Duration `yaml:"interval" env:"BEYLA_PROCESSES_INTERVAL"`
}

// Collector returns runtime information about the currently running processes.
// The collector receives each application trace from the newPids internal channel,
// to know which PIDs are active.
type Collector struct {
	cfg                *CollectConfig
	harvest            *Harvester
	cache              *simplelru.LRU[int32, *linuxProcess]
	log                *slog.Logger
	newPids            <-chan []request.Span
	collectedProcesses *msg.Queue[[]*Status]
}

// NewCollectorProvider creates and returns a new process Collector, given an agent context.
func NewCollectorProvider(
	cfg *CollectConfig,
	in <-chan []request.Span,
	out *msg.Queue[[]*Status],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		// we purge entries explicitly so size is unbounded
		cache, _ := simplelru.NewLRU[int32, *linuxProcess](math.MaxInt, nil)
		collector := &Collector{
			cfg:                cfg,
			harvest:            newHarvester(cfg, cache),
			cache:              cache,
			log:                pslog(),
			newPids:            in,
			collectedProcesses: out,
		}
		return collector.Run, nil
	}
}

func (ps *Collector) Run(ctx context.Context) {
	// TODO: set app metadata as key for later decoration? (e.g. K8s metadata, svc.Attrs)
	pids := map[int32]*svc.Attrs{}
	collectTicker := time.NewTicker(ps.cfg.Interval)
	defer ps.collectedProcesses.Close()
	defer collectTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			ps.log.Debug("exiting process collector")
			return
		case spans := <-ps.newPids:
			// updating PIDs map with spans information
			for i := range spans {
				pids[spans[i].Service.ProcPID] = &spans[i].Service
			}
		case <-collectTicker.C:
			procs, removed := ps.Collect(pids)
			for _, rp := range removed {
				delete(pids, rp)
			}
			ps.collectedProcesses.Send(procs)
		}
	}
}

// Collect returns the status for all the running processes, decorated with Docker runtime information, if applies.
// It also returns the PIDs that have to be removed from the map, as they do not exist anymore
func (ps *Collector) Collect(pids map[int32]*svc.Attrs) ([]*Status, []int32) {
	results := make([]*Status, 0, len(pids))

	var removed []int32
	for pid, svcID := range pids {
		status, err := ps.harvest.Harvest(svcID)
		if err != nil {
			ps.log.Debug("skipping process", "pid", pid, "error", err)
			ps.harvest.cache.Remove(pid)
			removed = append(removed, pid)
			continue
		}

		results = append(results, status)
	}

	// remove processes from cache that haven't been collected in this iteration
	// (this means they already disappeared so there is no need for caching)
	for ps.cache.Len() > len(results) {
		ps.cache.RemoveOldest()
	}

	return results, removed
}
