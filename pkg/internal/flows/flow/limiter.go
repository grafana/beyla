// Copyright Red Hat / IBM
// Copyright Grafana Labs
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

// This implementation is a derivation of the code in
// https://github.com/netobserv/netobserv-ebpf-agent/tree/release-1.4

package flow

import (
	"time"

	"github.com/sirupsen/logrus"
)

const initialLogPeriod = time.Minute
const maxLogPeriod = time.Hour

var cllog = logrus.WithField("component", "capacity.Limiter")

// CapacityLimiter forwards the flows between two nodes but checks the status of the destination
// node's buffered channel. If it is already full, it drops the incoming flow and periodically will
// log a message about the number of lost flows.
type CapacityLimiter struct {
	droppedFlows int
}

func (c *CapacityLimiter) Limit(in <-chan []*Record, out chan<- []*Record) {
	go c.logDroppedFlows()
	for i := range in {
		if len(out) < cap(out) || cap(out) == 0 {
			out <- i
		} else {
			c.droppedFlows += len(i)
		}
	}
}

func (c *CapacityLimiter) logDroppedFlows() {
	logPeriod := initialLogPeriod
	debugging := logrus.IsLevelEnabled(logrus.DebugLevel)
	for {
		time.Sleep(logPeriod)

		// a race condition might happen in this counter but it's not important as it's just for
		// logging purposes
		df := c.droppedFlows
		if df > 0 {
			c.droppedFlows = 0
			cllog.Warnf("%d flows were dropped during the last %s because the agent is forwarding "+
				"more flows than the remote ingestor is able to process. You might "+
				"want to increase the CACHE_MAX_FLOWS and CACHE_ACTIVE_TIMEOUT property",
				df, logPeriod)

			// if not debug logs, backoff to avoid flooding the log with warning messages
			if !debugging && logPeriod < maxLogPeriod {
				logPeriod *= 2
				if logPeriod > maxLogPeriod {
					logPeriod = maxLogPeriod
				}
			}
		} else {
			logPeriod = initialLogPeriod
		}
	}
}
