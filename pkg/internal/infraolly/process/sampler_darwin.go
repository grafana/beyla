// Copyright 2020 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
package process

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"


)

// processSampler is an implementation of the metrics_sender.Sampler interface, which returns runtime information about
// the currently running processes
type processSampler struct {
	harvest           Harvester
	containerSamplers []metrics.ContainerSampler
	lastRun           time.Time
	hasAlreadyRun     bool
	interval          time.Duration
}

var (
	_                       sampler.Sampler = (*processSampler)(nil) // static interface assertion
	containerNotRunningErrs                 = map[string]struct{}{}
)

// NewProcessSampler creates and returns a new process Sampler, given an agent context.
func NewProcessSampler(ctx agent.AgentContext) sampler.Sampler {
	hasConfig := ctx != nil && ctx.Config() != nil

	ttlSecs := config.DefaultContainerCacheMetadataLimit
	apiVersion := ""
	interval := config.FREQ_INTERVAL_FLOOR_PROCESS_METRICS
	dockerContainerdNamespace := ""
	if hasConfig {
		cfg := ctx.Config()
		ttlSecs = cfg.ContainerMetadataCacheLimit
		apiVersion = cfg.DockerApiVersion
		dockerContainerdNamespace = cfg.DockerContainerdNamespace
		interval = cfg.MetricsProcessSampleRate
	}
	harvester := newHarvester(ctx)
	containerSamplers := metrics.GetContainerSamplers(time.Duration(ttlSecs)*time.Second, apiVersion, dockerContainerdNamespace)

	return &processSampler{
		harvest:           harvester,
		containerSamplers: containerSamplers,
		interval:          time.Second * time.Duration(interval),
	}

}

func (ps *processSampler) OnStartup() {}

func (ps *processSampler) Name() string {
	return "ProcessSampler"
}

func (ps *processSampler) Interval() time.Duration {
	return ps.interval
}

func (ps *processSampler) Disabled() bool {
	return ps.Interval() <= config.FREQ_DISABLE_SAMPLING
}

// Sample returns samples for all the running processes, decorated with container runtime information, if applies.
func (ps *processSampler) Sample() (results sample.EventBatch, err error) {
	var elapsedMs int64
	var elapsedSeconds float64
	now := time.Now()
	if ps.hasAlreadyRun {
		elapsedMs = (now.UnixNano() - ps.lastRun.UnixNano()) / 1000000
	}
	elapsedSeconds = float64(elapsedMs) / 1000
	ps.lastRun = now

	pids, err := ps.harvest.Pids()
	if err != nil {
		return nil, err
	}

	var containerDecorators []metrics.ProcessDecorator

	for _, containerSampler := range ps.containerSamplers {
		if !containerSampler.Enabled() {
			continue
		}

		decorator, err := containerSampler.NewDecorator()
		if err != nil {
			// ensure containerDecorator is set to nil if error
			decorator = nil
			if id := containerIDFromNotRunningErr(err); id != "" {
				if _, ok := containerNotRunningErrs[id]; !ok {
					containerNotRunningErrs[id] = struct{}{}
					mplog.WithError(err).Warn("instantiating container sampler process decorator")
				}
			} else {
				mplog.WithError(err).Warn("instantiating container sampler process decorator")
				if strings.Contains(err.Error(), "client is newer than server") {
					mplog.WithError(err).Error("Only docker api version from 1.24 upwards are officially supported. You can still use the docker_api_version configuration to work with older versions. You can check https://docs.docker.com/develop/sdk/ what api version maps with each docker version.")
				}
			}
		} else {
			containerDecorators = append(containerDecorators, decorator)
		}
	}

	for _, pid := range pids {
		var processSample *Sample
		var err error

		processSample, err = ps.harvest.Do(pid, elapsedSeconds)
		if err != nil {
			procLog := mplog.WithError(err)
			if errors.Is(err, errProcessWithoutRSS) {
				procLog = procLog.WithField(config.TracesFieldName, config.ProcessTrace)
			}

			procLog.WithField("pid", pid).Debug("Skipping process.")
			continue
		}

		for _, containerDecorator := range containerDecorators {
			if containerDecorator != nil {
				containerDecorator.Decorate(processSample)
			}
		}

		results = append(results, ps.normalizeSample(processSample))
	}

	ps.hasAlreadyRun = true
	return results, nil
}

func (ps *processSampler) normalizeSample(s *Sample) sample.Event {
	if len(s.ContainerLabels) > 0 {
		sb, err := json.Marshal(s)
		if err == nil {
			bm := &types.FlatProcessSample{}
			if err = json.Unmarshal(sb, bm); err == nil {
				for name, value := range s.ContainerLabels {
					key := fmt.Sprintf("containerLabel_%s", name)
					(*bm)[key] = value
				}
				return bm
			}
		} else {
			mplog.WithError(err).WithField("sample", fmt.Sprintf("%+v", s)).Debug("normalizeSample can't operate on the sample.")
		}
	}
	return s
}

func containerIDFromNotRunningErr(err error) string {
	prefix := "Error response from daemon: Container "
	suffix := " is not running"
	msg := err.Error()
	i := strings.Index(msg, prefix)
	j := strings.Index(msg, suffix)
	if i == -1 || j == -1 {
		return ""
	}
	return msg[len(prefix):j]
}
