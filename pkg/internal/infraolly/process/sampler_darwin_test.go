// Copyright 2020 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
package process

import (
	"errors"
	"testing"

	"github.com/newrelic/infrastructure-agent/pkg/metrics"

	"github.com/newrelic/infrastructure-agent/internal/agent/mocks"
	"github.com/newrelic/infrastructure-agent/pkg/config"
	"github.com/newrelic/infrastructure-agent/pkg/metrics/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestProcessSampler_Sample(t *testing.T) {
	ctx := new(mocks.AgentContext)
	cfg := &config.Config{RunMode: config.ModeRoot}
	ctx.On("Config").Times(3).Return(cfg)

	harvester := &HarvesterMock{}
	sampler := NewProcessSampler(ctx).(*processSampler)
	sampler.harvest = harvester

	samples := []*Sample{
		{
			ProcessDisplayName: "proc 1",
			ProcessID:          1,
		},
		{
			ProcessDisplayName: "proc 2",
			ProcessID:          2,
		},
		{
			ProcessDisplayName: "proc 3",
			ProcessID:          3,
		},
	}
	var pids []int32
	for _, s := range samples {
		pids = append(pids, s.ProcessID)
	}

	harvester.ShouldReturnPids(pids, nil)
	for _, s := range samples {
		harvester.ShouldDo(s.ProcessID, 0, s, nil)
	}

	eventBatch, err := sampler.Sample()
	assert.Nil(t, err)
	assert.Len(t, eventBatch, len(samples))
	for i, e := range eventBatch {
		assert.Equal(t, samples[i], e)
	}

	mock.AssertExpectationsForObjects(t, ctx, harvester)
}

func TestProcessSampler_Sample_ErrorOnProcessShouldNotStop(t *testing.T) {
	ctx := new(mocks.AgentContext)
	cfg := &config.Config{RunMode: config.ModeRoot}
	ctx.On("Config").Times(3).Return(cfg)

	harvester := &HarvesterMock{}
	sampler := NewProcessSampler(ctx).(*processSampler)
	sampler.harvest = harvester

	samples := []struct {
		pid  int32
		name string
		err  error
	}{
		{
			name: "proc 1",
			pid:  1,
		},
		{
			name: "proc 2",
			pid:  2,
			err:  errors.New("some error"),
		},
		{
			name: "proc 3",
			pid:  3,
		},
	}
	var pids []int32
	for _, s := range samples {
		pids = append(pids, s.pid)
	}

	harvester.ShouldReturnPids(pids, nil)
	for _, s := range samples {
		harvester.ShouldDo(s.pid, 0, &Sample{ProcessID: s.pid, ProcessDisplayName: s.name}, s.err)
	}

	eventBatch, err := sampler.Sample()
	assert.Nil(t, err)
	assert.Len(t, eventBatch, 2)
	assert.Equal(t, int32(1), eventBatch[0].(*Sample).ProcessID)
	assert.Equal(t, int32(3), eventBatch[1].(*Sample).ProcessID)

	mock.AssertExpectationsForObjects(t, ctx, harvester)
}

func TestProcessSampler_Sample_DockerDecorator(t *testing.T) {
	ctx := new(mocks.AgentContext)
	cfg := &config.Config{RunMode: config.ModeRoot}
	ctx.On("Config").Times(3).Return(cfg)

	harvester := &HarvesterMock{}
	sampler := NewProcessSampler(ctx).(*processSampler)
	sampler.harvest = harvester
	sampler.containerSamplers = []metrics.ContainerSampler{&fakeContainerSampler{}}

	samples := []*Sample{
		{
			ProcessDisplayName: "proc 1",
			ProcessID:          1,
		},
		{
			ProcessDisplayName: "proc 2",
			ProcessID:          2,
		},
		{
			ProcessDisplayName: "proc 3",
			ProcessID:          3,
		},
	}
	var pids []int32
	for _, s := range samples {
		pids = append(pids, s.ProcessID)
	}

	harvester.ShouldReturnPids(pids, nil)
	for _, s := range samples {
		harvester.ShouldDo(s.ProcessID, 0, s, nil)
	}

	eventBatch, err := sampler.Sample()
	assert.Nil(t, err)
	assert.Len(t, eventBatch, len(samples))
	for i, e := range eventBatch {
		flatProcessSample := e.(*types.FlatProcessSample)
		assert.Equal(t, float64(samples[i].ProcessID), (*flatProcessSample)["processId"])
		assert.Equal(t, samples[i].ProcessDisplayName, (*flatProcessSample)["processDisplayName"])
		assert.Equal(t, "decorated", (*flatProcessSample)["containerImage"])
		assert.Equal(t, "value1", (*flatProcessSample)["containerLabel_label1"])
		assert.Equal(t, "value2", (*flatProcessSample)["containerLabel_label2"])
	}

	mock.AssertExpectationsForObjects(t, ctx, harvester)
}
