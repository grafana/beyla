// Copyright 2020 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
package process

import (
	"fmt"
	"math"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/golang-lru/v2/simplelru"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestLinuxHarvester_IsPrivileged(t *testing.T) {
	cases := []struct {
		mode       string
		privileged bool
	}{
		{mode: config.ModeRoot, privileged: true},
		{mode: config.ModePrivileged, privileged: true},
		{mode: config.ModeUnprivileged, privileged: false},
	}
	for _, c := range cases {
		t.Run(fmt.Sprint("mode ", c.mode), func(t *testing.T) {
			ctx := new(mocks.AgentContext)
			ctx.On("Config").Return(&config.Config{RunMode: c.mode})
			ctx.On("GetServiceForPid", mock.Anything).Return("", false)

			cache, _ := simplelru.NewLRU[int32, *cacheEntry](math.MaxInt, nil)
			h := newHarvester(ctx, &cache)

			// If not privileged, it is expected to not report neither FDs nor IO counters
			sample, err := h.Do(int32(os.Getpid()), 100)
			require.NoError(t, err)
			if c.privileged {
				assert.NotNil(t, sample.FdCount)
				assert.NotNil(t, sample.IOTotalReadCount)
			} else {
				assert.Nil(t, sample.FdCount)
				assert.Nil(t, sample.IOTotalReadCount)
			}
		})
	}
}

func TestLinuxHarvester_Pids(t *testing.T) {
	// Given a process harvester
	ctx := new(mocks.AgentContext)
	ctx.On("Config").Return(&config.Config{})
	cache, _ := simplelru.NewLRU[int32, *cacheEntry](math.MaxInt, nil)
	h := newHarvester(ctx, &cache)

	// When th Pids are retrieved
	pids, err := h.Pids()

	// A pids list is returned
	require.NoError(t, err)
	require.NotEmpty(t, pids)

	// And it contains the pids of the running processes (e.g. current testing executable)
	require.Contains(t, pids, int32(os.Getpid()))
}

func TestLinuxHarvester_Do(t *testing.T) {
	// Given a process harvester
	ctx := new(mocks.AgentContext)
	ctx.On("Config").Return(&config.Config{})
	ctx.On("GetServiceForPid", mock.Anything).Return("", false)
	cache, _ := simplelru.NewLRU[int32, *cacheEntry](math.MaxInt, nil)
	h := newHarvester(ctx, &cache)

	// When retrieving for a given process sample (e.g. the current testing executable)
	sample, err := h.Do(int32(os.Getpid()), 0)

	// It returns the corresponding process sample with valid data
	require.NoError(t, err)
	require.NotNil(t, sample)

	assert.Equal(t, int32(os.Getpid()), sample.ProcessID)
	assert.Equal(t, "process.test", sample.Command)
	assert.Contains(t, sample.CmdLine, os.Args[0])
	assert.NotEmpty(t, sample.User)
	assert.Contains(t, "RSD", sample.Status,
		"process status must be R (running), S (interruptible sleep) or D (uninterruptible sleep)")
	assert.True(t, sample.MemoryVMSBytes > 0)
	assert.True(t, sample.ThreadCount > 0)
	assert.Equal(t, "process.test", sample.ProcessDisplayName)
	assert.Equal(t, "ProcessSample", sample.EventType)
}

func TestLinuxHarvester_Do_Privileged(t *testing.T) {
	current, err := user.Current()
	require.NoError(t, err)
	if current.Username != "root" {
		t.Skip("this test requires privileges. Current user: ", current.Username)
	}

	// Given a process harvester running in privileged mode
	ctx := new(mocks.AgentContext)
	ctx.On("Config").Return(&config.Config{RunMode: config.ModeRoot})
	ctx.On("GetServiceForPid", mock.Anything).Return("", false)
	cache, _ := simplelru.NewLRU[int32, *cacheEntry](math.MaxInt, nil)
	h := newHarvester(ctx, &cache)

	// When retrieving for a given process sample (e.g. the current testing executable)
	sample, err := h.Do(int32(os.Getpid()), 0)

	// It returns the corresponding process sample with valid data
	require.NoError(t, err)
	require.NotNil(t, sample)

	assert.NotNil(t, sample.FdCount)

	// And when the process sample is retrieved again
	sample, err = h.Do(int32(os.Getpid()), 0)
	require.NoError(t, err)
	require.NotNil(t, sample)

	// Per second deltas are returned
	assert.NotNil(t, sample.IOReadBytesPerSecond)
	assert.NotNil(t, sample.IOReadCountPerSecond)
	assert.NotNil(t, sample.IOWriteBytesPerSecond)
	assert.NotNil(t, sample.IOWriteCountPerSecond)
}

func TestLinuxHarvester_Do_DisableStripCommandLine(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "1m")
	require.NoError(t, cmd.Start())
	defer func() {
		_ = cmd.Process.Kill()
	}()

	// Given a process harvester
	ctx := new(mocks.AgentContext)
	// configure to not strip the command line
	ctx.On("Config").Return(&config.Config{StripCommandLine: false})
	ctx.On("GetServiceForPid", mock.Anything).Return("", false)
	cache, _ := simplelru.NewLRU[int32, *cacheEntry](math.MaxInt, nil)
	h := newHarvester(ctx, &cache)

	testhelpers.Eventually(t, 5*time.Second, func(t require.TestingT) {
		// When retrieving for a given process sample (e.g. the current testing executable)
		sample, err := h.Do(int32(cmd.Process.Pid), 0)

		// It returns the corresponding Command line without stripping arguments
		require.NoError(t, err)
		require.NotNil(t, sample)

		assert.False(t, strings.HasSuffix(sample.CmdLine, "sleep"), "%q should have arguments", sample.CmdLine)
		assert.Contains(t, sample.CmdLine, "sleep")
	})
}

func TestLinuxHarvester_Do_EnableStripCommandLine(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "1m")
	require.NoError(t, cmd.Start())
	defer func() {
		_ = cmd.Process.Kill()
	}()

	// Given a process harvester
	ctx := new(mocks.AgentContext)
	// configure to not strip the command line
	ctx.On("Config").Return(&config.Config{StripCommandLine: true})
	ctx.On("GetServiceForPid", mock.Anything).Return("", false)
	cache, _ := simplelru.NewLRU[int32, *cacheEntry](math.MaxInt, nil)
	h := newHarvester(ctx, &cache)

	testhelpers.Eventually(t, 5*time.Second, func(t require.TestingT) {
		// When retrieving for a given process sample (e.g. the current testing executable)
		sample, err := h.Do(int32(cmd.Process.Pid), 0)

		// It returns the corresponding Command line without stripping arguments
		require.NoError(t, err)
		require.NotNil(t, sample)

		assert.True(t, strings.HasSuffix(sample.CmdLine, "sleep"), "%q should not have arguments", sample.CmdLine)
	})
}

func TestLinuxHarvester_Do_InvalidateCache_DifferentCmd(t *testing.T) {
	currentPid := int32(os.Getpid())

	// Given a process harvester
	ctx := new(mocks.AgentContext)
	ctx.On("Config").Return(&config.Config{})
	ctx.On("GetServiceForPid", mock.Anything).Return("", false)

	// That has cached an old process sharing the PID with a new process
	cache, _ := simplelru.NewLRU[int32, *cacheEntry](math.MaxInt, nil)
	cache.Add(currentPid, &cacheEntry{process: &linuxProcess{cmdLine: "something old"}})
	h := newHarvester(ctx, &cache)

	// When the process is harvested
	sample, err := h.Do(currentPid, 0)
	require.NoError(t, err)

	// The sample is updated
	assert.NotEmpty(t, sample.Command)
	assert.NotEqual(t, "something old", sample.Command)
}

func TestLinuxHarvester_Do_InvalidateCache_DifferentPid(t *testing.T) {
	currentPid := int32(os.Getpid())

	// Given a process harvester
	ctx := new(mocks.AgentContext)
	ctx.On("Config").Return(&config.Config{})
	ctx.On("GetServiceForPid", mock.Anything).Return("", false)

	// That has cached an old process sharing the PID with a new process
	cache, _ := simplelru.NewLRU[int32, *cacheEntry](math.MaxInt, nil)
	cache.Add(currentPid, &cacheEntry{process: &linuxProcess{stats: procStats{ppid: -1}}})
	h := newHarvester(ctx, &cache)

	// When the process is harvested
	sample, err := h.Do(currentPid, 0)
	require.NoError(t, err)

	// The sample is updated
	assert.NotEqual(t, -1, sample.ParentProcessID)
}

func TestLinuxHarvester_GetServiceForPid(t *testing.T) {
	// Given a process harvester
	ctx := new(mocks.AgentContext)
	ctx.On("Config").Return(&config.Config{})
	// That matches a given PID with an existing service name
	ctx.On("GetServiceForPid", os.Getpid()).Return("MyServiceIdentifier", true)
	cache, _ := simplelru.NewLRU[int32, *cacheEntry](math.MaxInt, nil)
	h := newHarvester(ctx, &cache)

	// When retrieving the process sampler
	sample, err := h.Do(int32(os.Getpid()), 0)

	// It returns the corresponding process names
	require.NoError(t, err)
	require.NotNil(t, sample)
	assert.Equal(t, "MyServiceIdentifier", sample.ProcessDisplayName)
	assert.Equal(t, "process.test", sample.Command)
	assert.Contains(t, sample.CmdLine, os.Args[0])
}

func TestLinuxHarvester_GetServiceForPid_OnEmptyUseCommandName(t *testing.T) {

	// Given a process harvester
	ctx := new(mocks.AgentContext)
	ctx.On("Config").Return(&config.Config{})
	// That matches a given PID with an existing service name that is EMPTY
	ctx.On("GetServiceForPid", os.Getpid()).Return("", true)
	cache, _ := simplelru.NewLRU[int32, *cacheEntry](math.MaxInt, nil)
	h := newHarvester(ctx, &cache)

	// When retrieving the process sampler
	sample, err := h.Do(int32(os.Getpid()), 0)

	// It returns the corresponding process names
	require.NoError(t, err)
	require.NotNil(t, sample)
	assert.Equal(t, sample.Command, sample.ProcessDisplayName)
	assert.Equal(t, "process.test", sample.Command)
	assert.Contains(t, sample.CmdLine, os.Args[0])
}
