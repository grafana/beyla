// Copyright 2020 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
package process

import (
	"fmt"
	"math"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/golang-lru/v2/simplelru"
	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLinuxHarvester_IsPrivileged(t *testing.T) {
	cases := []struct {
		mode       RunMode
		privileged bool
	}{
		{mode: RunModeRoot, privileged: true},
		{mode: RunModePrivileged, privileged: true},
		{mode: RunModeUnprivileged, privileged: false},
	}
	for _, c := range cases {
		t.Run(fmt.Sprint("mode ", c.mode), func(t *testing.T) {
			cache, _ := simplelru.NewLRU[int32, *cacheEntry](math.MaxInt, nil)
			h := newHarvester(Config{RunMode: c.mode}, cache)

			// If not privileged, it is expected to not report neither FDs nor IO counters
			sample, err := h.Do(int32(os.Getpid()))
			require.NoError(t, err)
			if c.privileged {
				assert.NotZero(t, sample.FdCount)
				assert.NotZero(t, sample.IOReadCount)
			} else {
				assert.Zero(t, sample.FdCount)
				assert.Zero(t, sample.IOReadCount)
			}
		})
	}
}

func TestLinuxHarvester_Do(t *testing.T) {
	// Given a process harvester
	cache, _ := simplelru.NewLRU[int32, *cacheEntry](math.MaxInt, nil)
	h := newHarvester(Config{}, cache)

	// When retrieving for a given process sample (e.g. the current testing executable)
	sample, err := h.Do(int32(os.Getpid()))

	// It returns the corresponding process sample with valid data
	require.NoError(t, err)
	require.NotNil(t, sample)

	assert.Equal(t, int32(os.Getpid()), sample.ProcessID)
	assert.Equal(t, "process.test", sample.Command)
	assert.Contains(t, sample.CmdLine, os.Args[0])
	assert.NotEmpty(t, sample.User)
	assert.Contains(t, "RSD", sample.Status,
		"process status must be R (running), S (interruptible sleep) or D (uninterruptible sleep)")
	assert.NotZero(t, sample.MemoryVMSBytes)
	assert.NotZero(t, sample.MemoryRSSBytes)
	assert.NotZero(t, sample.CPUPercent)
	assert.NotZero(t, sample.CPUUserPercent)
	assert.NotZero(t, sample.CPUSystemPercent)
	assert.NotZero(t, sample.ParentProcessID)
	assert.NotZero(t, sample.ThreadCount)
	assert.NotZero(t, sample.FdCount)
	assert.NotZero(t, sample.ThreadCount)
}

func TestLinuxHarvester_Do_FullCommandLine(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "1m")
	require.NoError(t, cmd.Start())
	defer func() {
		_ = cmd.Process.Kill()
	}()

	// Given a process harvester configured to showw the full command line
	cache, _ := simplelru.NewLRU[int32, *cacheEntry](math.MaxInt, nil)
	h := newHarvester(Config{FullCommandLine: true}, cache)

	test.Eventually(t, 5*time.Second, func(t require.TestingT) {
		// When retrieving for a given process sample (e.g. the current testing executable)
		sample, err := h.Do(int32(cmd.Process.Pid))

		// It returns the corresponding Command line without stripping arguments
		require.NoError(t, err)
		require.NotNil(t, sample)

		assert.False(t, strings.HasSuffix(sample.CmdLine, "sleep"), "%q should have arguments", sample.CmdLine)
		assert.Contains(t, sample.CmdLine, "sleep")
	})
}

func TestLinuxHarvester_Do_StripCommandLine(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "1m")
	require.NoError(t, cmd.Start())
	defer func() {
		_ = cmd.Process.Kill()
	}()

	// Given a process harvester
	cache, _ := simplelru.NewLRU[int32, *cacheEntry](math.MaxInt, nil)
	h := newHarvester(Config{FullCommandLine: true}, cache)

	test.Eventually(t, 5*time.Second, func(t require.TestingT) {
		// When retrieving for a given process sample (e.g. the current testing executable)
		sample, err := h.Do(int32(cmd.Process.Pid))

		// It returns the corresponding Command line without stripping arguments
		require.NoError(t, err)
		require.NotNil(t, sample)

		assert.True(t, strings.HasSuffix(sample.CmdLine, "sleep"), "%q should not have arguments", sample.CmdLine)
	})
}

func TestLinuxHarvester_Do_InvalidateCache_DifferentCmd(t *testing.T) {
	currentPid := int32(os.Getpid())

	// Given a process harvester
	// That has cached an old process sharing the PID with a new process
	cache, _ := simplelru.NewLRU[int32, *cacheEntry](math.MaxInt, nil)
	cache.Add(currentPid, &cacheEntry{process: &linuxProcess{cmdLine: "something old"}})
	h := newHarvester(Config{}, cache)

	// When the process is harvested
	sample, err := h.Do(currentPid)
	require.NoError(t, err)

	// The sample is updated
	assert.NotEmpty(t, sample.Command)
	assert.NotEqual(t, "something old", sample.Command)
}

func TestLinuxHarvester_Do_InvalidateCache_DifferentPid(t *testing.T) {
	currentPid := int32(os.Getpid())

	// Given a process harvester
	// That has cached an old process sharing the PID with a new process
	cache, _ := simplelru.NewLRU[int32, *cacheEntry](math.MaxInt, nil)
	cache.Add(currentPid, &cacheEntry{process: &linuxProcess{stats: procStats{ppid: -1}}})
	h := newHarvester(Config{}, cache)

	// When the process is harvested
	sample, err := h.Do(currentPid)
	require.NoError(t, err)

	// The sample is updated
	assert.NotEqual(t, -1, sample.ParentProcessID)
}
