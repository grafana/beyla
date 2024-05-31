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
			h := newHarvester(&Config{RunMode: c.mode}, cache)

			// If not privileged, it is expected to not report neither FDs nor IO counters
			status, err := h.Do(int32(os.Getpid()))
			require.NoError(t, err)
			if c.privileged {
				assert.NotZero(t, status.FdCount)
				assert.NotZero(t, status.IOReadCount)
			} else {
				assert.Zero(t, status.FdCount)
				assert.Zero(t, status.IOReadCount)
			}
		})
	}
}

func TestLinuxHarvester_Do(t *testing.T) {
	// Given a process harvester
	cache, _ := simplelru.NewLRU[int32, *cacheEntry](math.MaxInt, nil)
	h := newHarvester(&Config{}, cache)

	// When retrieving for a given process status (e.g. the current testing executable)
	status, err := h.Do(int32(os.Getpid()))

	// It returns the corresponding process status with valid data
	require.NoError(t, err)
	require.NotNil(t, status)

	assert.Equal(t, int32(os.Getpid()), status.ProcessID)
	assert.Equal(t, "process.test", status.Command)
	assert.Contains(t, status.CommandLine, os.Args[0])
	assert.NotEmpty(t, status.User)
	assert.Contains(t, "RSD", status.Status,
		"process status must be R (running), S (interruptible sleep) or D (uninterruptible sleep)")
	assert.NotZero(t, status.MemoryVMSBytes)
	assert.NotZero(t, status.MemoryRSSBytes)
	assert.NotZero(t, status.CPUPercent)
	assert.NotZero(t, status.CPUUserPercent)
	assert.NotZero(t, status.CPUSystemPercent)
	assert.NotZero(t, status.ParentProcessID)
	assert.NotZero(t, status.ThreadCount)
	assert.NotZero(t, status.FdCount)
	assert.NotZero(t, status.ThreadCount)
}

func TestLinuxHarvester_Do_FullCommandLine(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "1m")
	require.NoError(t, cmd.Start())
	defer func() {
		_ = cmd.Process.Kill()
	}()

	// Given a process harvester configured to showw the full command line
	cache, _ := simplelru.NewLRU[int32, *cacheEntry](math.MaxInt, nil)
	h := newHarvester(&Config{}, cache)

	test.Eventually(t, 5*time.Second, func(t require.TestingT) {
		// When retrieving for a given process status (e.g. the current testing executable)
		status, err := h.Do(int32(cmd.Process.Pid))

		// It returns the corresponding Command line without stripping arguments
		require.NoError(t, err)
		require.NotNil(t, status)

		assert.False(t, strings.HasSuffix(status.CommandLine, "sleep"), "%q should have arguments", status.CommandLine)
		assert.Contains(t, status.CommandLine, "sleep")
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
	h := newHarvester(&Config{}, cache)

	test.Eventually(t, 5*time.Second, func(t require.TestingT) {
		// When retrieving for a given process status (e.g. the current testing executable)
		status, err := h.Do(int32(cmd.Process.Pid))

		// It returns the corresponding Command line without stripping arguments
		require.NoError(t, err)
		require.NotNil(t, status)

		assert.True(t, strings.HasSuffix(status.CommandLine, "sleep"), "%q should not have arguments", status.CommandLine)
	})
}

func TestLinuxHarvester_Do_InvalidateCache_DifferentCmd(t *testing.T) {
	currentPid := int32(os.Getpid())

	// Given a process harvester
	// That has cached an old process sharing the PID with a new process
	cache, _ := simplelru.NewLRU[int32, *cacheEntry](math.MaxInt, nil)
	cache.Add(currentPid, &cacheEntry{process: &linuxProcess{cmdLine: "something old"}})
	h := newHarvester(&Config{}, cache)

	// When the process is harvested
	status, err := h.Do(currentPid)
	require.NoError(t, err)

	// The status is updated
	assert.NotEmpty(t, status.Command)
	assert.NotEqual(t, "something old", status.Command)
}

func TestLinuxHarvester_Do_InvalidateCache_DifferentPid(t *testing.T) {
	currentPid := int32(os.Getpid())

	// Given a process harvester
	// That has cached an old process sharing the PID with a new process
	cache, _ := simplelru.NewLRU[int32, *cacheEntry](math.MaxInt, nil)
	cache.Add(currentPid, &cacheEntry{process: &linuxProcess{stats: procStats{ppid: -1}}})
	h := newHarvester(&Config{}, cache)

	// When the process is harvested
	status, err := h.Do(currentPid)
	require.NoError(t, err)

	// The status is updated
	assert.NotEqual(t, -1, status.ParentProcessID)
}
