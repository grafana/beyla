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

//go:build linux

package process

import (
	"fmt"
	"math"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/hashicorp/golang-lru/v2/simplelru"
	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
)

func TestLinuxHarvester_IsPrivileged(t *testing.T) {
	cases := []struct {
		mode       RunMode
		privileged bool
	}{
		{mode: RunModePrivileged, privileged: true},
		{mode: RunModeUnprivileged, privileged: false},
	}
	for _, c := range cases {
		t.Run(fmt.Sprint("mode ", c.mode), func(t *testing.T) {
			cache, _ := simplelru.NewLRU[int32, *linuxProcess](math.MaxInt, nil)
			h := newHarvester(&CollectConfig{RunMode: c.mode}, cache)

			// If not privileged, it is expected to not report neither FDs nor IO counters
			status, err := h.Harvest(&svc.Attrs{ProcPID: int32(os.Getpid())})
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

func TestLinuxHarvester_Harvest(t *testing.T) {
	// Given a process harvester
	cache, _ := simplelru.NewLRU[int32, *linuxProcess](math.MaxInt, nil)
	h := newHarvester(&CollectConfig{}, cache)

	// When retrieving for a given process status (e.g. the current testing executable)
	status, err := h.Harvest(&svc.Attrs{ProcPID: int32(os.Getpid())})

	// It returns the corresponding process status with valid data
	require.NoError(t, err)
	require.NotNil(t, status)

	assert.Equal(t, int32(os.Getpid()), status.ID.ProcessID)
	assert.Equal(t, "process.test", status.ID.Command)
	assert.Contains(t, status.ID.CommandLine, os.Args[0])
	assert.NotEmpty(t, status.ID.User)
	assert.Contains(t, "RSD", status.Status,
		"process status must be R (running), S (interruptible sleep) or D (uninterruptible sleep)")
	assert.NotZero(t, status.MemoryVMSBytes)
	assert.NotZero(t, status.MemoryRSSBytes)
	assert.NotZero(t, status.ID.ParentProcessID)
	assert.NotZero(t, status.ThreadCount)
}

func TestLinuxHarvester_Harvest_FullCommandLine(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "1m")
	require.NoError(t, cmd.Start())
	defer func() {
		_ = cmd.Process.Kill()
	}()

	test.Eventually(t, 5*time.Second, func(t require.TestingT) {
		// Given a process harvester configured to showw the full command line
		cache, _ := simplelru.NewLRU[int32, *linuxProcess](math.MaxInt, nil)
		h := newHarvester(&CollectConfig{}, cache)

		// When retrieving for a given process status (e.g. the current testing executable)
		status, err := h.Harvest(&svc.Attrs{ProcPID: int32(cmd.Process.Pid)})

		// It returns the corresponding Command line without stripping arguments
		require.NoError(t, err)
		require.NotNil(t, status)

		assert.Equal(t, "sleep", status.ID.ExecName)
		assert.Equal(t, "/bin/sleep", status.ID.ExecPath)
		assert.Equal(t, "/bin/sleep 1m", status.ID.CommandLine)
		assert.Equal(t, "sleep", status.ID.Command)
		assert.Equal(t, []string{"1m"}, status.ID.CommandArgs)
	})
}

func TestLinuxHarvester_Do_InvalidateCache_DifferentCmd(t *testing.T) {
	currentPid := int32(os.Getpid())

	// Given a process harvester
	// That has cached an old process sharing the PID with a new process
	cache, _ := simplelru.NewLRU[int32, *linuxProcess](math.MaxInt, nil)
	cache.Add(currentPid, &linuxProcess{stats: procStats{command: "something old"}})
	h := newHarvester(&CollectConfig{}, cache)

	// When the process is harvested
	status, err := h.Harvest(&svc.Attrs{ProcPID: currentPid})
	require.NoError(t, err)

	// The status is updated
	assert.NotEmpty(t, status.ID.Command)
	assert.NotEqual(t, "something old", status.ID.Command)
}

func TestLinuxHarvester_Do_InvalidateCache_DifferentPid(t *testing.T) {
	currentPid := int32(os.Getpid())

	// Given a process harvester
	// That has cached an old process sharing the PID with a new process
	cache, _ := simplelru.NewLRU[int32, *linuxProcess](math.MaxInt, nil)
	cache.Add(currentPid, &linuxProcess{stats: procStats{ppid: -1}})
	h := newHarvester(&CollectConfig{}, cache)

	// When the process is harvested
	status, err := h.Harvest(&svc.Attrs{ProcPID: currentPid})
	require.NoError(t, err)

	// The status is updated
	assert.NotEqual(t, -1, status.ID.ParentProcessID)
}
