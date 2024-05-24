// Copyright 2020 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
package process

import (
	"errors"
	"testing"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/process"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func Test_collectProcStats_NameError(t *testing.T) {
	proc := &ProcessMock{}
	expectedError := errors.New("some error")

	proc.ShouldReturnName("", expectedError)

	stats, err := collectProcStats(proc)

	assert.Equal(t, expectedError, err)
	assert.Equal(t, procStats{}, stats)
	//mocked objects assertions
	mock.AssertExpectationsForObjects(t, proc)
}

func Test_collectProcStats_NumThreadsError(t *testing.T) {
	proc := &ProcessMock{}
	expectedError := errors.New("some error")

	proc.ShouldReturnName("some name", nil)
	proc.ShouldReturnProcessId(1)
	proc.ShouldReturnNumThreads(0, expectedError)

	stats, err := collectProcStats(proc)

	assert.Equal(t, expectedError, err)
	assert.Equal(t, procStats{}, stats)
	//mocked objects assertions
	mock.AssertExpectationsForObjects(t, proc)
}

func Test_collectProcStats_StatusError(t *testing.T) {
	proc := &ProcessMock{}
	expectedError := errors.New("some error")

	proc.ShouldReturnName("some name", nil)
	proc.ShouldReturnProcessId(1)
	proc.ShouldReturnNumThreads(4, nil)
	proc.ShouldReturnStatus([]string{}, expectedError)

	stats, err := collectProcStats(proc)

	assert.Equal(t, expectedError, err)
	assert.Equal(t, procStats{}, stats)
	//mocked objects assertions
	mock.AssertExpectationsForObjects(t, proc)
}

func Test_collectProcStats_MemoryInfoError(t *testing.T) {
	proc := &ProcessMock{}
	expectedError := errors.New("some error")

	proc.ShouldReturnName("some name", nil)
	proc.ShouldReturnProcessId(1)
	proc.ShouldReturnNumThreads(4, nil)
	proc.ShouldReturnStatus([]string{"some status"}, nil)
	proc.ShouldReturnMemoryInfo(&process.MemoryInfoStat{}, expectedError)

	stats, err := collectProcStats(proc)

	assert.Equal(t, expectedError, err)
	assert.Equal(t, procStats{}, stats)
	//mocked objects assertions
	mock.AssertExpectationsForObjects(t, proc)
}

func Test_collectProcStats_CpuPercentError(t *testing.T) {
	proc := &ProcessMock{}
	expectedError := errors.New("some error")

	proc.ShouldReturnName("some name", nil)
	proc.ShouldReturnProcessId(1)
	proc.ShouldReturnNumThreads(4, nil)
	proc.ShouldReturnStatus([]string{"some status"}, nil)
	proc.ShouldReturnMemoryInfo(&process.MemoryInfoStat{}, nil)
	proc.ShouldReturnCPUPercent(0, expectedError)

	stats, err := collectProcStats(proc)

	assert.Equal(t, expectedError, err)
	assert.Equal(t, procStats{}, stats)
	//mocked objects assertions
	mock.AssertExpectationsForObjects(t, proc)
}

func Test_collectProcStats_CpuTimesError(t *testing.T) {
	proc := &ProcessMock{}
	expectedError := errors.New("some error")

	proc.ShouldReturnName("some name", nil)
	proc.ShouldReturnProcessId(1)
	proc.ShouldReturnNumThreads(4, nil)
	proc.ShouldReturnStatus([]string{"some status"}, nil)
	proc.ShouldReturnMemoryInfo(&process.MemoryInfoStat{}, nil)
	proc.ShouldReturnCPUPercent(0, nil)
	proc.ShouldReturnTimes(&cpu.TimesStat{}, expectedError)

	stats, err := collectProcStats(proc)

	assert.Equal(t, expectedError, err)
	assert.Equal(t, procStats{}, stats)
	//mocked objects assertions
	mock.AssertExpectationsForObjects(t, proc)
}

func Test_collectProcStats_NoErrorsInitProcess(t *testing.T) {
	tests := []struct {
		name       string
		command    string
		processId  int32
		numThreads int32
		status     string
		memStat    *process.MemoryInfoStat
		cpuPercent float64
		timesStat  *cpu.TimesStat
		expected   procStats
	}{
		{
			name:       "invalid rss",
			command:    "some command",
			processId:  1,
			numThreads: 3,
			status:     "some status",
			memStat: &process.MemoryInfoStat{
				RSS: 0,
				VMS: 232,
			},
			cpuPercent: 10,
			timesStat:  &cpu.TimesStat{User: 2, System: 8},
			expected: procStats{
				command:    "some command",
				ppid:       0,
				numThreads: 3,
				state:      "some status",
				vmRSS:      0,
				vmSize:     232,
				cpu: CPUInfo{
					Percent: 10,
					User:    2,
					System:  8,
				},
			},
		},
		{
			name:       "invalid vmsize",
			command:    "some command",
			processId:  1,
			numThreads: 3,
			status:     "some status",
			memStat: &process.MemoryInfoStat{
				RSS: 45,
				VMS: 0,
			},
			cpuPercent: 10,
			timesStat:  &cpu.TimesStat{User: 2, System: 8},
			expected: procStats{
				command:    "some command",
				ppid:       0,
				numThreads: 3,
				state:      "some status",
				vmRSS:      45,
				vmSize:     0,
				cpu: CPUInfo{
					Percent: 10,
					User:    2,
					System:  8,
				},
			},
		},
		{
			name:       "happy path",
			command:    "some command",
			processId:  1,
			numThreads: 3,
			status:     "some status",
			memStat: &process.MemoryInfoStat{
				RSS: 45,
				VMS: 22,
			},
			cpuPercent: 10,
			timesStat:  &cpu.TimesStat{User: 2, System: 8},
			expected: procStats{
				command:    "some command",
				ppid:       0,
				numThreads: 3,
				state:      "some status",
				vmRSS:      45,
				vmSize:     22,
				cpu: CPUInfo{
					Percent: 10,
					User:    2,
					System:  8,
				},
			},
		},
	}

	proc := &ProcessMock{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proc.ShouldReturnName(tt.command, nil)
			proc.ShouldReturnProcessId(tt.processId)
			proc.ShouldReturnNumThreads(tt.numThreads, nil)
			proc.ShouldReturnStatus([]string{tt.status}, nil)
			proc.ShouldReturnMemoryInfo(tt.memStat, nil)
			proc.ShouldReturnCPUPercent(tt.cpuPercent, nil)
			proc.ShouldReturnTimes(tt.timesStat, nil)

			stats, err := collectProcStats(proc)

			assert.Nil(t, err)
			assert.Equal(t, tt.expected, stats)
			//mocked objects assertions
			mock.AssertExpectationsForObjects(t, proc)
		})
	}
}

func Test_collectProcStats_NoErrorsProcessWithParent(t *testing.T) {
	tests := []struct {
		name             string
		command          string
		processId        int32
		parentProcessId  int32
		parentProcessErr error
		numThreads       int32
		status           string
		memStat          *process.MemoryInfoStat
		cpuPercent       float64
		timesStat        *cpu.TimesStat
		expected         procStats
	}{
		{
			name:             "parent process ok",
			command:          "some command",
			processId:        16,
			parentProcessId:  11,
			parentProcessErr: nil,
			numThreads:       3,
			status:           "some status",
			memStat: &process.MemoryInfoStat{
				RSS: 0,
				VMS: 232,
			},
			cpuPercent: 10,
			timesStat:  &cpu.TimesStat{User: 2, System: 8},
			expected: procStats{
				command:    "some command",
				ppid:       11,
				numThreads: 3,
				state:      "some status",
				vmRSS:      0,
				vmSize:     232,
				cpu: CPUInfo{
					Percent: 10,
					User:    2,
					System:  8,
				},
			},
		},
		{
			name:             "error getting parent process",
			command:          "some command",
			processId:        16,
			parentProcessId:  11,
			parentProcessErr: errors.New("some error"),
			numThreads:       3,
			status:           "some status",
			memStat: &process.MemoryInfoStat{
				RSS: 0,
				VMS: 232,
			},
			cpuPercent: 10,
			timesStat:  &cpu.TimesStat{User: 2, System: 8},
			expected: procStats{
				command:    "some command",
				ppid:       0,
				numThreads: 3,
				state:      "some status",
				vmRSS:      0,
				vmSize:     232,
				cpu: CPUInfo{
					Percent: 10,
					User:    2,
					System:  8,
				},
			},
		},
	}

	parentProc := &ProcessMock{}
	proc := &ProcessMock{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proc.ShouldReturnName(tt.command, nil)
			proc.ShouldReturnParent(parentProc, tt.parentProcessErr)
			if tt.parentProcessErr == nil {
				parentProc.ShouldReturnProcessId(tt.parentProcessId)
			}
			proc.ShouldReturnProcessId(tt.processId)
			proc.ShouldReturnNumThreads(tt.numThreads, nil)
			proc.ShouldReturnStatus([]string{tt.status}, nil)
			proc.ShouldReturnMemoryInfo(tt.memStat, nil)
			proc.ShouldReturnCPUPercent(tt.cpuPercent, nil)
			proc.ShouldReturnTimes(tt.timesStat, nil)

			stats, err := collectProcStats(proc)

			assert.Nil(t, err)
			assert.Equal(t, tt.expected, stats)
			//mocked objects assertions
			mock.AssertExpectationsForObjects(t, proc)
		})
	}
}

func Test_calculatePercent(t *testing.T) {
	tests := []struct {
		name            string
		t1              CPUInfo
		t2              CPUInfo
		delta           float64
		numcpu          int
		expectedPercent float64
	}{
		{
			name:            "delta 0",
			expectedPercent: 0,
		},
		{
			name:            "bad delta",
			delta:           -1,
			expectedPercent: 0,
		},
		{
			name:   "good delta",
			delta:  10,
			numcpu: 2,
			t1: CPUInfo{
				User:   24,
				System: 33,
			},
			t2: CPUInfo{
				User:   42,
				System: 55,
			},
			expectedPercent: ((44 / 10) * 100) * 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			percent := calculatePercent(tt.t1, tt.t2, tt.delta, tt.numcpu)
			assert.Equal(t, tt.expectedPercent, percent)
		})
	}
}

//nolint:exhaustruct
func Test_Calculate_Process_CmdLine(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		cmdLine  string
		args     bool
		expected string
	}{
		{
			name:     "empty",
			cmdLine:  "",
			expected: "",
		},
		{
			name:     "ignoring dash on session commands",
			cmdLine:  "-zsh",
			expected: "zsh",
		},
		{
			name:     "no arguments & args enabled",
			cmdLine:  "/sbin/launchd",
			args:     true,
			expected: "/sbin/launchd",
		},
		{
			name:     "no arguments & args disabled",
			cmdLine:  "/sbin/launchd",
			args:     false,
			expected: "/sbin/launchd",
		},
		{
			name:     "arguments & args enabled",
			cmdLine:  "/sbin/launchd -arg_a=1 -arg_b 2",
			args:     true,
			expected: "/sbin/launchd -arg_a=1 -arg_b 2",
		},
		{
			name:     "arguments & args disabled",
			cmdLine:  "/sbin/launchd -arg_a=1 -arg_b 2",
			args:     false,
			expected: "/sbin/launchd",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			process := &ProcessMock{}
			process.ShouldReturnCmdLine(tt.cmdLine, nil)
			darwinProcess := darwinProcess{
				process: process,
			}

			result, err := darwinProcess.CmdLine(tt.args)
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}
