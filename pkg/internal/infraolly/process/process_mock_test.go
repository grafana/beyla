// Copyright New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package process

import (
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/process"
	"github.com/stretchr/testify/mock"
)

type ProcessMock struct {
	mock.Mock
}

func (s *ProcessMock) Username() (string, error) {
	args := s.Called()

	return args.String(0), args.Error(1)
}

func (s *ProcessMock) ShouldReturnUsername(username string, err error) {
	s.
		On("Username").
		Once().
		Return(username, err)
}

func (s *ProcessMock) Name() (string, error) {
	args := s.Called()

	return args.String(0), args.Error(1)
}

func (s *ProcessMock) ShouldReturnName(name string, err error) {
	s.
		On("Name").
		Once().
		Return(name, err)
}

func (s *ProcessMock) Cmdline() (string, error) {
	args := s.Called()

	return args.String(0), args.Error(1)
}

func (s *ProcessMock) ShouldReturnCmdLine(cmdLine string, err error) {
	s.
		On("Cmdline").
		Once().
		Return(cmdLine, err)
}

func (s *ProcessMock) ProcessId() int32 {
	args := s.Called()

	return args.Get(0).(int32)
}

func (s *ProcessMock) ShouldReturnProcessId(processId int32) {
	s.ShouldReturnProcessIdMultipleTimes(processId, 1)
}

func (s *ProcessMock) ShouldReturnProcessIdMultipleTimes(processId int32, times int) {
	s.
		On("ProcessId").
		Times(times).
		Return(processId)
}

func (s *ProcessMock) Parent() (Process, error) {
	args := s.Called()

	return args.Get(0).(Process), args.Error(1)
}

func (s *ProcessMock) ShouldReturnParent(process Process, err error) {
	s.
		On("Parent").
		Once().
		Return(process, err)
}

func (s *ProcessMock) NumThreads() (int32, error) {
	args := s.Called()

	return args.Get(0).(int32), args.Error(1)
}

func (s *ProcessMock) ShouldReturnNumThreads(num int32, err error) {
	s.
		On("NumThreads").
		Once().
		Return(num, err)
}

func (s *ProcessMock) Status() ([]string, error) {
	args := s.Called()

	return args.Get(0).([]string), args.Error(1)
}
func (s *ProcessMock) ShouldReturnStatus(status []string, err error) {
	s.
		On("Status").
		Once().
		Return(status, err)
}

func (s *ProcessMock) MemoryInfo() (*process.MemoryInfoStat, error) {
	args := s.Called()

	return args.Get(0).(*process.MemoryInfoStat), args.Error(1)
}
func (s *ProcessMock) ShouldReturnMemoryInfo(memInfo *process.MemoryInfoStat, err error) {
	s.
		On("MemoryInfo").
		Once().
		Return(memInfo, err)
}

func (s *ProcessMock) CPUPercent() (float64, error) {
	args := s.Called()

	return args.Get(0).(float64), args.Error(1)
}
func (s *ProcessMock) ShouldReturnCPUPercent(percent float64, err error) {
	s.
		On("CPUPercent").
		Once().
		Return(percent, err)
}

func (s *ProcessMock) Times() (*cpu.TimesStat, error) {
	args := s.Called()

	return args.Get(0).(*cpu.TimesStat), args.Error(1)
}
func (s *ProcessMock) ShouldReturnTimes(times *cpu.TimesStat, err error) {
	s.
		On("Times").
		Once().
		Return(times, err)
}
