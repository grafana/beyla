// Copyright New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package process

import (
	"github.com/shirou/gopsutil/v3/process"
	"github.com/stretchr/testify/mock"
)

type SnapshotMock struct {
	mock.Mock
}

func (s *SnapshotMock) Pid() int32 {
	args := s.Called()

	return args.Get(0).(int32)
}

func (s *SnapshotMock) ShouldReturnPid(pid int32) {
	s.
		On("Pid").
		Once().
		Return(pid)
}

func (s *SnapshotMock) Ppid() int32 {
	args := s.Called()

	return args.Get(0).(int32)
}

func (s *SnapshotMock) ShouldReturnPpid(ppid int32) {
	s.
		On("Ppid").
		Once().
		Return(ppid)
}

func (s *SnapshotMock) Status() string {
	args := s.Called()

	return args.String(0)
}

func (s *SnapshotMock) ShouldReturnStatus(status string) {
	s.
		On("Status").
		Once().
		Return(status)
}

func (s *SnapshotMock) Command() string {
	args := s.Called()

	return args.String(0)
}

func (s *SnapshotMock) ShouldReturnCommand(command string) {
	s.
		On("Command").
		Once().
		Return(command)
}

func (s *SnapshotMock) CmdLine(withArgs bool) (string, error) {
	args := s.Called(withArgs)

	return args.String(0), args.Error(1)
}

func (s *SnapshotMock) ShouldReturnCmdLine(withArgs bool, cmd string, err error) {
	s.
		On("CmdLine", withArgs).
		Once().
		Return(cmd, err)
}

func (s *SnapshotMock) Username() (string, error) {
	args := s.Called()

	return args.String(0), args.Error(1)
}

func (s *SnapshotMock) ShouldReturnUsername(cmd string, err error) {
	s.
		On("Username").
		Once().
		Return(cmd, err)
}

func (s *SnapshotMock) CPUTimes() (CPUInfo, error) {
	args := s.Called()

	return args.Get(0).(CPUInfo), args.Error(1)
}

func (s *SnapshotMock) ShouldReturnCPUTimes(cpu CPUInfo, err error) {
	s.
		On("CPUTimes").
		Once().
		Return(cpu, err)
}

func (s *SnapshotMock) IOCounters() (*process.IOCountersStat, error) {
	args := s.Called()

	return args.Get(0).(*process.IOCountersStat), args.Error(1)
}

func (s *SnapshotMock) ShouldReturnIOCounters(io *process.IOCountersStat, err error) {
	s.
		On("IOCounters").
		Once().
		Return(io, err)
}

func (s *SnapshotMock) NumThreads() int32 {
	args := s.Called()

	return args.Get(0).(int32)
}

func (s *SnapshotMock) ShouldReturnNumThreads(num int32) {
	s.
		On("NumThreads").
		Once().
		Return(num)
}

func (s *SnapshotMock) NumFDs() (int32, error) {
	args := s.Called()

	return args.Get(0).(int32), args.Error(1)
}

func (s *SnapshotMock) ShouldReturnNumFDs(num int32, err error) {
	s.
		On("NumFDs").
		Once().
		Return(num, err)
}

func (s *SnapshotMock) VmRSS() int64 {
	args := s.Called()

	return args.Get(0).(int64)
}

func (s *SnapshotMock) ShouldReturnVmRSS(rss int64) {
	s.
		On("VmRSS").
		Once().
		Return(rss)
}

func (s *SnapshotMock) VmSize() int64 {
	args := s.Called()

	return args.Get(0).(int64)
}

func (s *SnapshotMock) ShouldReturnVmSize(size int64) {
	s.
		On("VmSize").
		Once().
		Return(size)
}
