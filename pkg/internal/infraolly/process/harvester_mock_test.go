// Copyright 2020 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//go:build linux || darwin
// +build linux darwin

package process

import (
	"github.com/stretchr/testify/mock"
)

type HarvesterMock struct {
	mock.Mock
}

func (h *HarvesterMock) Pids() ([]int32, error) {
	args := h.Called()

	return args.Get(0).([]int32), args.Error(1)
}

func (h *HarvesterMock) ShouldReturnPids(pids []int32, err error) {
	h.
		On("Pids").
		Once().
		Return(pids, err)
}

func (h *HarvesterMock) Do(pid int32, elapsedSeconds float64) (*Sample, error) {
	args := h.Called(pid, elapsedSeconds)

	return args.Get(0).(*Sample), args.Error(1)
}

func (h *HarvesterMock) ShouldDo(pid int32, elapsedSeconds float64, sample *Sample, err error) {
	h.
		On("Do", pid, elapsedSeconds).
		Once().
		Return(sample, err)
}
