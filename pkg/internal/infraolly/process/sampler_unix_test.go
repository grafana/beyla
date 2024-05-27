//go:build !windows
// +build !windows

// Copyright New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package process


type fakeContainerSampler struct{}

func (cs *fakeContainerSampler) Enabled() bool {
	return true
}

func (*fakeContainerSampler) NewDecorator() (metrics.ProcessDecorator, error) { //nolint:ireturn
	return &fakeDecorator{}, nil
}

type fakeDecorator struct{}

func (pd *fakeDecorator) Decorate(process *Sample) {
	process.ContainerImage = "decorated"
	process.ContainerLabels = map[string]string{
		"label1": "value1",
		"label2": "value2",
	}
}
