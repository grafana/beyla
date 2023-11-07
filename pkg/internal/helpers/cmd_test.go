// Copyright 2020 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//go:build linux
// +build linux

package helpers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunCommand(t *testing.T) {
	var err error
	obtainedOutput := [3]string{}

	// Can we run a ps command?
	obtainedOutput[0], err = RunCommand("/bin/ps", "", "-ef")
	require.NoError(t, err)
	assert.NotEqual(t, "", obtainedOutput[0])

	// Can we run a grep command?
	obtainedOutput[1], err = RunCommand("/bin/grep", obtainedOutput[0], "a")
	require.NoError(t, err)
	assert.NotEqual(t, "", obtainedOutput[1])

	// Can we run a foo command?
	obtainedOutput[2], err = RunCommand("foo", "", "goo")
	require.Error(t, err)
	assert.Equal(t, "", obtainedOutput[2])
}
