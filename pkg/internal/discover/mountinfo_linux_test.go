// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Original source:
// https://github.com/cilium/cilium/blob/5130d33a835638c78dda2572d7dc92091ffb3dc1/pkg/mountinfo/mountinfo_test.go

//go:build linux

package discover

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// TestIsMountFS tests the public function IsMountFS. We cannot expect every
// system and machine to have any predictable mounts, but let's try a couple
// of very well known paths.
func TestIsMountFS(t *testing.T) {
	mounted, matched, err := IsMountFS(unix.PROC_SUPER_MAGIC, "/proc")
	assert.NoError(t, err)
	assert.True(t, mounted)
	assert.True(t, matched)
}
