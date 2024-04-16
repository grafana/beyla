// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Original source:
// https://github.com/cilium/cilium/blob/5130d33a835638c78dda2572d7dc92091ffb3dc1/pkg/mountinfo/mountinfo_privileged_test.go

//go:build linux

package discover

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

const privilegedEnv = "PRIVILEGED_TESTS"

// TestIsMountFSbyMount tests the public function IsMountFS by performing
// an actual mount.
func TestIsMountFSbyMount(t *testing.T) {
	if os.Getenv(privilegedEnv) == "" {
		t.Skipf("Set %s to run this test", privilegedEnv)
	}
	tmpDir, err := os.MkdirTemp("", "IsMountFS_")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	mounted, matched, err := IsMountFS(unix.TMPFS_MAGIC, tmpDir)
	assert.NoError(t, err)
	assert.False(t, mounted)
	assert.False(t, matched)

	err = unix.Mount("tmpfs", tmpDir, "tmpfs", 0, "")
	assert.NoError(t, err)
	defer func() {
		err := unix.Unmount(tmpDir, unix.MNT_DETACH)
		assert.NoError(t, err)
	}()

	// deliberately check with wrong fstype
	mounted, matched, err = IsMountFS(unix.PROC_SUPER_MAGIC, tmpDir)
	assert.NoError(t, err)
	assert.True(t, mounted)
	assert.False(t, matched)

	// now check with proper fstype
	mounted, matched, err = IsMountFS(unix.TMPFS_MAGIC, tmpDir)
	assert.NoError(t, err)
	assert.True(t, mounted)
	assert.True(t, matched)
}
