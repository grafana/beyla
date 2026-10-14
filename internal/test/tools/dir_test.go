// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProjectDir(t *testing.T) {
	prjDir := ProjectDir()
	// Test that the project relative dir is correct by checking for the
	// existence of a file that should be only placed in the project
	// root (e.g. Makefile)
	fi, err := os.Stat(path.Join(prjDir, "Makefile"))
	require.NoError(t, err)
	require.NotNil(t, fi)
	assert.NotEmpty(t, fi.Name())
}
