// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package maps

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSliceToSet(t *testing.T) {
	assert.Equal(t, map[int]struct{}{1: {}, 2: {}, 3: {}},
		SliceToSet([]int{2, 3, 1, 1, 1, 2, 3}))
}

func TestSetToSlice(t *testing.T) {
	slice := SetToSlice(map[int]struct{}{1: {}, 2: {}, 3: {}})
	slices.Sort(slice)
	assert.Equal(t, []int{1, 2, 3}, slice)
}
