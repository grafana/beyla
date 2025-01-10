package ebpf

import (
	"fmt"
	"testing"
)

func TestRoundToNearestMultiple(t *testing.T) {
	tests := []struct {
		x, n, expected uint32
	}{
		{0, 5, 5},   // x < n, should return n
		{3, 5, 5},   // x < n, should return n
		{5, 5, 5},   // x == n, should return n (no rounding needed)
		{6, 5, 5},   // x > n, should round down
		{7, 5, 5},   // x > n, should round down
		{12, 5, 10}, // x > n, should round down
		{13, 5, 15}, // x > n, should round up
		{9, 7, 7},   // x < n, should return n
		{10, 7, 7},  // x == n, should return n
		{11, 7, 14}, // x > n, should round to the nearest multiple
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("x=%d, n=%d", tt.x, tt.n), func(t *testing.T) {
			got := roundToNearestMultiple(tt.x, tt.n)
			if got != tt.expected {
				t.Errorf("roundToNearestMultiple(%d, %d) = %d; want %d", tt.x, tt.n, got, tt.expected)
			}
		})
	}
}
