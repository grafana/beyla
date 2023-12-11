package goexec

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSupportedGoVersion(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		// Unsupported versions
		{input: "1.15", want: false},
		{input: "1.15.1", want: false},
		{input: "1.15.15", want: false},
		{input: "1.16beta1", want: false},
		{input: "1.16rc1", want: false},
		{input: "1.16", want: false},
		{input: "1.16.1", want: false},
		{input: "1.16.15", want: false},

		// Supported versions
		{input: "1.17", want: true},
		{input: "1.17beta1", want: true},
		{input: "1.17rc1", want: true},
		{input: "1.17rc2", want: true},
		{input: "1.17.1", want: true},
		{input: "1.17.13", want: true},
		{input: "1.18", want: true},
		{input: "1.18.9", want: true},

		// Uncleaned Go version strings
		{input: "go1.16.4", want: false},
		{input: "go1.21.4", want: true},
		{input: "devel go1.22-098f059 Mon Dec 4 23:03:04 2023 +0000", want: true},

		// Invalid versions
		{input: "devel", want: false},
		{input: "go", want: false},
		{input: "098f059", want: false},
		{input: "Mon Dec 4 23:03:04 2023 +0000", want: false},
	}

	for _, tt := range tests {
		got := supportedGoVersion(tt.input)
		assert.Equal(t, tt.want, got, "input: %v", tt.input)
	}
}
