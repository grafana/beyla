// Package goexec helps analyzing Go executables
package goexec

import (
	"github.com/grafana/beyla/v2/pkg/internal/exec"
)

type FieldOffsets map[GoOffset]any

func StructMemberOffsets(elfFile *exec.FileInfo) (FieldOffsets, error) {
	return structMemberOffsets(elfFile.ELF)
}
