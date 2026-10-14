// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package tcmanager // import "go.opentelemetry.io/obi/pkg/internal/ebpf/tcmanager"

import (
	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/config"
)

type dummyManager struct{}

func NewTCXManager() TCManager {
	return &dummyManager{}
}

func NewNetlinkManager() TCManager {
	return &dummyManager{}
}

func (d *dummyManager) Shutdown()                                              {}
func (d *dummyManager) AddProgram(_ string, _ *ebpf.Program, _ AttachmentType) {}
func (d *dummyManager) RemoveProgram(_ string)                                 {}
func (d *dummyManager) InterfaceName(_ int) (string, bool)                     { return "", false }
func (d *dummyManager) SetInterfaceManager(_ *InterfaceManager)                {}
func (d *dummyManager) Errors() chan error                                     { return nil }

func EnsureCiliumCompatibility(_ config.TCBackend) error { return nil }
