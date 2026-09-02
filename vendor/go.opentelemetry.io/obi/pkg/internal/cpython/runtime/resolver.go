// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package runtime // import "go.opentelemetry.io/obi/pkg/internal/cpython/runtime"

import (
	"errors"
	"fmt"
	"os"

	"go.opentelemetry.io/obi/pkg/appolly/app"
)

var errUnsupportedLayout = errors.New("unsupported CPython runtime layout")

// Resolver resolves supported CPython process images into BPF attachment plans.
type Resolver struct {
	analysisCache resolverAnalysisCache
}

// NewResolver creates an empty CPython runtime resolver.
func NewResolver() *Resolver {
	return &Resolver{analysisCache: newResolverAnalysisCache()}
}

// GCCompletionProbeKind identifies a probe that runs after CPython updates its GC counters.
type GCCompletionProbeKind uint8

const (
	GCCompletionProbeUSDT GCCompletionProbeKind = iota + 1
	GCCompletionProbePrivateReturn
)

// GCCompletionProbe identifies one probe location in the mapped CPython object.
type GCCompletionProbe struct {
	Kind            GCCompletionProbeKind
	FileOffset      uint64
	SemaphoreOffset uint64
}

// MetricTarget contains the immutable process and BPF metadata for one Python lifecycle.
// The mapped object stays open until Close so attachment cannot follow a changed path.
type MetricTarget struct {
	PID       app.PID
	StartTime uint64
	Device    uint64
	Inode     uint64

	RuntimeAddress          uint64
	RuntimeFinalizing       uint64
	RuntimeInterpretersMain uint64
	InterpreterGC           uint64
	GCGenerationStats       uint64

	PrimaryProbe  GCCompletionProbe
	FallbackProbe *GCCompletionProbe
	attachment    *os.File
}

// AttachmentPath returns a stable path for link.OpenExecutable.
func (t *MetricTarget) AttachmentPath() string {
	if t == nil || t.attachment == nil {
		return ""
	}
	return fmt.Sprintf("/proc/self/fd/%d", t.attachment.Fd())
}

// Close releases the mapped object after attachment finishes.
func (t *MetricTarget) Close() error {
	if t == nil || t.attachment == nil {
		return nil
	}
	err := t.attachment.Close()
	t.attachment = nil
	return err
}
