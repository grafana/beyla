// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package harvest // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"

type (
	JavaRoutes   struct{ Attacher JavaAttacher }
	JavaAttacher interface {
		Init()
		Cleanup()
	}
)

func NewJavaRoutesHarvester() *JavaRoutes {
	return &JavaRoutes{Attacher: fakeAttacher{}}
}
func (h *JavaRoutes) ExtractRoutes(_ int32) (*RouteHarvesterResult, error) { return nil, nil }

type fakeAttacher struct{}

func (f fakeAttacher) Init()    {}
func (f fakeAttacher) Cleanup() {}
