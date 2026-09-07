// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package javaagent // import "go.opentelemetry.io/obi/pkg/internal/java"

import "context"

// placeholder to avoid compilation errors in non-linux platforms

type JavaInjector struct{}

func NewJavaInjector(_ any) (*JavaInjector, error) { return nil, nil }
func (*JavaInjector) NewExecutable(_ context.Context, _ InjectionTarget) error {
	return nil
}
