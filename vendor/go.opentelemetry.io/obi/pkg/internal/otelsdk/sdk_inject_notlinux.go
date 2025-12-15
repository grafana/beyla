// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package otelsdk

// placeholder to avoid compilation errors in non-linux platforms

type SDKInjector struct{}

func NewSDKInjector(_ any) *SDKInjector        { return nil }
func (*SDKInjector) NewExecutable(_ any) error { return nil }
func (*SDKInjector) Enabled() bool             { return false }
