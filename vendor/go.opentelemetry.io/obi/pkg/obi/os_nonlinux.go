// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package obi

func CheckOSSupport() error {
	return nil
}

func CheckOSCapabilities(_ *Config) error {
	return nil
}

func KernelVersion() (major, minor int) {
	return 5, 17
}
