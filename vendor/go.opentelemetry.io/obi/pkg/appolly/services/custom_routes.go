// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package services

type CustomRoutesConfig struct {
	Incoming []string `yaml:"incoming"`
	Outgoing []string `yaml:"outgoing"`
}
