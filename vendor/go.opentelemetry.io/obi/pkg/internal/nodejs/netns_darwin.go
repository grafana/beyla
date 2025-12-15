// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejs

func withNetNS(_ int, fn func() error) error {
	return fn()
}
