// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ec2 // import "go.opentelemetry.io/contrib/detectors/aws/ec2"

// Version is the current release version of the EC2 resource detector.
func Version() string {
	return "1.35.0"
	// This string is updated by the pre_release.sh script during release
}

// SemVersion is the semantic version to be supplied to tracer/meter creation.
//
// Deprecated: Use [Version] instead.
func SemVersion() string {
	return Version()
}
