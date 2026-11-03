// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schema // import "go.opentelemetry.io/obi/internal/config/schema"

import "fmt"

// NotV2Error reports input that does not contain an OBI v2 configuration.
//
// It is distinct from UnsupportedVersionError: NotV2Error means no usable OBI v2
// version marker was found, while UnsupportedVersionError means a version marker
// was found but is not supported by this package.
type NotV2Error struct {
	Reason string
}

func (e *NotV2Error) Error() string {
	if e == nil || e.Reason == "" {
		return "configuration is not OBI config v2"
	}
	return "configuration is not OBI config v2: " + e.Reason
}

func (e *NotV2Error) Is(target error) bool {
	_, ok := target.(*NotV2Error)
	return ok
}

// UnsupportedVersionError reports an OBI v2 version field whose value is present
// but not handled by this package.
type UnsupportedVersionError struct {
	Version string
}

func (e *UnsupportedVersionError) Error() string {
	return fmt.Sprintf("unsupported OBI config version %q", e.Version)
}

// UnsupportedFileFormatError reports an OpenTelemetry declarative file_format
// value whose version is present but not handled by this package.
type UnsupportedFileFormatError struct {
	FileFormat string
}

func (e *UnsupportedFileFormatError) Error() string {
	return fmt.Sprintf("unsupported OpenTelemetry config file_format %q", e.FileFormat)
}

// ReceiverLayoutError reports a standalone OBI configuration envelope passed
// to the Collector receiver parser.
type ReceiverLayoutError struct{}

func (*ReceiverLayoutError) Error() string {
	return "standalone OBI config v2 layout is not valid in receiver config; " +
		"move extensions.obi.capture fields to the receiver top level and set version there"
}

// SectionNotAllowedError reports a standalone-only configuration section in a
// receiver-embedded OBI config.
type SectionNotAllowedError struct {
	// Section is the YAML key that is not allowed in receiver config.
	Section string
}

func (e *SectionNotAllowedError) Error() string {
	return fmt.Sprintf(
		"section %q is not allowed in receiver config; remove it from the receiver config or run this config in standalone mode",
		e.Section,
	)
}
