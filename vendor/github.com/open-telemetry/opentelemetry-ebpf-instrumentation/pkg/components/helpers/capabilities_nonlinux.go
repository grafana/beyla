//go:build !linux

package helpers

// Fake file to avoid failing tests in non-linux environments

type OSCapability uint8

func (c OSCapability) String() string {
	return "FAKE"
}

type OSCapabilities int

func GetCurrentProcCapabilities() (*OSCapabilities, error) { return nil, nil }
func SetCurrentProcCapabilities(_ *OSCapabilities) error   { return nil }
func (caps *OSCapabilities) Has(_ OSCapability) bool       { return false }
func (caps *OSCapabilities) Clear(_ OSCapability)          {}
func (caps *OSCapabilities) Set(_ OSCapability)            {}
