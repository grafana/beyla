//go:build !linux

package beyla

func CheckOSSupport() error {
	return nil
}

func CheckOSCapabilities(_ *Config) error {
	return nil
}
