//go:build !linux

package beyla

func CheckOSSupport() error {
	return nil
}

func CheckOSCapabilities(_ *Config) error {
	return nil
}

func KernelVersion() (major, minor int) {
	return 5, 17
}
