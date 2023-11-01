package ebpfcommon

func findNamespace(_ int32) (uint32, error) {
	// convenience method to allow unit tests compiling in Darwin
	return 0, nil
}

func findNamespacedPids(_ int32) ([]uint32, error) {
}
