package ebpfcommon

func FindNamespace(_ uint32) (uint32, error) {
	// convenience method to allow unit tests compiling in Darwin
	return 0, nil
}

func FindNamespacedPids(_ uint32) ([]uint32, error) {
	return nil, nil
}
