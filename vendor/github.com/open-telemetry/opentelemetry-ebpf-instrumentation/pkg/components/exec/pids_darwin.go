package exec

func FindNamespace(_ int32) (uint32, error) {
	// convenience method to allow unit tests compiling in Darwin
	return 0, nil
}

func FindNamespacedPids(_ int32) ([]uint32, error) {
	return nil, nil
}
