package httpfltr

// TODO: the httpfltr_linux.go will compile perfectly with Mac, so we can remove this file and rename httpfltr_linux.go

func findNamespace(_ int32) (uint32, error) {
	// convenience method to allow unit tests compiling in Darwin
	return 0, nil
}

func findNamespacedPids(_ int32) ([]uint32, error) {
	return nil, nil
}
