package httpfltr

func findNamespace(_ int32) (uint32, error) {
	// convenience method to allow unit tests compiling in Darwin
	return 1, nil
}

func findLibssl() (string, error) {
	return "", nil
}
