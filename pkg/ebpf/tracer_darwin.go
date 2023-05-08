package ebpf

func bpfMount(_ string) error {
	// dummy function to compilation errors in Darwin, due to the
	// different signatures of unix.Mount functions
	return nil
}
