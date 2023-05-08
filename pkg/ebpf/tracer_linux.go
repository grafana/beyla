package ebpf

import "golang.org/x/sys/unix"

func bpfMount(pinPath string) error {
	return unix.Mount(pinPath, pinPath, "bpf", 0, "")
}
