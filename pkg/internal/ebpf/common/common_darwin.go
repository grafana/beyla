package ebpfcommon

func KernelVersion() (major, minor int) {
	return 0, 0
}

func hasCapSysAdmin() bool {
	return false
}

func HasHostPidAccess() bool {
	return false
}

func HasHostNetworkAccess() (bool, error) {
	return false, nil
}

func FindNetworkNamespace(pid int32) (string, error) {
	return "", nil
}

func RootDirectoryForPID(pid int32) string {
	return ""
}
