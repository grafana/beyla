package ebpfcommon

func KernelVersion() (major, minor int) {
	return 0, 0
}

func hasCapSysAdmin() bool {
	return false
}

func HasHostPidAccess() bool {
	return true
}

func HasHostNetworkAccess() (bool, error) {
	return false, nil
}

func FindNetworkNamespace(_ int32) (string, error) {
	return "", nil
}

func RootDirectoryForPID(_ int32) string {
	return ""
}
