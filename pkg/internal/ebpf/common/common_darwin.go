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
