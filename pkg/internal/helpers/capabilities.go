//go:build linux

package helpers

import (
	"os"

	"golang.org/x/sys/unix"
)

type OSCapability uint8

var capDesc = map[OSCapability]string{
	unix.CAP_AUDIT_CONTROL:      "CAP_AUDIT_CONTROL",
	unix.CAP_AUDIT_READ:         "CAP_AUDIT_READ",
	unix.CAP_AUDIT_WRITE:        "CAP_AUDIT_WRITE",
	unix.CAP_BLOCK_SUSPEND:      "CAP_BLOCK_SUSPEND",
	unix.CAP_BPF:                "CAP_BPF",
	unix.CAP_CHECKPOINT_RESTORE: "CAP_CHECKPOINT_RESTORE",
	unix.CAP_CHOWN:              "CAP_CHOWN",
	unix.CAP_DAC_OVERRIDE:       "CAP_DAC_OVERRIDE",
	unix.CAP_DAC_READ_SEARCH:    "CAP_DAC_READ_SEARCH",
	unix.CAP_FOWNER:             "CAP_FOWNER",
	unix.CAP_FSETID:             "CAP_FSETID",
	unix.CAP_IPC_LOCK:           "CAP_IPC_LOCK",
	unix.CAP_IPC_OWNER:          "CAP_IPC_OWNER",
	unix.CAP_KILL:               "CAP_KILL",
	unix.CAP_LEASE:              "CAP_LEASE",
	unix.CAP_LINUX_IMMUTABLE:    "CAP_LINUX_IMMUTABLE",
	unix.CAP_MAC_ADMIN:          "CAP_MAC_ADMIN",
	unix.CAP_MAC_OVERRIDE:       "CAP_MAC_OVERRIDE",
	unix.CAP_MKNOD:              "CAP_MKNOD",
	unix.CAP_NET_ADMIN:          "CAP_NET_ADMIN",
	unix.CAP_NET_BIND_SERVICE:   "CAP_NET_BIND_SERVICE",
	unix.CAP_NET_BROADCAST:      "CAP_NET_BROADCAST",
	unix.CAP_NET_RAW:            "CAP_NET_RAW",
	unix.CAP_PERFMON:            "CAP_PERFMON",
	unix.CAP_SETFCAP:            "CAP_SETFCAP",
	unix.CAP_SETGID:             "CAP_SETGID",
	unix.CAP_SETPCAP:            "CAP_SETPCAP",
	unix.CAP_SETUID:             "CAP_SETUID",
	unix.CAP_SYSLOG:             "CAP_SYSLOG",
	unix.CAP_SYS_ADMIN:          "CAP_SYS_ADMIN",
	unix.CAP_SYS_BOOT:           "CAP_SYS_BOOT",
	unix.CAP_SYS_CHROOT:         "CAP_SYS_CHROOT",
	unix.CAP_SYS_MODULE:         "CAP_SYS_MODULE",
	unix.CAP_SYS_NICE:           "CAP_SYS_NICE",
	unix.CAP_SYS_PACCT:          "CAP_SYS_PACCT",
	unix.CAP_SYS_PTRACE:         "CAP_SYS_PTRACE",
	unix.CAP_SYS_RAWIO:          "CAP_SYS_RAWIO",
	unix.CAP_SYS_RESOURCE:       "CAP_SYS_RESOURCE",
	unix.CAP_SYS_TIME:           "CAP_SYS_TIME",
	unix.CAP_SYS_TTY_CONFIG:     "CAP_SYS_TTY_CONFIG",
	unix.CAP_WAKE_ALARM:         "CAP_WAKE_ALARM",
}

func (c OSCapability) String() string {
	if str, ok := capDesc[c]; ok {
		return str
	}

	return "UNKNOWN"
}

// From the capget(2) manpage:
// Note that 64-bit capabilities use datap[0] and datap[1], whereas 32-bit capabilities use only datap[0].
type OSCapabilities [2]unix.CapUserData

func capUserHeader() *unix.CapUserHeader {
	return &unix.CapUserHeader{
		Version: unix.LINUX_CAPABILITY_VERSION_3,
		Pid:     int32(os.Getpid()),
	}
}

func GetCurrentProcCapabilities() (*OSCapabilities, error) {
	caps := OSCapabilities{}

	err := unix.Capget(capUserHeader(), &caps[0])

	return &caps, err
}

func SetCurrentProcCapabilities(caps *OSCapabilities) error {
	return unix.Capset(capUserHeader(), &caps[0])
}

func (caps *OSCapabilities) Has(c OSCapability) bool {
	return ((*caps)[c>>5].Effective & (1 << (c & 31))) > 0
}

func (caps *OSCapabilities) Clear(c OSCapability) {
	(*caps)[c>>5].Effective &= ^(1 << (c & 31))
}

func (caps *OSCapabilities) Set(c OSCapability) {
	(*caps)[c>>5].Effective |= (1 << (c & 31))
}
