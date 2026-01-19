//go:build linux
// +build linux

package jvm

import (
	"syscall"
	"unsafe"
)

const (
	SYS_SEMGET = 64
	SYS_SEMOP  = 65
	IPC_CREAT  = 01000
	IPC_NOWAIT = 04000
)

type sembuf struct {
	Num uint16
	Op  int16
	Flg int16
}

// System V semaphore operations for Linux
func semget(key, nsems, semflg int) (int, error) {
	r1, _, errno := syscall.Syscall(SYS_SEMGET, uintptr(key), uintptr(nsems), uintptr(semflg))
	if int(r1) == -1 {
		return -1, errno
	}
	return int(r1), nil
}

func semop(semid int, sops []sembuf) error {
	_, _, errno := syscall.Syscall(SYS_SEMOP, uintptr(semid), uintptr(unsafe.Pointer(&sops[0])), uintptr(len(sops)))
	if errno != 0 {
		return errno
	}
	return nil
}

func createSembuf(num uint16, op int16, flg int16) sembuf {
	return sembuf{
		Num: num,
		Op:  op,
		Flg: flg,
	}
}

// Ftok uses the given pathname (which must refer to an existing, accessible file) and
// the least significant 8 bits of proj_id (which must be nonzero) to generate
// a key_t type System V IPC key.
func ftok(pathname string, projectid uint8) (int, error) {
	var stat = syscall.Stat_t{}
	if err := syscall.Stat(pathname, &stat); err != nil {
		return 0, err
	}
	return int(uint(projectid&0xff)<<24 | uint((stat.Dev&0xff)<<16) | (uint(stat.Ino) & 0xffff)), nil
}
