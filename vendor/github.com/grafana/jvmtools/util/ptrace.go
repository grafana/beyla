package util

import (
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const maxAttachRetries = 5
const noSuchProcess = "no such process"

type JavaProgram struct {
	Info *FileInfo
	Tids map[int]struct{}
}

func waitPid(pid int) error {
	ret, err := unix.Wait4(pid, nil, unix.WALL, nil)

	if err != nil {
		return err
	}

	if ret == pid {
		return nil
	}

	return fmt.Errorf("error waiting for process with pid %d, result %d", pid, ret)
}

func AttachToJavaProgram(fileInfo *FileInfo) (*JavaProgram, error) {
	stopped := map[int]struct{}{}
	retries := map[int]int{}

	for i := 0; i < maxAttachRetries; i++ {
		err := syscall.PtraceAttach(fileInfo.Pid)
		if err == nil {
			waitPid(fileInfo.Pid)
			stopped[fileInfo.Pid] = struct{}{}
		}
	}

	for {
		threads, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", fileInfo.Pid))
		if err != nil {
			return nil, err
		}

		currentThreads := map[int]struct{}{}
		newThreads := false
		for _, t := range threads {
			parsedTid, err := strconv.ParseInt(t.Name(), 10, 32)
			if err != nil {
				return nil, err
			}

			tid := int(parsedTid)

			_, ok := stopped[tid]

			if ok {
				currentThreads[tid] = struct{}{}
				continue
			}

			newThreads = true

			err = syscall.PtraceAttach(tid)

			if err != nil {
				if strings.Contains(err.Error(), noSuchProcess) {
					continue
				}

				_, ok := retries[tid]
				if ok {
					retries[tid]++
				} else {
					retries[tid] = 1
				}

				if retries[tid] > maxAttachRetries {
					return nil, fmt.Errorf("failed to stop thread %d after %d retries", tid, maxAttachRetries)
				}

				continue
			}

			err = waitPid(tid)
			if err != nil {
				detachErr := syscall.PtraceDetach(tid)
				if detachErr != nil && !strings.Contains(detachErr.Error(), noSuchProcess) {
					fmt.Printf("detach failed for tid %d, error %v", tid, detachErr)
				}
				return nil, err
			}

			currentThreads[tid] = struct{}{}
			stopped[tid] = struct{}{}
		}

		// Reset the stopped map, maybe some old threads are no longer here
		if !newThreads {
			stopped = currentThreads
			break
		}
	}

	return &JavaProgram{Info: fileInfo, Tids: stopped}, nil
}

func (p *JavaProgram) DetachFromJavaProgram() error {
	for tid := range p.Tids {
		err := syscall.PtraceDetach(tid)
		if err != nil {
			if !strings.Contains(err.Error(), noSuchProcess) {
				return err
			}
		}
		waitPid(tid)
	}

	return nil
}

func (p *JavaProgram) ReadMemoryIntoBuf(address uintptr, buf []byte, size int) error {
	_, err := syscall.PtracePeekData(p.Info.Pid, address, buf[:size])
	if err != nil {
		return err
	}

	return nil
}

func (p *JavaProgram) WriteBufInfoMemory(address uintptr, buf []byte, size int) error {
	_, err := syscall.PtracePokeData(p.Info.Pid, address, buf[:size])
	if err != nil {
		return err
	}

	return nil
}

func (p *JavaProgram) ReadMemory(address uintptr, size int) ([]byte, error) {
	out := make([]byte, size)
	err := p.ReadMemoryIntoBuf(address, out, size)
	if err != nil {
		return nil, err
	}

	return out, nil
}

func (p *JavaProgram) ReadUint64(address uintptr) (uint64, error) {
	out, err := p.ReadMemory(address, 8)
	if err != nil {
		return 0, err
	}

	return binary.LittleEndian.Uint64(out), nil
}

func (p *JavaProgram) ReadSymbolValues(syms map[string]uintptr) (map[string]uint64, error) {
	r := map[string]uint64{}

	for sym, addr := range syms {
		val, err := p.ReadUint64(addr)
		if err != nil {
			return nil, fmt.Errorf("error reading value for %s[@%x], error %v", sym, addr, err)
		}

		r[sym] = val
	}

	return r, nil
}
