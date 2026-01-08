// Converted from C code from the jattach project
package jvm

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

const (
	MaxNotifyFiles = 256
)

type j9Attacher struct {
	notifyLock [MaxNotifyFiles]int
	logger     *slog.Logger
	fd         int
}

func newJ9Attacher(logger *slog.Logger) *j9Attacher {
	return &j9Attacher{
		logger: logger,
	}
}

// Translate HotSpot command to OpenJ9 equivalent
func translateCommand(argv []string) string {
	if len(argv) == 0 {
		return ""
	}

	argc := len(argv)
	cmd := argv[0]
	var result string

	switch cmd {
	case "load":
		if argc >= 2 {
			arg3 := ""
			if argc > 3 {
				arg3 = argv[3]
			}
			if argc > 2 && argv[2] == "true" {
				result = fmt.Sprintf("ATTACH_LOADAGENTPATH(%s,%s)", argv[1], arg3)
			} else {
				result = fmt.Sprintf("ATTACH_LOADAGENT(%s,%s)", argv[1], arg3)
			}
		}

	case "jcmd":
		arg1 := "help"
		if argc > 1 {
			arg1 = argv[1]
		}
		result = fmt.Sprintf("ATTACH_DIAGNOSTICS:%s", arg1)
		for i := 2; i < argc; i++ {
			result += "," + argv[i]
		}

	case "threaddump":
		arg1 := ""
		if argc > 1 {
			arg1 = argv[1]
		}
		result = fmt.Sprintf("ATTACH_DIAGNOSTICS:Thread.print,%s", arg1)

	case "dumpheap":
		arg1 := ""
		if argc > 1 {
			arg1 = argv[1]
		}
		result = fmt.Sprintf("ATTACH_DIAGNOSTICS:Dump.heap,%s", arg1)

	case "inspectheap":
		arg1 := ""
		if argc > 1 {
			arg1 = argv[1]
		}
		result = fmt.Sprintf("ATTACH_DIAGNOSTICS:GC.class_histogram,%s", arg1)

	case "datadump":
		arg1 := ""
		if argc > 1 {
			arg1 = argv[1]
		}
		result = fmt.Sprintf("ATTACH_DIAGNOSTICS:Dump.java,%s", arg1)

	case "properties":
		result = "ATTACH_GETSYSTEMPROPERTIES"

	case "agentProperties":
		result = "ATTACH_GETAGENTPROPERTIES"

	default:
		result = cmd
	}

	return result
}

// Send command with arguments to socket
func writeCommand(fd int, cmd string) error {
	data := []byte(cmd)
	data = append(data, 0) // null terminator

	off := 0
	for off < len(data) {
		n, err := syscall.Write(fd, data[off:])
		if err != nil || n <= 0 {
			return fmt.Errorf("write failed")
		}
		off += n
	}
	return nil
}

func closeWithErrno(fd int) {
	syscall.Close(fd)
}

func acquireLock(tmpPath, subdir, filename string) (int, error) {
	path := filepath.Join(tmpPath, ".com_ibm_tools_attach", subdir, filename)

	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT, 0666)
	if err != nil {
		return -1, err
	}

	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		syscall.Close(fd)
		return -1, err
	}

	return fd, nil
}

func releaseLock(lockFd int) {
	syscall.Flock(lockFd, syscall.LOCK_UN)
	syscall.Close(lockFd)
}

func createAttachSocket() (int, int, error) {
	// Try IPv6 socket first, then fall back to IPv4
	s, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_STREAM, 0)
	if err == nil {
		addr := &syscall.SockaddrInet6{}
		if err := syscall.Bind(s, addr); err == nil {
			if err := syscall.Listen(s, 0); err == nil {
				sa, err := syscall.Getsockname(s)
				if err == nil {
					if sa6, ok := sa.(*syscall.SockaddrInet6); ok {
						return s, int(sa6.Port), nil
					}
				}
			}
		}
		closeWithErrno(s)
	}

	// Fall back to IPv4
	s, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		return -1, 0, err
	}

	addr := &syscall.SockaddrInet4{}
	if err := syscall.Bind(s, addr); err != nil {
		closeWithErrno(s)
		return -1, 0, err
	}

	if err := syscall.Listen(s, 0); err != nil {
		closeWithErrno(s)
		return -1, 0, err
	}

	sa, err := syscall.Getsockname(s)
	if err != nil {
		closeWithErrno(s)
		return -1, 0, err
	}

	if sa4, ok := sa.(*syscall.SockaddrInet4); ok {
		return s, int(sa4.Port), nil
	}

	closeWithErrno(s)
	return -1, 0, fmt.Errorf("failed to get socket port")
}

func closeAttachSocket(tmpPath string, s, pid int) {
	path := filepath.Join(tmpPath, ".com_ibm_tools_attach", strconv.Itoa(pid), "replyInfo")
	syscall.Unlink(path)
	syscall.Close(s)
}

func randomKey() uint64 {
	key := uint64(time.Now().Unix()) * 0xc6a4a7935bd1e995

	fd, err := syscall.Open("/dev/urandom", syscall.O_RDONLY, 0)
	if err == nil {
		buf := make([]byte, 8)
		syscall.Read(fd, buf)
		syscall.Close(fd)

		for i := 0; i < 8; i++ {
			key ^= uint64(buf[i]) << (uint(i) * 8)
		}
	}

	return key
}

func writeReplyInfo(tmpPath string, pid, port int, key uint64) error {
	path := filepath.Join(tmpPath, ".com_ibm_tools_attach", strconv.Itoa(pid), "replyInfo")

	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	content := fmt.Sprintf("%016x\n%d\n", key, port)
	syscall.Write(fd, []byte(content))

	return nil
}

func notifySemaphore(tmpPath string, value, notifyCount int) error {
	path := filepath.Join(tmpPath, ".com_ibm_tools_attach", "_notifier")

	semKey, err := ftok(path, 0xa1)
	if err != nil {
		return err
	}

	semID, err := semget(semKey, 1, IPC_CREAT|0666)
	if err != nil {
		return err
	}

	flags := int16(0)
	if value < 0 {
		flags = IPC_NOWAIT
	}

	sb := createSembuf(0, int16(value), flags)

	for range notifyCount {
		semop(semID, []sembuf{sb})
	}

	return nil
}

func acceptClient(s int, key uint64) (int, error) {
	tv := syscall.Timeval{Sec: 5, Usec: 0}
	syscall.SetsockoptTimeval(s, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	nfd, _, err := syscall.Accept(s)
	if err != nil {
		return -1, fmt.Errorf("JVM did not respond: %w", err)
	}

	buf := make([]byte, 35)
	off := 0
	for off < len(buf) {
		n, err := syscall.Read(nfd, buf[off:])
		if err != nil || n <= 0 {
			syscall.Close(nfd)
			return -1, fmt.Errorf("the JVM connection was prematurely closed")
		}
		off += n
	}

	expected := fmt.Sprintf("ATTACH_CONNECTED %016x ", key)
	if !bytes.Equal(buf[:len(expected)], []byte(expected)) {
		syscall.Close(nfd)
		return -1, fmt.Errorf("unexpected JVM response %s", buf[:len(expected)])
	}

	// Reset the timeout, as the command execution may take arbitrary long time
	tv0 := syscall.Timeval{Sec: 0, Usec: 0}
	syscall.SetsockoptTimeval(nfd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv0)

	return nfd, nil
}

func (j *j9Attacher) lockNotificationFiles(tmpPath string) int {
	count := 0
	path := filepath.Join(tmpPath, ".com_ibm_tools_attach")

	dir, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer dir.Close()

	entries, err := dir.Readdir(-1) // all files
	if err != nil {
		return 0
	}

	for _, entry := range entries {
		if count >= MaxNotifyFiles {
			break
		}
		name := entry.Name()
		if len(name) > 0 && name[0] >= '1' && name[0] <= '9' && entry.IsDir() {
			if fd, err := acquireLock(tmpPath, name, "attachNotificationSync"); err == nil {
				j.notifyLock[count] = fd
				count++
			}
		}
	}

	return count
}

func (j *j9Attacher) unlockNotificationFiles(count int) {
	for i := range count {
		if j.notifyLock[i] >= 0 {
			releaseLock(j.notifyLock[i])
		}
	}
}

func isOpenJ9Process(tmpPath string, pid int) bool {
	path := filepath.Join(tmpPath, ".com_ibm_tools_attach", strconv.Itoa(pid), "attachInfo")
	_, err := os.Stat(path)
	return err == nil
}

func (j *j9Attacher) detach() {
	if j.fd == 0 {
		return
	}

	if writeCommand(j.fd, "ATTACH_DETACHED") != nil {
		return
	}

	buf := make([]byte, 256)
	for {
		n, err := syscall.Read(j.fd, buf)
		if err != nil || n <= 0 || buf[n-1] == 0 {
			break
		}
	}
}

func (j *j9Attacher) jattachOpenJ9(tmpPath string, pid, nspid int, argv []string) (io.ReadCloser, error) {
	attachLock, err := acquireLock(tmpPath, "", "_attachlock")
	if err != nil {
		return nil, fmt.Errorf("could not acquire attach lock: %w", err)
	}

	notifyCount := 0
	s := -1
	var port int

	defer func() {
		if s >= 0 {
			closeAttachSocket(tmpPath, s, nspid)
		}
		if notifyCount > 0 {
			j.unlockNotificationFiles(notifyCount)
			notifySemaphore(tmpPath, -1, notifyCount)
		}
		releaseLock(attachLock)
	}()

	s, port, err = createAttachSocket()
	if err != nil {
		return nil, fmt.Errorf("failed to listen to attach socket: %w", err)
	}

	key := randomKey()
	if err := writeReplyInfo(tmpPath, nspid, port, key); err != nil {
		return nil, fmt.Errorf("could not write replyInfo: %w", err)
	}

	notifyCount = j.lockNotificationFiles(tmpPath)
	if err := notifySemaphore(tmpPath, 1, notifyCount); err != nil {
		return nil, fmt.Errorf("could not notify semaphore: %w", err)
	}

	fd, err := acceptClient(s, key)
	if err != nil {
		return nil, err
	}

	j.fd = fd

	closeAttachSocket(tmpPath, s, nspid)
	s = -1
	j.unlockNotificationFiles(notifyCount)
	notifySemaphore(tmpPath, -1, notifyCount)
	notifyCount = 0
	releaseLock(attachLock)
	attachLock = -1

	j.logger.Info("Connected to remote JVM")

	cmd := translateCommand(argv)

	if err := writeCommand(fd, cmd); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("error writing to socket: %w", err)
	}

	reader := os.NewFile(uintptr(fd), "socket")

	return reader, nil
}
