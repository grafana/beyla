// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Converted from C code from the jattach project
package jvm // import "go.opentelemetry.io/obi/pkg/internal/jvmtools/jvm"

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
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
	if logger == nil {
		logger = slog.Default()
	}

	j := &j9Attacher{
		logger: logger,
		fd:     -1,
	}

	return j
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
		result = "ATTACH_DIAGNOSTICS:" + strings.Join(append([]string{arg1}, argv[2:]...), ",")

	case "threaddump":
		arg1 := ""
		if argc > 1 {
			arg1 = argv[1]
		}
		result = "ATTACH_DIAGNOSTICS:Thread.print," + arg1

	case "dumpheap":
		arg1 := ""
		if argc > 1 {
			arg1 = argv[1]
		}
		result = "ATTACH_DIAGNOSTICS:Dump.heap," + arg1

	case "inspectheap":
		arg1 := ""
		if argc > 1 {
			arg1 = argv[1]
		}
		result = "ATTACH_DIAGNOSTICS:GC.class_histogram," + arg1

	case "datadump":
		arg1 := ""
		if argc > 1 {
			arg1 = argv[1]
		}
		result = "ATTACH_DIAGNOSTICS:Dump.java," + arg1

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
		if err != nil {
			return fmt.Errorf("write failed: %w", err)
		}
		if n <= 0 {
			return fmt.Errorf("write failed: %w", io.ErrShortWrite)
		}
		off += n
	}
	return nil
}

func closeWithErrno(fd int) {
	_ = syscall.Close(fd)
}

func acquireLock(tmpPath, subdir, filename string) (int, error) {
	path := filepath.Join(tmpPath, ".com_ibm_tools_attach", subdir, filename)

	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT, 0o666)
	if err != nil {
		return -1, err
	}

	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		err = errors.Join(err, syscall.Close(fd))
		return -1, err
	}

	return fd, nil
}

func releaseLock(lockFd int) error {
	return errors.Join(
		syscall.Flock(lockFd, syscall.LOCK_UN),
		syscall.Close(lockFd),
	)
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
						return s, sa6.Port, nil
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
		return s, sa4.Port, nil
	}

	closeWithErrno(s)
	return -1, 0, errors.New("failed to get socket port")
}

func closeAttachSocket(tmpPath string, s, pid int) error {
	path := filepath.Join(tmpPath, ".com_ibm_tools_attach", strconv.Itoa(pid), "replyInfo")
	var err error
	if unlinkErr := syscall.Unlink(path); unlinkErr != nil && !errors.Is(unlinkErr, syscall.ENOENT) {
		err = errors.Join(err, unlinkErr)
	}

	return errors.Join(err, syscall.Close(s))
}

func randomKey() uint64 {
	key := uint64(time.Now().Unix()) * 0xc6a4a7935bd1e995

	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return key
	}

	for i, b := range buf {
		key ^= uint64(b) << (uint(i) * 8)
	}

	return key
}

func writeReplyInfo(tmpPath string, pid, port int, key uint64) error {
	path := filepath.Join(tmpPath, ".com_ibm_tools_attach", strconv.Itoa(pid), "replyInfo")

	content := fmt.Sprintf("%016x\n%d\n", key, port)
	return os.WriteFile(path, []byte(content), 0o600)
}

func notifySemaphore(tmpPath string, value, notifyCount int) error {
	if notifyCount <= 0 {
		return nil
	}

	path := filepath.Join(tmpPath, ".com_ibm_tools_attach", "_notifier")

	semKey, err := ftok(path, 0xa1)
	if err != nil {
		return err
	}

	semID, err := semget(semKey, 1, unix.IPC_CREAT|0o666)
	if err != nil {
		return err
	}

	flags := int16(0)
	if value < 0 {
		flags = unix.IPC_NOWAIT
	}

	sb := createSembuf(0, int16(value), flags)

	for range notifyCount {
		if err := semop(semID, []sembuf{sb}); err != nil {
			return fmt.Errorf("semop failed: %w", err)
		}
	}

	return nil
}

func acceptClient(s int, key uint64) (int, error) {
	tv := syscall.Timeval{Sec: 5, Usec: 0}
	if err := syscall.SetsockoptTimeval(s, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return -1, fmt.Errorf("could not set JVM response timeout: %w", err)
	}

	nfd, _, err := syscall.Accept(s)
	if err != nil {
		return -1, fmt.Errorf("jvm did not respond: %w", err)
	}

	buf := make([]byte, 35)
	off := 0
	for off < len(buf) {
		n, err := syscall.Read(nfd, buf[off:])
		if err != nil {
			_ = syscall.Close(nfd)
			return -1, fmt.Errorf("the JVM connection was prematurely closed: %w", err)
		}
		if n <= 0 {
			_ = syscall.Close(nfd)
			return -1, fmt.Errorf("the JVM connection was prematurely closed: %w", io.ErrUnexpectedEOF)
		}
		off += n
	}

	expected := fmt.Sprintf("ATTACH_CONNECTED %016x ", key)
	if !bytes.Equal(buf[:len(expected)], []byte(expected)) {
		_ = syscall.Close(nfd)
		return -1, fmt.Errorf("unexpected JVM response %s", buf[:len(expected)])
	}

	// Reset the timeout, as the command execution may take arbitrary long time
	tv0 := syscall.Timeval{Sec: 0, Usec: 0}
	if err := syscall.SetsockoptTimeval(nfd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv0); err != nil {
		_ = syscall.Close(nfd)
		return -1, fmt.Errorf("could not reset JVM response timeout: %w", err)
	}

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

func (j *j9Attacher) unlockNotificationFiles(count int) error {
	var err error

	for i := range count {
		if j.notifyLock[i] >= 0 {
			err = errors.Join(err, releaseLock(j.notifyLock[i]))
			j.notifyLock[i] = -1
		}
	}

	return err
}

func (j *j9Attacher) releaseNotificationFiles(tmpPath string, count int) error {
	return errors.Join(
		j.unlockNotificationFiles(count),
		notifySemaphore(tmpPath, -1, count),
	)
}

func isOpenJ9Process(tmpPath string, pid int) bool {
	path := filepath.Join(tmpPath, ".com_ibm_tools_attach", strconv.Itoa(pid), "attachInfo")
	_, err := os.Stat(path)
	return err == nil
}

type j9Reader struct {
	attacher *j9Attacher
}

func (r *j9Reader) Read(p []byte) (int, error) {
	if r.attacher.fd < 0 {
		return 0, os.ErrClosed
	}

	for {
		n, err := syscall.Read(r.attacher.fd, p)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return 0, err
		}
		if n == 0 {
			return 0, io.EOF
		}

		return n, nil
	}
}

func (r *j9Reader) Close() error {
	return r.attacher.detach()
}

func (j *j9Attacher) closeFD() error {
	if j.fd < 0 {
		return nil
	}

	fd := j.fd
	j.fd = -1
	return syscall.Close(fd)
}

func (j *j9Attacher) detach() error {
	if j.fd < 0 {
		return nil
	}

	fd := j.fd
	j.fd = -1

	var detachErr error
	if err := writeCommand(fd, "ATTACH_DETACHED"); err != nil {
		detachErr = errors.Join(detachErr, err)
	}

	buf := make([]byte, 256)
	if detachErr == nil {
		for {
			n, err := syscall.Read(fd, buf)
			if err != nil || n <= 0 || buf[n-1] == 0 {
				break
			}
		}
	}

	return errors.Join(detachErr, syscall.Close(fd))
}

func (j *j9Attacher) jattachOpenJ9(tmpPath string, nspid int, argv []string) (reader io.ReadCloser, err error) {
	attachLock, err := acquireLock(tmpPath, "", "_attachlock")
	if err != nil {
		return nil, fmt.Errorf("could not acquire attach lock: %w", err)
	}

	notifyCount := 0
	s := -1
	var port int

	defer func() {
		var cleanupErr error
		if s >= 0 {
			cleanupErr = errors.Join(cleanupErr, closeAttachSocket(tmpPath, s, nspid))
		}
		if notifyCount > 0 {
			cleanupErr = errors.Join(cleanupErr, j.releaseNotificationFiles(tmpPath, notifyCount))
		}
		if attachLock >= 0 {
			cleanupErr = errors.Join(cleanupErr, releaseLock(attachLock))
		}
		if err != nil {
			cleanupErr = errors.Join(cleanupErr, j.closeFD())
		}
		if cleanupErr != nil {
			err = errors.Join(err, cleanupErr)
		}
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

	closeErr := closeAttachSocket(tmpPath, s, nspid)
	s = -1
	if closeErr != nil {
		return nil, fmt.Errorf("could not close attach socket: %w", closeErr)
	}

	notifyErr := j.releaseNotificationFiles(tmpPath, notifyCount)
	notifyCount = 0
	if notifyErr != nil {
		return nil, fmt.Errorf("could not release OpenJ9 notification files: %w", notifyErr)
	}

	releaseErr := releaseLock(attachLock)
	attachLock = -1
	if releaseErr != nil {
		return nil, fmt.Errorf("could not release OpenJ9 attach lock: %w", releaseErr)
	}

	j.logger.Info("connected to remote JVM")

	cmd := translateCommand(argv)

	if writeErr := writeCommand(fd, cmd); writeErr != nil {
		return nil, errors.Join(fmt.Errorf("error writing to socket: %w", writeErr), j.closeFD())
	}

	return &j9Reader{attacher: j}, nil
}
