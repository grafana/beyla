package jvm

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/grafana/jvmtools/util"
)

// Check if remote JVM has already opened socket for Dynamic Attach
func checkSocket(pid int, tmpPath string) bool {
	path := fmt.Sprintf("%s/.java_pid%d", tmpPath, pid)
	info, err := os.Stat(path)
	return err == nil && (info.Mode()&os.ModeSocket != 0)
}

// Check if a file is owned by current user
func getFileOwner(path string) (uid int) {
	info, err := os.Stat(path)
	if err != nil {
		return -1
	}
	stat := info.Sys().(*syscall.Stat_t)
	return int(stat.Uid)
}

// Force remote JVM to start Attach listener.
// HotSpot will start Attach listener in response to SIGQUIT if it sees .attach_pid file
func startAttachMechanism(pid, nspid, attachPid int, tmpPath string) bool {
	path := fmt.Sprintf("/proc/%d/cwd/.attach_pid%d", attachPid, nspid)
	fd, err := os.Create(path)
	if err != nil || (fd.Close() == nil && getFileOwner(path) != os.Geteuid()) {
		os.Remove(path)
		path = fmt.Sprintf("%s/.attach_pid%d", tmpPath, nspid)
		fd, err = os.Create(path)
		if err != nil {
			return false
		}
		fd.Close()
	}

	syscall.Kill(pid, syscall.SIGQUIT)

	ts := 20 * time.Millisecond
	for i := 0; i < 300; i++ {
		time.Sleep(ts)
		if checkSocket(nspid, tmpPath) {
			os.Remove(path)
			return true
		}
		ts += 20 * time.Millisecond
	}

	os.Remove(path)
	return false
}

// Connect to UNIX domain socket created by JVM for Dynamic Attach
func connectSocket(pid int, tmpPath string) (net.Conn, error) {
	return net.Dial("unix", fmt.Sprintf("%s/.java_pid%d", tmpPath, pid))
}

// Send command with arguments to socket
func writeCommand(conn net.Conn, args []string) error {
	request := make([]byte, 0)

	request = append(request, byte('1'))
	request = append(request, byte(0))

	for i := 0; i < 4; i++ {
		if i < len(args) {
			request = append(request, []byte(args[i])...)
		}
		request = append(request, byte(0))
	}

	_, err := conn.Write(request)
	return err
}

func jattachHotspot(pid, nspid, attachPid int, args []string, tmpPath string, logger *slog.Logger) (io.ReadCloser, error) {
	if !checkSocket(nspid, tmpPath) && !startAttachMechanism(pid, nspid, attachPid, tmpPath) {
		return nil, errors.New("could not start the attach mechanism")
	}

	conn, err := connectSocket(nspid, tmpPath)
	if err != nil {
		return nil, fmt.Errorf("could not connect to JVM socket: %w", err)
	}

	logger.Debug("connected to the JVM")

	if err := writeCommand(conn, args); err != nil {
		return nil, fmt.Errorf("error writing to the JVM socket: %w", err)
	}

	return conn, nil
}

func Jattach(pid int, argv []string, logger *slog.Logger) (io.ReadCloser, error) {
	myUID := syscall.Geteuid()
	myGID := syscall.Getegid()
	targetUID := myUID
	targetGID := myGID
	var nspid int

	if util.GetProcessInfo(pid, &targetUID, &targetGID, &nspid) != nil {
		return nil, fmt.Errorf("process not found: %v", pid)
	}

	// Container support: switch to the target namespaces.
	// Network and IPC namespaces are essential for OpenJ9 connection.
	util.EnterNS(pid, "net")
	util.EnterNS(pid, "ipc")
	mntChanged := util.EnterNS(pid, "mnt")

	// In HotSpot, dynamic attach is allowed only for the clients with the same euid/egid.
	// If we are running under root, switch to the required euid/egid automatically.
	if (myGID != targetGID && syscall.Setegid(int(targetGID)) != nil) ||
		(myUID != targetUID && syscall.Seteuid(int(targetUID)) != nil) {
		return nil, errors.New("failed to change credentials to match the target process")
	}

	attachPid := pid
	if mntChanged > 0 {
		attachPid = nspid
	}

	tmpPath := util.GetTmpPath(attachPid)

	// Make write() return EPIPE instead of abnormal process termination
	signal.Ignore(syscall.SIGPIPE)

	res, err := jattachHotspot(pid, nspid, attachPid, argv, tmpPath, logger)
	if err != nil {
		return nil, err
	}

	if (myGID != targetGID && syscall.Setegid(int(myUID)) != nil) ||
		(myUID != targetUID && syscall.Seteuid(int(myGID)) != nil) {
		return nil, errors.New("failed to change credentials back to my user")
	}

	return res, nil
}
