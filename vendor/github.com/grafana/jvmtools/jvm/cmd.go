package jvm

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/grafana/jvmtools/util"
)

type JAttacher struct {
	logger     *slog.Logger
	j9attacher *j9Attacher
	myUID      int
	myGID      int
	myPID      int
}

func NewJAttacher(logger *slog.Logger) *JAttacher {
	return &JAttacher{
		logger:     logger,
		j9attacher: nil,
	}
}

func (j *JAttacher) Init() {
	myUID := syscall.Geteuid()
	myGID := syscall.Getegid()
	myPID := os.Getpid()

	j.myUID = myUID
	j.myGID = myGID
	j.myPID = myPID
}

func (j *JAttacher) Cleanup() error {
	if j.j9attacher != nil {
		j.j9attacher.detach()
	}
	if err := syscall.Seteuid(j.myUID); err != nil {
		j.logger.Error("failed to restore uid", "error", err)
	}
	if err := syscall.Setegid(j.myGID); err != nil {
		j.logger.Error("failed to restore gid", "error", err)
	}

	util.EnterNS(j.myPID, "net")
	util.EnterNS(j.myPID, "ipc")
	util.EnterNS(j.myPID, "mnt")

	return nil
}

func (j *JAttacher) Attach(pid int, argv []string, ignoreOnJ9 bool) (io.ReadCloser, error) {
	targetUID := j.myUID
	targetGID := j.myGID
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
	if (j.myGID != targetGID && syscall.Setegid(int(targetGID)) != nil) ||
		(j.myUID != targetUID && syscall.Seteuid(int(targetUID)) != nil) {
		return nil, errors.New("failed to change credentials to match the target process")
	}

	attachPid := pid
	if mntChanged > 0 {
		attachPid = nspid
	}

	tmpPath := util.GetTmpPath(attachPid)

	// Make write() return EPIPE instead of abnormal process termination
	signal.Ignore(syscall.SIGPIPE)

	if isOpenJ9Process(tmpPath, attachPid) {
		if ignoreOnJ9 {
			return nil, nil
		}
		j9attacher := newJ9Attacher(j.logger)
		j.j9attacher = j9attacher
		return j.j9attacher.jattachOpenJ9(tmpPath, pid, nspid, argv)
	}

	return jattachHotspot(pid, nspid, attachPid, argv, tmpPath, j.logger)
}
