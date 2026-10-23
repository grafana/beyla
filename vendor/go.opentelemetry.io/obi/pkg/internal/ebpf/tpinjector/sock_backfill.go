// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package tpinjector // import "go.opentelemetry.io/obi/pkg/internal/ebpf/tpinjector"

import (
	"bufio"
	"errors"
	"fmt"
	"math"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/prometheus/procfs"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/netns"
)

// TCP states as /proc/net/tcp prints them
const (
	tcpEstablishedState = 1
	tcpSynSentState     = 2
	tcpListenState      = 10
)

// above fs.nr_open's ceiling, so the probe can never duplicate a real descriptor
const unopenedFD = math.MaxInt32

// a netns's TCP sockets as of one read
type tcpTable struct {
	netns   uint64
	readAt  time.Time
	clients map[uint64]bool // socket inode: whether it is a client connection
}

type socketFD struct {
	fd    int
	inode uint64
}

var errNetCgroupsDiffer = errors.New("the process's net_cls or net_prio cgroups differ from OBI's")

// pidfd_getfd needs ptrace access to the target: EBADF means access was granted
func canDuplicateProcessFDs() bool {
	pidfd, err := unix.PidfdOpen(1, 0)
	if err != nil {
		return false
	}
	defer unix.Close(pidfd)

	_, err = unix.PidfdGetfd(pidfd, unopenedFD, 0)
	return errors.Is(err, unix.EBADF)
}

// otherwise every client socket is enrolled, as the ones opened before discovery can't be backfilled
func (p *Tracer) canBackfillSockets() bool {
	if !canDuplicateProcessFDs() {
		p.log.Warn("cannot duplicate the sockets of other processes (missing CAP_SYS_PTRACE?): " +
			"context propagation enrolls the TCP client sockets of every process on the host")
		return false
	}

	if netCgroupsInUse(p.procFS) {
		p.log.Info("cgroup v1 net_cls or net_prio is in use, and duplicating a socket would move it to OBI's: " +
			"context propagation enrolls the TCP client sockets of every process on the host")
		return false
	}

	if !procInOwnPIDNamespace(p.procFS) {
		p.log.Debug("/proc numbers processes in a pid namespace other than OBI's, so pidfd_open can't find them: " +
			"context propagation enrolls the TCP client sockets of every process on the host")
		return false
	}

	p.log.Debug("context propagation enrolls the TCP client sockets of instrumented processes only")
	return true
}

// pidfd_open resolves pids in OBI's own pid namespace
func procInOwnPIDNamespace(fs procfs.FS) bool {
	self, err := fs.Self()
	if err != nil {
		return false
	}
	first, err := fs.Proc(1)
	if err != nil {
		return false
	}

	own, err := self.Namespaces()
	if err != nil {
		return false
	}
	procs, err := first.Namespaces()
	if err != nil {
		return false
	}

	ownPID, ok := own["pid"]
	return ok && ownPID == procs["pid"]
}

// pidfd_getfd moves a duplicated socket to the caller's net_cls and net_prio cgroups (__receive_sock)
func netCgroups(proc procfs.Proc) ([]procfs.Cgroup, error) {
	cgroups, err := proc.Cgroups()
	if err != nil {
		return nil, err
	}

	return slices.DeleteFunc(cgroups, func(c procfs.Cgroup) bool {
		return !slices.Contains(c.Controllers, "net_cls") && !slices.Contains(c.Controllers, "net_prio")
	}), nil
}

func netCgroupsInUse(fs procfs.FS) bool {
	self, err := fs.Self()
	if err != nil {
		return true
	}

	cgroups, err := netCgroups(self)
	return err != nil || len(cgroups) > 0
}

func sameNetCgroups(fs procfs.FS, pid app.PID) error {
	self, err := fs.Self()
	if err != nil {
		return err
	}
	target, err := fs.Proc(int(pid))
	if err != nil {
		return err
	}

	own, err := netCgroups(self)
	if err != nil {
		return err
	}
	theirs, err := netCgroups(target)
	if err != nil {
		return err
	}

	if !slices.EqualFunc(own, theirs, func(a, b procfs.Cgroup) bool {
		return a.HierarchyID == b.HierarchyID && a.Path == b.Path
	}) {
		return errNetCgroupsDiffer
	}

	return nil
}

// false when the process's sockets can't be duplicated unchanged, so the netns walk has to cover them
func (p *Tracer) backfillSockets(pid app.PID, since time.Time) bool {
	if !p.sockhashSafe() {
		return true
	}

	p.socketsMu.Lock()
	defer p.socketsMu.Unlock()

	if err := sameNetCgroups(p.procFS, pid); err != nil {
		p.log.Debug("can't duplicate the process's sockets", "pid", pid, "error", err)
		return false
	}

	// an exited leader hides its threads' descriptors from /proc/<pid>/fd and pidfd_getfd
	if exited, err := leaderExited(p.procFS, pid); err != nil || exited {
		p.log.Debug("can't duplicate the process's sockets", "pid", pid, "error", err, "leaderExited", exited)
		return false
	}

	pidfd, err := unix.PidfdOpen(int(pid), 0)
	if errors.Is(err, unix.ESRCH) {
		return true
	}
	if err != nil {
		p.log.Debug("can't duplicate the process's sockets", "pid", pid, "error", err)
		return false
	}
	defer unix.Close(pidfd)

	sockets, err := socketFDs(pid)
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	if err != nil {
		p.log.Debug("can't duplicate the process's sockets", "pid", pid, "error", err)
		return false
	}

	var table *tcpTable
	seen := map[uint64]struct{}{}
	for _, s := range sockets {
		if p.socketsStopped.Load() {
			return true
		}
		if _, ok := seen[s.inode]; ok {
			continue
		}

		if table == nil {
			if table, err = p.tcpTable(pid, since); err != nil {
				p.log.Debug("can't duplicate the process's sockets", "pid", pid, "error", err)
				return false
			}
		}
		// only client connections are duplicated: the app can close its descriptor while OBI holds the copy
		if !table.clients[s.inode] {
			continue
		}

		// the descriptor can have been reused while the table was read
		if inode, ok := fdSocketInode(pid, s.fd); !ok || inode != s.inode {
			continue
		}

		dup, err := unix.PidfdGetfd(pidfd, s.fd, 0)
		switch {
		case errors.Is(err, unix.EBADF):
			// closed meanwhile
			continue
		case errors.Is(err, unix.ESRCH):
			return true
		case err != nil:
			p.log.Debug("can't duplicate the process's sockets", "pid", pid, "error", err)
			return false
		}

		// the descriptor number can have been reused since it was listed
		var st unix.Stat_t
		if unix.Fstat(dup, &st) == nil && st.Ino == s.inode {
			p.backfillSocket(dup)
			seen[s.inode] = struct{}{}
		}
		unix.Close(dup)
	}

	return true
}

// the table vouched for the socket, so the copy is held for as few syscalls as possible
func (p *Tracer) backfillSocket(fd int) {
	// a failed connect leaves a socket that can listen since the table was read
	if accepting, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ACCEPTCONN); err != nil || accepting != 0 {
		return
	}

	cookie, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
	if err != nil {
		return
	}

	// marked before the insert: the established callback enrolls a handshake that completes in between
	key := uint32(fd)
	if err := p.bpfObjects.SocketCookie.Update(&key, cookie, ebpf.UpdateNoExist); err != nil &&
		!errors.Is(err, ebpf.ErrKeyExist) {
		return
	}

	// fails for a socket that is not established yet, which the mark covers
	if err := p.bpfObjects.SockDir.Update(&cookie, uint32(fd), ebpf.UpdateNoExist); err == nil {
		if err := p.bpfObjects.TrackedSockCookies.Update(&cookie, uint8(1), ebpf.UpdateAny); err != nil {
			p.log.Debug("can't register backfilled socket cookie", "error", err)
		}
	}
}

func leaderExited(fs procfs.FS, pid app.PID) (bool, error) {
	proc, err := fs.Proc(int(pid))
	if err != nil {
		return false, err
	}
	stat, err := proc.Stat()
	if err != nil {
		return false, err
	}

	return stat.State == "Z", nil
}

// read after the process was enrolled, it lists every connection opened before: later ones are marked at connect
func (p *Tracer) tcpTable(pid app.PID, since time.Time) (*tcpTable, error) {
	info, err := os.Stat(fmt.Sprintf("/proc/%d/ns/net", pid))
	if err != nil {
		return nil, err
	}
	netns := info.Sys().(*syscall.Stat_t).Ino

	if last := p.lastTCPTable; last != nil && last.netns == netns && last.readAt.After(since) {
		return last, nil
	}

	var table *tcpTable
	if p.bpfIterObjects.ObiSkIterTcpClients != nil {
		table, err = p.iterTCPTable(pid)
	} else {
		table, err = readTCPTable(pid)
	}
	if err != nil {
		return nil, err
	}
	table.netns = netns
	p.lastTCPTable = table

	return table, nil
}

func (p *Tracer) iterTCPTable(pid app.PID) (*tcpTable, error) {
	if p.clientsIter == nil {
		lnk, err := link.AttachIter(link.IterOptions{Program: p.bpfIterObjects.ObiSkIterTcpClients})
		if err != nil {
			return nil, err
		}
		p.AddCloser(lnk)
		p.clientsIter = lnk
	}

	return clientSockets(pid, p.clientsIter)
}

// the client sockets of the process's network namespace, as obi_sk_iter_tcp_clients lists them
func clientSockets(pid app.PID, clients *link.Iter) (*tcpTable, error) {
	table := &tcpTable{clients: map[uint64]bool{}}
	err := netns.WithNetNS(int(pid), func() error {
		rd, err := clients.Open()
		if err != nil {
			return err
		}
		defer rd.Close()

		scanner := bufio.NewScanner(rd)
		for scanner.Scan() {
			inode, err := strconv.ParseUint(scanner.Text(), 10, 64)
			if err != nil {
				return err
			}
			table.clients[inode] = true
		}
		return scanner.Err()
	})
	table.readAt = time.Now()

	return table, err
}

// the TCP sockets of the process's network namespace, below kernel 5.11
func readTCPTable(pid app.PID) (*tcpTable, error) {
	fs, err := procfs.NewFS(fmt.Sprintf("/proc/%d", pid))
	if err != nil {
		return nil, err
	}

	var lines procfs.NetTCP
	for _, read := range []func() (procfs.NetTCP, error){fs.NetTCP, fs.NetTCP6} {
		l, err := read()
		// a namespace without IPv6 has no tcp6 table
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		lines = append(lines, l...)
	}

	// an accepted socket's local port is a listening port, which tells it apart from a client socket
	listening := map[uint64]struct{}{}
	for _, line := range lines {
		if line.St == tcpListenState {
			listening[line.LocalPort] = struct{}{}
		}
	}

	table := &tcpTable{readAt: time.Now(), clients: make(map[uint64]bool, len(lines))}
	for _, line := range lines {
		_, passive := listening[line.LocalPort]
		table.clients[line.Inode] = !passive && (line.St == tcpEstablishedState || line.St == tcpSynSentState)
	}

	return table, nil
}

func socketFDs(pid app.PID) ([]socketFD, error) {
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		return nil, err
	}

	sockets := make([]socketFD, 0, len(entries))
	for _, e := range entries {
		fd, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if inode, ok := fdSocketInode(pid, fd); ok {
			sockets = append(sockets, socketFD{fd: fd, inode: inode})
		}
	}

	return sockets, nil
}

// the inode of the socket the process's descriptor refers to, false for anything else
func fdSocketInode(pid app.PID, fd int) (uint64, bool) {
	target, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, fd))
	if err != nil {
		return 0, false
	}

	inode, ok := strings.CutPrefix(target, "socket:[")
	if !ok {
		return 0, false
	}

	ino, err := strconv.ParseUint(strings.TrimSuffix(inode, "]"), 10, 64)
	return ino, err == nil
}
