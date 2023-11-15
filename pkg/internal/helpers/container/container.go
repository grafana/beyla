// Package container provides helper tools to inspect container information
package container

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"runtime"
	"strconv"
	"syscall"
)

type Info struct {
	Hostname string
	IPs      []string
}

func InfoForPID(pid int) (Info, error) {
	log := slog.With("component", "container.InfoForPID", "pid", pid)

	// This function uses the SetNS syscall, which changes the namespaces for the
	// current thread. We must prevent that other goroutines uses the current
	// thread until we restore back the original namespace
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	beylaPID := os.Getpid()
	if err := setNS(pid, "uts"); err != nil {
		return Info{}, fmt.Errorf("changing UTS namespace for PID %d: %w", pid, err)
	}
	processHostName, err := os.Hostname()
	if err != nil {
		log.Warn("can't get container hostname for process. Keeping it empty",
			"pid", pid, "error", err)
	}
	// restoring Beyla UTS PID
	if err := setNS(beylaPID, "uts"); err != nil {
		return Info{}, fmt.Errorf("restoring UTS namespace for Beyla: %w", err)
	}

	if err := setNS(pid, "net"); err != nil {
		return Info{}, fmt.Errorf("changing NET namespace for PID %d: %w", pid, err)
	}
	ips := localIPs()
	// restoring Beyla NET PID
	if err := setNS(beylaPID, "net"); err != nil {
		return Info{}, fmt.Errorf("restoring NET namespace for Beyla: %w", err)
	}

	return Info{
		Hostname: processHostName,
		IPs:      ips,
	}, nil
}

// setNS invokes its homonym syscall (https://man7.org/linux/man-pages/man2/setns.2.html)
// for a given PID and namespace type
func setNS(pid int, nstype string) error {
	nsPath := "/proc/" + strconv.Itoa(pid) + "/ns/" + nstype
	fd, err := syscall.Open(nsPath, syscall.O_RDONLY, 0666)
	if err != nil {
		return fmt.Errorf("can't open %s: %w", nsPath, err)
	}
	defer syscall.Close(fd)

	ret, errno, err := syscall.RawSyscall(syscall.SYS_SETNS, uintptr(fd), 0, 0)
	if ret != 0 {
		return fmt.Errorf("can't set namespace. Errno %d: %w", errno, err)
	}
	return nil
}

// localIPs returns the non loopback local IPs of the host
func localIPs() []string {
	var ips []string
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	for _, address := range addrs {
		// check the address type and if it is not a loopback the display it
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			ips = append(ips, ipnet.IP.String())
		}
	}
	return ips
}
