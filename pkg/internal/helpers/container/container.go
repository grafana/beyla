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

func idlog() *slog.Logger {
	return slog.With("component", "container.InfoDatabase")
}

type InfoDatabase struct {
	byPID map[int]Info
}

func (id *InfoDatabase) Add(pid int) {
	ifp, err := infoForPID(pid)
	if err != nil {
		idlog().Warn("failing to store container information", "pid", pid, "error", err)
		return
	}
	id.byPID[pid] = ifp
}

func (id *InfoDatabase) Delete(pid int) {
	delete(id.byPID, pid)
}

func (id *InfoDatabase) Get(pid int) (Info, bool) {
	info, ok := id.byPID[pid]
	return info, ok
}

type Info struct {
	Hostname string
	IPs      []string
}

func infoForPID(pid int) (Info, error) {
	// This function uses the SetNS syscall, which changes the namespaces for the
	// current thread. We must prevent that other goroutines use the current
	// thread until we restore back the original namespace
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	beylaPID := os.Getpid()

	processHostName, err := getProcessHostName(pid, beylaPID)
	if err != nil {
		return Info{}, err
	}

	ips, err := getProcessIPs(pid, beylaPID)
	if err != nil {
		return Info{}, err
	}

	return Info{
		Hostname: processHostName,
		IPs:      ips,
	}, nil
}

func getProcessHostName(processPID, beylaPID int) (string, error) {
	if err := setNS(processPID, "uts"); err != nil {
		return "", fmt.Errorf("changing UTS namespace for PID %d: %w", processPID, err)
	}
	defer func() {
		// restoring Beyla UTS PID
		if err := setNS(beylaPID, "uts"); err != nil {
			idlog().Error("can't restore UTS namespace for Beyla. This can"+
				" result in wrong information about containers or pods",
				"error", err, "beylaPID", beylaPID)
		}
	}()
	processHostName, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("error getting container hostname for process %d: %w", processPID, err)
	}
	return processHostName, nil
}

func getProcessIPs(processPID, beylaPID int) ([]string, error) {
	if err := setNS(processPID, "net"); err != nil {
		return nil, fmt.Errorf("changing NET namespace for PID %d: %w", processPID, err)
	}
	ips := localIPs()

	// restoring Beyla NET PID
	if err := setNS(beylaPID, "net"); err != nil {
		idlog().Error("can't restore NET namespace for Beyla. This can"+
			" result in wrong information about containers or pods",
			"error", err, "beylaPID", beylaPID)
	}
	return ips, nil
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
