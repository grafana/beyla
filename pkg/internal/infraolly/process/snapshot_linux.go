// Copyright 2020 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
package process

import (
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/newrelic/infrastructure-agent/pkg/helpers"
	"github.com/pkg/errors"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/process"
)

// linuxProcess is an implementation of the process.Snapshot interface for linux hosts. It is designed to be highly
// optimized and avoid unnecessary/duplicated system calls.
type linuxProcess struct {
	// if privileged == false, some operations will be avoided: FD and IO count.
	privileged bool

	stats    procStats
	process  *process.Process
	lastCPU  CPUInfo
	lastTime time.Time

	// data that will be reused between samples of the same process.
	pid     int32
	user    string
	cmdLine string
}

// needed to calculate RSS.
var pageSize int64

// needed to calculate CPU times.
var clockTicks int64

// for testing getting username from getent.
var getEntCommand = helpers.RunCommand //nolint:gochecknoglobals

var (
	errMalformedGetentEntry  = errors.New("malformed getent entry")
	errInvalidUidsForProcess = errors.New("invalid uids for process")
)

func init() {
	pageSize = int64(os.Getpagesize())
	if pageSize <= 0 {
		pageSize = 4096 // default value
	}

	clockTicks = int64(cpu.ClocksPerSec)
	if clockTicks <= 0 {
		clockTicks = 100 // default value
	}
}

var _ Snapshot = (*linuxProcess)(nil) // static interface assertion

// getLinuxProcess returns a linux process snapshot, trying to reuse the data from a previous snapshot of the same
// process.
func getLinuxProcess(pid int32, previous *linuxProcess, privileged bool) (*linuxProcess, error) {
	var gops *process.Process
	var err error

	procStats, err := readProcStat(pid)
	if err != nil {
		return nil, err
	}

	// Reusing information from the last snapshot for the same process
	// If the name or the PPID changed from the previous, we'll consider this sample is just
	// a new process that shares the PID with an old one.
	// if a process with the same CommandName but different CmdLine or User name
	// occupies the same PID, the cache won't refresh the CmdLine and Username.
	if previous == nil || procStats.command != previous.Command() || procStats.ppid != previous.Ppid() {
		gops, err = process.NewProcess(pid)
		if err != nil {
			return nil, err
		}
		return &linuxProcess{
			privileged: privileged,
			pid:        pid,
			process:    gops,
			stats:      procStats,
		}, nil
	}

	// Otherwise, instead of creating a new process snapshot, we just reuse the previous one, with updated data
	previous.stats = procStats

	return previous, nil
}

func (pw *linuxProcess) Pid() int32 {
	return pw.pid
}

func (pw *linuxProcess) Username() (string, error) {
	var err error
	if pw.user == "" { // caching user
		// try to get it from gopsutil and return it if ok
		pw.user, err = pw.process.Username()
		if err == nil {
			return pw.user, nil
		}

		// get the uid to be retrieved from getent
		uid, err := pw.uid()
		if err != nil {
			return "", err
		}

		// try to get it using getent
		pw.user, err = usernameFromGetent(uid)
		if err != nil {
			return "", err
		}
	}
	return pw.user, nil
}

func (pw *linuxProcess) uid() (int32, error) {
	uuids, err := pw.process.Uids()
	if err != nil {
		return 0, fmt.Errorf("error getting process uids: %w", err) //nolint:wrapcheck
	}

	if len(uuids) == 0 {
		return 0, errInvalidUidsForProcess //nolint:wrapcheck
	}

	return uuids[0], nil
}

// usernameFromGetent returns the username using getent https://man7.org/linux/man-pages/man1/getent.1.html
// getent passwd format example:
// deleteme:x:63367:63367:Dynamic User:/:/usr/sbin/nologin
func usernameFromGetent(uid int32) (string, error) {
	out, err := getEntCommand("/usr/bin/getent", "", []string{"passwd", fmt.Sprintf("%d", uid)}...)
	if err != nil {
		return "", err
	}

	if sepIdx := strings.Index(out, ":"); sepIdx > 0 {
		return out[0:sepIdx], nil
	}

	return "", errMalformedGetentEntry //nolint:wrapcheck
}

func (pw *linuxProcess) IOCounters() (*process.IOCountersStat, error) {
	if !pw.privileged {
		return nil, nil
	}
	return pw.process.IOCounters()
}

// NumFDs returns the number of file descriptors. It returns -1 (and nil error) if the Agent does not have privileges to
// access this information.
func (pw *linuxProcess) NumFDs() (int32, error) {
	if !pw.privileged {
		return -1, nil
	}
	pid := pw.process.Pid
	statPath := helpers.HostProc(strconv.Itoa(int(pid)), "fd")
	d, err := os.Open(statPath)
	if err != nil {
		return 0, err
	}
	defer d.Close()
	fnames, err := d.Readdirnames(-1)
	return int32(len(fnames)), nil
}

/////////////////////////////
// Data to be derived from /proc/<pid>/stat
/////////////////////////////

type procStats struct {
	command    string
	ppid       int32
	numThreads int32
	state      string
	vmRSS      int64
	vmSize     int64
	cpu        CPUInfo
}

// /proc/<pid>/stat standard field indices according to: http://man7.org/linux/man-pages/man5/proc.5.html
// because the first two fields are treated separately those indices are smaller with 2 elements than in the doc.
const (
	statState      = 0
	statPPID       = 1
	statUtime      = 11
	statStime      = 12
	statNumThreads = 17
	statVsize      = 20
	statRss        = 21
)

// readProcStat will gather information about the pid from /proc/<pid>/stat file.
func readProcStat(pid int32) (procStats, error) {
	statPath := helpers.HostProc(strconv.Itoa(int(pid)), "stat")

	content, err := ioutil.ReadFile(statPath)
	if err != nil {
		return procStats{}, err
	}

	return parseProcStat(string(content))
}

// parseProcStat is used to parse the content of the /proc/<pid>/stat file.
func parseProcStat(content string) (procStats, error) {
	stats := procStats{}

	i := strings.Index(content, "(")
	if i == -1 {
		return stats, fmt.Errorf("could not find command name start symbol '(' for stats: %s", content)
	}
	// Drop the first first field which is the pid.
	content = content[i+1:]

	i = strings.Index(content, ")")
	if i == -1 {
		return stats, fmt.Errorf("could not find command name end symbol ')' for stats: %s", content)
	}

	// Command Name found as the second field inside the brackets.
	stats.command = content[:i]

	fields := strings.Fields(content[i+1:])

	// Process State
	stats.state = fields[statState]

	// Parent PID
	ppid, err := strconv.ParseInt(fields[statPPID], 10, 32)
	if err != nil {
		return stats, errors.Wrapf(err, "for stats: %s", string(content))
	}
	stats.ppid = int32(ppid)

	// User time
	utime, err := strconv.ParseInt(fields[statUtime], 10, 64)
	if err != nil {
		return stats, errors.Wrapf(err, "for stats: %s", string(content))
	}
	stats.cpu.User = float64(utime) / float64(clockTicks)

	// System time
	stime, err := strconv.ParseInt(fields[statStime], 10, 64)
	if err != nil {
		return stats, errors.Wrapf(err, "for stats: %s", string(content))
	}
	stats.cpu.System = float64(stime) / float64(clockTicks)

	// Number of threads
	nthreads, err := strconv.ParseInt(fields[statNumThreads], 10, 32)
	if err != nil {
		return stats, errors.Wrapf(err, "for stats: %s", string(content))
	}
	stats.numThreads = int32(nthreads)

	// VM Memory size
	stats.vmSize, err = strconv.ParseInt(fields[statVsize], 10, 64)
	if err != nil {
		return stats, errors.Wrapf(err, "for stats: %s", string(content))
	}

	// VM RSS size
	stats.vmRSS, err = strconv.ParseInt(fields[statRss], 10, 64)
	if err != nil {
		return stats, errors.Wrapf(err, "for stats: %s", string(content))
	}
	stats.vmRSS *= pageSize

	return stats, nil
}

func (pw *linuxProcess) CPUTimes() (CPUInfo, error) {
	now := time.Now()

	if pw.lastTime.IsZero() {
		// invoked first time
		pw.lastCPU = pw.stats.cpu
		pw.lastTime = now
		return pw.stats.cpu, nil
	}

	// Calculate CPU percent from user time, system time, and last harvested cpu counters
	numcpu := runtime.NumCPU()
	delta := (now.Sub(pw.lastTime).Seconds()) * float64(numcpu)
	pw.stats.cpu.Percent = calculatePercent(pw.lastCPU, pw.stats.cpu, delta, numcpu)
	pw.lastCPU = pw.stats.cpu
	pw.lastTime = now

	return pw.stats.cpu, nil
}

func calculatePercent(t1, t2 CPUInfo, delta float64, numcpu int) float64 {
	if delta == 0 {
		return 0
	}
	deltaProc := t2.User + t2.System - t1.User - t1.System
	overallPercent := ((deltaProc / delta) * 100) * float64(numcpu)
	return overallPercent
}

func (pw *linuxProcess) Ppid() int32 {
	return pw.stats.ppid
}

func (pw *linuxProcess) NumThreads() int32 {
	return pw.stats.numThreads
}

func (pw *linuxProcess) Status() string {
	return pw.stats.state
}

func (pw *linuxProcess) VmRSS() int64 {
	return pw.stats.vmRSS
}

func (pw *linuxProcess) VmSize() int64 {
	return pw.stats.vmSize
}

func (pw *linuxProcess) Command() string {
	return pw.stats.command
}

//////////////////////////
// Data to be derived from /proc/<pid>/cmdline: command line, and command line without arguments
//////////////////////////

func (pw *linuxProcess) CmdLine(withArgs bool) (string, error) {
	if pw.cmdLine != "" {
		return pw.cmdLine, nil
	}

	cmdPath := helpers.HostProc(strconv.Itoa(int(pw.pid)), "cmdline")
	procCmdline, err := ioutil.ReadFile(cmdPath)
	if err != nil {
		procCmdline = nil // we can't be sure internal libraries return nil on error
	}

	if len(procCmdline) == 0 {
		return "", nil // zombie process
	}

	// Ignoring dash on session commands
	if procCmdline[0] == '-' {
		procCmdline = procCmdline[1:]
	}

	cmdLineBytes := make([]byte, 0, len(procCmdline))
	for i := 0; i < len(procCmdline); i++ {
		if procCmdline[i] == 0 {
			// ignoring the trailing zero that ends /proc/<pid>/cmdline, but adding the last character if the file
			// does not end in zero
			if withArgs && i < len(procCmdline)-1 {
				cmdLineBytes = append(cmdLineBytes, ' ')
			} else {
				break
			}
		} else {
			cmdLineBytes = append(cmdLineBytes, procCmdline[i])
		}
	}
	pw.cmdLine = helpers.SanitizeCommandLine(string(cmdLineBytes))
	return pw.cmdLine, nil
}
