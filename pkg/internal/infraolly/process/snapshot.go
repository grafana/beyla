// Copyright 2020 New Relic Corporation
// Copyright 2024 Grafana Labs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// This implementation was inspired by the code in https://github.com/newrelic/infrastructure-agent

package process

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/process"

	"github.com/grafana/beyla/v2/pkg/internal/helpers"
)

const unknown string = "-"

// CPUInfo represents CPU usage statistics at a given point
type CPUInfo struct {
	// User time of CPU, in seconds
	UserTime float64
	// System time of CPU, in seconds
	SystemTime float64
	// Wait time of CPU, in seconds
	WaitTime float64
}

// linuxProcess provides basic function to acquire process information from Linux hosts.
// It is designed to be highly optimized and avoid unnecessary/duplicated system calls.
type linuxProcess struct {
	// if privileged == false, some operations will be avoided: FD and IO count.
	privileged bool

	measureTime time.Time
	stats       procStats
	prevStats   procStats
	process     *process.Process

	// used to calculate CPU utilization ratios
	previousMeasureTime time.Time
	previousIOCounters  *process.IOCountersStat
	previousNetRx       int64
	previousNetTx       int64

	procFSRoot string

	// data that will be reused between harvests of the same process.
	pid                int32
	user               string
	commandInfoFetched bool
	commandArgs        []string
	commandLine        string
	execPath           string
	execName           string
}

// needed to calculate RSS.
var pageSize int64

// needed to calculate CPU times.
var clocksPerSec int64

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

	clocksPerSec = int64(cpu.ClocksPerSec)
	if clocksPerSec <= 0 {
		clocksPerSec = 100 // default value
	}
}

// getLinuxProcess returns a linux process snapshot, trying to reuse the data from a previous snapshot of the same
// process.
func getLinuxProcess(cachedCopy *linuxProcess, procFSRoot string, pid int32, privileged bool) (*linuxProcess, error) {
	var gops *process.Process
	var err error

	measureTime := time.Now()
	currentStats, err := readProcStat(procFSRoot, pid)
	if err != nil {
		return nil, err
	}

	// Reusing information from the last snapshot for the same process
	// If the name or the PPID changed from the cachedCopy, we'll consider this sample is just
	// a new process that shares the PID with an old one.
	// if a process with the same Command but different CommandLine or User name
	// occupies the same PID, the cache won't refresh the CommandLine and Username.
	if cachedCopy == nil ||
		currentStats.command != cachedCopy.stats.command ||
		currentStats.ppid != cachedCopy.stats.ppid {

		gops, err = process.NewProcess(pid)
		if err != nil {
			return nil, err
		}
		return &linuxProcess{
			privileged:          privileged,
			pid:                 pid,
			process:             gops,
			stats:               currentStats,
			measureTime:         measureTime,
			previousMeasureTime: measureTime,
			procFSRoot:          procFSRoot,
		}, nil
	}

	// Otherwise, instead of creating a new process snapshot, we just reuse the cachedCopy one, with updated data
	cachedCopy.previousMeasureTime = cachedCopy.measureTime
	cachedCopy.stats = currentStats
	cachedCopy.measureTime = measureTime

	return cachedCopy, nil
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
			if pw.user == "" {
				pw.user = unknown
			}
			return pw.user, nil
		}

		// get the uid to be retrieved from getent
		uid, err := pw.uid()
		if err != nil {
			pw.user = unknown
			return pw.user, err
		}

		// try to get it using getent
		pw.user, err = usernameFromGetent(uid)
		if err != nil {
			pw.user = unknown
			return pw.user, err
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
	statPath := path.Join(pw.procFSRoot, strconv.Itoa(int(pid)), "fd")
	d, err := os.Open(statPath)
	if err != nil {
		return 0, err
	}
	defer d.Close()
	fnames, err := d.Readdirnames(-1)
	return int32(len(fnames)), err
}

// procStats contains data to be parsed from /proc/<pid>/stat
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
	statCUtime     = 13
	statCStime     = 14
	statNumThreads = 17
	statVsize      = 20
	statRss        = 21
)

// readProcStat will gather information about the pid from /proc/<pid>/stat file.
func readProcStat(procFSRoot string, pid int32) (procStats, error) {
	statPath := path.Join(procFSRoot, strconv.Itoa(int(pid)), "stat")

	content, err := os.ReadFile(statPath)
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
		return stats, errors.Wrapf(err, "for stats: %s", content)
	}
	stats.ppid = int32(ppid)

	// User time
	utime, err := strconv.ParseInt(fields[statUtime], 10, 64)
	if err != nil {
		return stats, errors.Wrapf(err, "for stats: %s", content)
	}
	stats.cpu.UserTime = float64(utime) / float64(clocksPerSec)

	// System time
	stime, err := strconv.ParseInt(fields[statStime], 10, 64)
	if err != nil {
		return stats, errors.Wrapf(err, "for stats: %s", content)
	}
	stats.cpu.SystemTime = float64(stime) / float64(clocksPerSec)

	// wait time, both in kernel and user modes
	cutime, err := strconv.ParseInt(fields[statCUtime], 10, 64)
	if err != nil {
		return stats, errors.Wrapf(err, "for stats: %s", content)
	}
	cstime, err := strconv.ParseInt(fields[statCStime], 10, 64)
	if err != nil {
		return stats, errors.Wrapf(err, "for stats: %s", content)
	}
	stats.cpu.WaitTime = float64(cutime+cstime) / float64(clocksPerSec)

	// Number of threads
	nthreads, err := strconv.ParseInt(fields[statNumThreads], 10, 32)
	if err != nil {
		return stats, errors.Wrapf(err, "for stats: %s", content)
	}
	stats.numThreads = int32(nthreads)

	// VM Memory size
	stats.vmSize, err = strconv.ParseInt(fields[statVsize], 10, 64)
	if err != nil {
		return stats, errors.Wrapf(err, "for stats: %s", content)
	}

	// VM RSS size
	stats.vmRSS, err = strconv.ParseInt(fields[statRss], 10, 64)
	if err != nil {
		return stats, errors.Wrapf(err, "for stats: %s", content)
	}
	stats.vmRSS *= pageSize

	return stats, nil
}

var netLineRegexp = regexp.MustCompile(`\n\s*[^\n:]*:\s*(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(\d+).*`)

// /proc/<pid>/net/dev is assumed to have a structure like this
// Inter-|   Receive                                                |  Transmit
//
//	face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
//	   lo:   15074     172    0    0    0     0          0         0    15074     172    0    0    0     0       0          0
//	 eth0:  181770     628    0    0    0     0          0         0    54903     402    0    0    0     0       0          0
func parseProcNetDev(content []byte) (rx int64, tx int64) {
	entries := netLineRegexp.FindAllSubmatch(content, -1)
	for _, parsedData := range entries {
		if len(parsedData) < 3 {
			continue
		}
		r, _ := strconv.Atoi(string(parsedData[1]))
		rx += int64(r)
		t, _ := strconv.Atoi(string(parsedData[2]))
		tx += int64(t)
	}
	return rx, tx
}

// fetchCommandInfo derives command information from /proc/<pid>/cmdline file
func (pw *linuxProcess) fetchCommandInfo() {
	if pw.commandInfoFetched {
		return
	}
	pw.commandInfoFetched = true

	cmdPath := path.Join(pw.procFSRoot, strconv.Itoa(int(pw.pid)), "cmdline")
	procCmdline, err := os.ReadFile(cmdPath)
	if err != nil {
		procCmdline = nil // we can't be sure internal libraries return nil on error
	}

	if len(procCmdline) == 0 {
		return // zombie process
	}

	// Ignoring dash on session commands
	if procCmdline[0] == '-' {
		procCmdline = procCmdline[1:]
	}

	fullCommandLine := strings.Builder{}
	// get command
	procCmdline = sanitizeCommandLine(procCmdline)

	// get command args
	procCmdline, pw.execPath, _ = getNextArg(procCmdline)
	pw.execName = path.Base(pw.execPath)

	fullCommandLine.WriteString(pw.execPath)
	for {
		var arg string
		var ok bool
		procCmdline, arg, ok = getNextArg(procCmdline)
		if !ok {
			break
		}
		fullCommandLine.WriteByte(' ')
		fullCommandLine.WriteString(arg)
		pw.commandArgs = append(pw.commandArgs, arg)
	}
	pw.commandLine = fullCommandLine.String()
}

// getNextArg consumes the next found argument from a /proc/*/cmdline string
// (where arguments are separated by the zero byte)
func getNextArg(procCmdline []byte) ([]byte, string, bool) {
	if len(procCmdline) == 0 {
		return nil, "", false
	}
	var arg []byte
	for len(procCmdline) > 0 && procCmdline[0] != 0 {
		arg = append(arg, procCmdline[0])
		procCmdline = procCmdline[1:]
	}
	// ignore the zero when it's an argument separator
	if len(procCmdline) > 0 {
		procCmdline = procCmdline[1:]
	}
	return procCmdline, string(arg), true
}

// sanitizeCommandLine cleans the command line to remove wrappers like quotation marks.
func sanitizeCommandLine(cmd []byte) []byte {
	return bytes.Trim(cmd, " \t\n\v\f\r\"'`")
}
