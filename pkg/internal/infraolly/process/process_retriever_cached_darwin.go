// Copyright New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package process

import (
	"fmt"
	"github.com/newrelic/infrastructure-agent/pkg/helpers"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/process"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	ClockTicks = 100 // C.sysconf(C._SC_CLK_TCK)
)

type CommandRunner func(command string, stdin string, arguments ...string) (string, error)

var commandRunner CommandRunner = helpers.RunCommand

// ProcessRetrieverCached acts as a process.ProcessRetriever and retrieves a process.Process from its pid
// it uses an in-memory cache to store the information of all running processes with a short ttl enough to
// read information of all processes with just 2 calls to ps
// it uses c&p parts of code of gopsutil which was the 1st approach but makes too may system calls
type ProcessRetrieverCached struct {
	cache cache
}

func NewProcessRetrieverCached(ttl time.Duration) *ProcessRetrieverCached {
	return &ProcessRetrieverCached{cache: cache{ttl: ttl}}
}

// ProcessById returns a process.Process by pid or error if not found
func (s *ProcessRetrieverCached) ProcessById(pid int32) (Process, error) {
	procs, err := s.processesFromCache()
	if err != nil {
		return nil, err
	}
	if proc, ok := procs[pid]; ok {
		return &proc, nil
	}

	return nil, fmt.Errorf("cannot find process with pid %v", pid)
}

// processesFromCache returns all processes running. These will be retrieved and cached for cache.ttl time
func (s *ProcessRetrieverCached) processesFromCache() (map[int32]psItem, error) {
	s.cache.Lock()
	defer s.cache.Unlock()

	if s.cache.expired() {
		psBin, err := exec.LookPath("ps")
		if err != nil {
			return nil, err
		}
		// it's easier to get the thread num per process from different call
		processesThreads, err := s.getProcessThreads(psBin)
		if err != nil {
			return nil, err
		}
		// it's easier to get the thread num per process from different call
		fullCmd, err := s.getProcessFullCmd(psBin)
		if err != nil {
			return nil, err
		}
		//get all processes and inject numThreads
		items, err := s.retrieveProcesses(psBin)
		if err != nil {
			return nil, err
		}
		items = addThreadsAndCmdToPsItems(items, processesThreads, fullCmd)
		s.cache.update(items)
	}

	return s.cache.items, nil
}

func addThreadsAndCmdToPsItems(items map[int32]psItem, processesThreads map[int32]int32, processesCmd map[int32]string) map[int32]psItem {
	itemsWithAllInfo := make(map[int32]psItem)
	for pid, item := range items {
		if numThreads, ok := processesThreads[pid]; ok {
			item.numThreads = numThreads
		}
		if cmd, ok := processesCmd[pid]; ok {
			item.cmdLine = cmd
		}
		itemsWithAllInfo[pid] = item
	}
	return itemsWithAllInfo
}

func (s *ProcessRetrieverCached) retrieveProcesses(psBin string) (map[int32]psItem, error) {

	// get all processes info
	args := []string{"ax", "-c", "-o", "pid,ppid,user,state,utime,stime,etime,rss,vsize,pagein,command"}
	out, err := commandRunner(psBin, "", args...)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(out, "\n")
	items := make(map[int32]psItem)
	for _, line := range lines[1:] {
		var lineItems []string
		for _, lineItem := range strings.Split(line, " ") {
			if lineItem == "" {
				continue
			}
			lineItems = append(lineItems, strings.TrimSpace(lineItem))
		}
		if len(lineItems) > 10 {
			pid, _ := strconv.Atoi(lineItems[0])
			ppid, _ := strconv.Atoi(lineItems[1])
			user := lineItems[2]
			state := lineItems[3]
			utime := lineItems[4]
			stime := lineItems[5]
			etime := lineItems[6]
			rss, _ := strconv.ParseInt(lineItems[7], 10, 64)
			vsize, _ := strconv.ParseInt(lineItems[8], 10, 64)
			pagein, _ := strconv.ParseInt(lineItems[9], 10, 64)
			command := strings.Join(lineItems[10:], " ")

			item := psItem{
				pid:      int32(pid),
				ppid:     int32(ppid),
				username: user,
				state:    []string{convertStateToGopsutilState(state[0:1])},
				utime:    utime,
				stime:    stime,
				etime:    etime,
				rss:      rss,
				vsize:    vsize,
				pagein:   pagein,
				command:  command,
			}
			items[int32(pid)] = item
		} else {
			mplog.WithField("ps_output", out).Error("ps output is expected to have >10 columns")
		}
	}
	return items, nil
}

// convertStateToGopsutilState converts ps state to gopsutil v3 state
// C&P from https://github.com/shirou/gopsutil/blob/v3.21.11/v3/process/process.go#L575
func convertStateToGopsutilState(letter string) string {
	// Sources
	// Darwin: http://www.mywebuniversity.com/Man_Pages/Darwin/man_ps.html
	// FreeBSD: https://www.freebsd.org/cgi/man.cgi?ps
	// Linux https://man7.org/linux/man-pages/man1/ps.1.html
	// OpenBSD: https://man.openbsd.org/ps.1#state
	// Solaris: https://github.com/collectd/collectd/blob/1da3305c10c8ff9a63081284cf3d4bb0f6daffd8/src/processes.c#L2115
	switch letter {
	case "A":
		return process.Daemon
	case "D", "U":
		return process.Blocked
	case "E":
		return process.Detached
	case "I":
		return process.Idle
	case "L":
		return process.Lock
	case "O":
		return process.Orphan
	case "R":
		return process.Running
	case "S":
		return process.Sleep
	case "T", "t":
		// "t" is used by Linux to signal stopped by the debugger during tracing
		return process.Stop
	case "W":
		return process.Wait
	case "Y":
		return process.System
	case "Z":
		return process.Zombie
	default:
		return process.UnknownState
	}
}

func (s *ProcessRetrieverCached) getProcessThreads(psBin string) (map[int32]int32, error) {
	// get all processes info with threads
	args := []string{"ax", "-M", "-c"}
	out, err := commandRunner(psBin, "", args...)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(out, "\n")
	processThreads := make(map[int32]int32)
	for _, line := range lines[1:] {
		if len(line) > 0 && line[0] != ' ' {
			//we exclude main process for simplicity
			continue
		}
		for _, lineItem := range strings.Split(line, " ") {
			if lineItem == "" {
				continue
			}
			pidAsInt, err := strconv.Atoi(strings.TrimSpace(lineItem))
			if err != nil {
				mplog.Warnf("pid %v doesn't look like an int", pidAsInt)
				continue
			}
			pid := int32(pidAsInt)
			if _, ok := processThreads[pid]; !ok {
				processThreads[pid] = 1 //main process already included
			}
			processThreads[pid]++
			//we are only interested in pid so break and process next line
			break
		}
	}

	return processThreads, nil
}

// getProcessFullCmd retrieves the full process command line w/o arguments (as commands can have spaces in mac :( )
func (s *ProcessRetrieverCached) getProcessFullCmd(psBin string) (map[int32]string, error) {
	// get all processes info with threads
	args := []string{"ax", "-o", "pid,command"}
	out, err := commandRunner(psBin, "", args...)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(out, "\n")
	processThreads := make(map[int32]string)
	for _, line := range lines[1:] {
		var lineItems []string
		for _, lineItem := range strings.Split(line, " ") {
			if lineItem == "" {
				continue
			}
			lineItems = append(lineItems, strings.TrimSpace(lineItem))
		}
		if len(lineItems) > 1 {
			pidAsInt, _ := strconv.Atoi(lineItems[0])
			cmd := strings.Join(lineItems[1:], " ")
			pid := int32(pidAsInt)
			if _, ok := processThreads[pid]; !ok {
				processThreads[pid] = cmd
			}
		}
	}

	return processThreads, nil
}

// createTime retrieves ceate time from ps output etime field
// it is a c&p of gopsutil process.CreateTimeWithContext
func createTime(etime string) (int64, error) {
	elapsedSegments := strings.Split(strings.Replace(etime, "-", ":", 1), ":")
	var elapsedDurations []time.Duration
	for i := len(elapsedSegments) - 1; i >= 0; i-- {
		p, err := strconv.ParseInt(elapsedSegments[i], 10, 0)
		if err != nil {
			return 0, err
		}
		elapsedDurations = append(elapsedDurations, time.Duration(p))
	}

	var elapsed = elapsedDurations[0] * time.Second
	if len(elapsedDurations) > 1 {
		elapsed += elapsedDurations[1] * time.Minute
	}
	if len(elapsedDurations) > 2 {
		elapsed += elapsedDurations[2] * time.Hour
	}
	if len(elapsedDurations) > 3 {
		elapsed += elapsedDurations[3] * time.Hour * 24
	}

	start := time.Now().Add(-elapsed)
	return start.Unix() * 1000, nil
}

// times retrieves ceate time from ps output utime and stime fields
// it is a c&p of gopsutil process.TimesWithContext
func times(utime string, stime string) (*cpu.TimesStat, error) {
	uCpuTimes, err := convertCPUTimes(utime)
	if err != nil {
		return nil, err
	}
	sCpuTimes, err := convertCPUTimes(stime)
	if err != nil {
		return nil, err
	}

	ret := &cpu.TimesStat{
		CPU:    "cpu",
		User:   uCpuTimes,
		System: sCpuTimes,
	}
	return ret, nil
}

// convertCPUTimes converts ps format cputime to time units that are in USER_HZ or Jiffies
// it is a c&p of gopsutil process.convertCPUTimes
func convertCPUTimes(s string) (ret float64, err error) {
	var t int
	var _tmp string
	if strings.Contains(s, ":") {
		_t := strings.Split(s, ":")
		hour, err := strconv.Atoi(_t[0])
		if err != nil {
			return ret, err
		}
		t += hour * 60 * 100
		_tmp = _t[1]
	} else {
		_tmp = s
	}

	_t := strings.Split(_tmp, ".")
	if err != nil {
		return ret, err
	}
	h, _ := strconv.Atoi(_t[0])
	t += h * 100
	h, _ = strconv.Atoi(_t[1])
	t += h
	return float64(t) / ClockTicks, nil
}

// psItem stores the information of a process and implements process.Process
type psItem struct {
	pid        int32
	ppid       int32
	numThreads int32
	username   string
	state      []string
	command    string
	cmdLine    string
	utime      string
	stime      string
	etime      string
	rss        int64
	vsize      int64
	pagein     int64
}

func (p *psItem) Username() (string, error) {
	return p.username, nil
}

func (p *psItem) Name() (string, error) {
	return p.command, nil
}

func (p *psItem) Cmdline() (string, error) {
	return p.cmdLine, nil
}

func (p *psItem) ProcessId() int32 {
	return p.pid
}

func (p *psItem) Parent() (Process, error) {
	return &psItem{pid: p.ppid}, nil
}

func (p *psItem) NumThreads() (int32, error) {
	return p.numThreads, nil
}

func (p *psItem) Status() ([]string, error) {
	return p.state, nil
}

func (p *psItem) MemoryInfo() (*process.MemoryInfoStat, error) {
	return &process.MemoryInfoStat{
		RSS:  uint64(p.rss) * 1024,
		VMS:  uint64(p.vsize) * 1024,
		Swap: uint64(p.pagein),
	}, nil
}

// CPUPercent  returns how many percent of the CPU time this process uses
// it is a c&p of gopsutil process.CPUPercent
func (p *psItem) CPUPercent() (float64, error) {
	crt_time, err := createTime(p.etime)
	if err != nil {
		return 0, err
	}

	cput, err := p.Times()
	if err != nil {
		return 0, err
	}

	created := time.Unix(0, crt_time*int64(time.Millisecond))
	totalTime := time.Since(created).Seconds()
	if totalTime <= 0 {
		return 0, nil
	}

	return 100 * cput.Total() / totalTime, nil
}

func (p *psItem) Times() (*cpu.TimesStat, error) {
	return times(p.utime, p.stime)
}

// cache in-memory cache not to call ps for every process
type cache struct {
	ttl time.Duration
	sync.Mutex
	items     map[int32]psItem
	createdAt time.Time
}

func (c *cache) expired() bool {
	return c == nil || c.createdAt.IsZero() || time.Since(c.createdAt) > c.ttl
}

func (c *cache) update(items map[int32]psItem) {
	c.items = items
	c.createdAt = time.Now()
}
