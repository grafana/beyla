// Copyright New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package process

import (
	"errors"
	"github.com/shirou/gopsutil/v3/cpu"
	process2 "github.com/shirou/gopsutil/v3/process"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"math"
	"testing"
	"time"
)

var psOut = []string{
	`PID  PPID USER             STAT     UTIME     STIME     ELAPSED    RSS      VSZ PAGEIN COMMAND
    1     0 root             Ss     3:56.38  18:41.21 07-21:03:49  12000  4481064      0 launchd
   68     1 joe              S      0:20.99   0:38.18 07-21:03:41    920  4471000      0 Google Chrome
   73     1 root             Ss     2:06.17   4:13.62 07-21:03:41   3108  4477816      0 fseventsd
   74    48 pam	             Ss     0:00.02   0:00.09 07-21:03:41     64  4322064      0 systemstats`,

	`PID  PPID USER             STAT     UTIME     STIME     ELAPSED    RSS      VSZ PAGEIN COMMAND
    1     0 root             Ss     3:58.38  18:51.21 07-21:04:49  12200  4482064      0 launchd
   68     1 joe              Ss     0:23.99   0:48.18 07-21:04:41    910  4473000      0 Google Chrome
   74    48 pam	             Ss     0:00.10   0:20.09 07-21:04:41     84  4324064      0 systemstats`,
}

var psCmdOut = []string{
	`PID COMMAND
    1    /sbin/launchd
   68    /Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/94.0.4606.61/Helpers/chrome_crashpad_handler --monitor-self-annotation=ptype=crashpad-handler --url=https://clients2.google.com/cr/report --annotation=channel= --annotation=plat=OS X --annotation=prod=Chrome_Mac --annotation=ver=94.0.4606.61 --handshake-fd=6
   73    /System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/FSEvents.framework/Versions/A/Support/fseventsd
   74    /usr/sbin/systemstats --daemon`,

	`PID  COMMAND
    1     /sbin/launchd
   68     /Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/94.0.4606.61/Helpers/chrome_crashpad_handler --monitor-self-annotation=ptype=crashpad-handler --url=https://clients2.google.com/cr/report --annotation=channel= --annotation=plat=OS X --annotation=prod=Chrome_Mac --annotation=ver=94.0.4606.61 --handshake-fd=6
   74     /usr/sbin/systemstats --daemon`,
}

var psThreadsOut = []string{
	`USER               PID   TT   %CPU STAT PRI     STIME     UTIME COMMAND
root                 1   ??    0.0 S    31T   0:00.36   0:00.08 launchd
                     1         0.0 S    20T   0:00.12   0:00.01
                     1         0.0 S    37T   0:00.00   0:00.00
                     1         0.0 S    37T   0:00.00   0:00.00
joe                 68   ??    0.0 S     4T   0:01.13   0:00.30 syslogd
                    68         0.0 S     4T   0:00.00   0:00.00
root                73   ??    0.0 S     4T   0:01.13   0:00.30 fseventsd
pam                 74         0.0 S     4T   0:00.00   0:00.00 systemstats`,

	`USER               PID   TT   %CPU STAT PRI     STIME     UTIME COMMAND
root                 1   ??    0.0 S    31T   0:00.36   0:00.08 launchd
                     1         0.0 S    20T   0:00.12   0:00.01
                     1         0.0 S    37T   0:00.00   0:00.00
                     1         0.0 S    37T   0:00.00   0:00.00
joe                 68   ??    0.0 S     4T   0:01.13   0:00.30 syslogd
                    68         0.0 S     4T   0:00.00   0:00.00
pam                 74         0.0 S     4T   0:00.00   0:00.00 systemstats`,
}

// commandRunnerMock mocks CommandRunner and so we can mock ps results
type commandRunnerMock struct {
	mock.Mock
}

func (c *commandRunnerMock) run(command string, stdin string, arguments ...string) (string, error) {
	args := c.Called(command, stdin, arguments)

	return args.String(0), args.Error(1)
}

func (c *commandRunnerMock) ShouldRunCommand(command string, stdin string, arguments []string, output string, err error) {
	c.
		On("run", command, stdin, arguments).
		Once().
		Return(output, err)
}

func (c *commandRunnerMock) ShouldRunCommandMultipleTimes(command string, stdin string, arguments []string, output string, err error) {
	c.
		On("run", command, stdin, arguments).
		Return(output, err)
}

func Test_ProcessRetrieverCached_InvalidPsOutputShouldNotBreakTheInternet(t *testing.T) {

	tests := []struct {
		name         string
		psOut        string
		psThreadsOut string
		psCmdOut     string
	}{
		{
			name:         "empty content in ps",
			psOut:        "",
			psThreadsOut: psThreadsOut[0],
			psCmdOut:     psCmdOut[0],
		},
		{
			name:         "empty content in ps threads",
			psOut:        psOut[0],
			psThreadsOut: "",
			psCmdOut:     psCmdOut[0],
		},
		{
			name:         "empty content in ps cmd",
			psOut:        psOut[0],
			psThreadsOut: psThreadsOut[0],
			psCmdOut:     "",
		},
		{
			name:  "some invalid data",
			psOut: "some invalid data\nin\nmultiple lines",
		},
		{
			name: "some missing columns",
			psOut: `PID  PPID USER      STAT       RSS      VSZ PAGEIN COMMAND
    1     0 root             Ss       12000  4481064      0 /sbin/launchd
   68     1 joe              S          920  4471000      0 /usr/sbin/syslogd
   73     1 root             Ss        3108  4477816      0 /System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/FSEvents.framework/Versions/A/Support/fseventsd
   74    48 pam	             Ss          64  4322064      0 /usr/sbin/systemstats --daemon`,
		},
	}

	ttl := time.Second * 0
	ret := NewProcessRetrieverCached(ttl)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmdRunMock := &commandRunnerMock{}
			commandRunner = cmdRunMock.run
			cmdRunMock.ShouldRunCommand("/bin/ps", "", []string{"ax", "-M", "-c"}, tt.psThreadsOut, nil)
			cmdRunMock.ShouldRunCommand("/bin/ps", "", []string{"ax", "-o", "pid,command"}, tt.psCmdOut, nil)
			cmdRunMock.ShouldRunCommand("/bin/ps", "", []string{"ax", "-c", "-o", "pid,ppid,user,state,utime,stime,etime,rss,vsize,pagein,command"}, tt.psOut, nil)
			_, err := ret.ProcessById(999)
			assert.EqualError(t, err, "cannot find process with pid 999")
			//mocked objects assertions
			mock.AssertExpectationsForObjects(t, cmdRunMock)
		})
	}
}

func Test_ProcessRetrieverCached_ProcessById_PsErrorOnThreads(t *testing.T) {
	expectedError := errors.New("this is an error")
	cmdRunMock := &commandRunnerMock{}
	commandRunner = cmdRunMock.run
	cmdRunMock.ShouldRunCommand("/bin/ps", "", []string{"ax", "-M", "-c"}, psThreadsOut[0], expectedError)

	ttl := time.Second * 0
	ret := NewProcessRetrieverCached(ttl)
	_, err := ret.ProcessById(68)
	assert.Equal(t, expectedError, err)

	//mocked objects assertions
	mock.AssertExpectationsForObjects(t, cmdRunMock)
}

func Test_ProcessRetrieverCached_ProcessById_PsErrorOnPsInfo(t *testing.T) {
	expectedError := errors.New("this is an error")
	cmdRunMock := &commandRunnerMock{}
	commandRunner = cmdRunMock.run
	cmdRunMock.ShouldRunCommand("/bin/ps", "", []string{"ax", "-M", "-c"}, psThreadsOut[0], nil)
	cmdRunMock.ShouldRunCommand("/bin/ps", "", []string{"ax", "-o", "pid,command"}, psCmdOut[0], nil)
	cmdRunMock.ShouldRunCommand("/bin/ps", "", []string{"ax", "-c", "-o", "pid,ppid,user,state,utime,stime,etime,rss,vsize,pagein,command"}, psOut[0], expectedError)

	ttl := time.Second * 0
	ret := NewProcessRetrieverCached(ttl)
	_, err := ret.ProcessById(68)
	assert.Equal(t, expectedError, err)

	//mocked objects assertions
	mock.AssertExpectationsForObjects(t, cmdRunMock)
}

func Test_ProcessRetrieverCached_ProcessById_NonExistingProcess(t *testing.T) {
	cmdRunMock := &commandRunnerMock{}
	commandRunner = cmdRunMock.run
	cmdRunMock.ShouldRunCommand("/bin/ps", "", []string{"ax", "-M", "-c"}, psThreadsOut[0], nil)
	cmdRunMock.ShouldRunCommand("/bin/ps", "", []string{"ax", "-o", "pid,command"}, psCmdOut[0], nil)
	cmdRunMock.ShouldRunCommand("/bin/ps", "", []string{"ax", "-c", "-o", "pid,ppid,user,state,utime,stime,etime,rss,vsize,pagein,command"}, psOut[0], nil)

	ttl := time.Second * 0
	ret := NewProcessRetrieverCached(ttl)
	_, err := ret.ProcessById(99999999)
	assert.EqualError(t, err, "cannot find process with pid 99999999")

	//mocked objects assertions
	mock.AssertExpectationsForObjects(t, cmdRunMock)
}

func Test_ProcessRetrieverCached_ProcessById_ExistingProcess(t *testing.T) {
	cmdRunMock := &commandRunnerMock{}
	commandRunner = cmdRunMock.run
	cmdRunMock.ShouldRunCommand("/bin/ps", "", []string{"ax", "-M", "-c"}, psThreadsOut[0], nil)
	cmdRunMock.ShouldRunCommand("/bin/ps", "", []string{"ax", "-o", "pid,command"}, psCmdOut[0], nil)
	cmdRunMock.ShouldRunCommand("/bin/ps", "", []string{"ax", "-c", "-o", "pid,ppid,user,state,utime,stime,etime,rss,vsize,pagein,command"}, psOut[0], nil)

	ttl := time.Second * 10
	ret := NewProcessRetrieverCached(ttl)
	process, err := ret.ProcessById(68)
	assert.Nil(t, err)
	assert.Equal(t, int32(68), process.ProcessId())
	assert.Equal(t, "Google Chrome", noError(process.Name()))
	assert.Equal(t, "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/94.0.4606.61/Helpers/chrome_crashpad_handler --monitor-self-annotation=ptype=crashpad-handler --url=https://clients2.google.com/cr/report --annotation=channel= --annotation=plat=OS X --annotation=prod=Chrome_Mac --annotation=ver=94.0.4606.61 --handshake-fd=6",
		noError(process.Cmdline()))
	assert.Equal(t, "joe", noError(process.Username()))
	assert.Equal(t, int32(1), noError(process.Parent()).(Process).ProcessId())
	assert.Equal(t, []string{process2.Sleep}, noError(process.Status()))
	assert.Equal(t, &cpu.TimesStat{CPU: "cpu", User: 20.99, System: 38.18}, noError(process.Times()))
	assert.Equal(t, &process2.MemoryInfoStat{RSS: uint64(920) * 1024, VMS: uint64(4471000) * 1024, Swap: uint64(0)}, noError(process.MemoryInfo()))
	assert.Equal(t, int32(2), noError(process.NumThreads()))
	assert.Equal(t, 0.00869, math.Round(noError(process.CPUPercent()).(float64)*100000)/100000)

	//mocked objects assertions
	mock.AssertExpectationsForObjects(t, cmdRunMock)
}

func Test_ProcessRetrieverCached_processesFromCache_reuseCacheIfTtlNotExpired(t *testing.T) {

	cmdRunMock := &commandRunnerMock{}
	commandRunner = cmdRunMock.run
	cmdRunMock.ShouldRunCommand("/bin/ps", "", []string{"ax", "-M", "-c"}, psThreadsOut[0], nil)
	cmdRunMock.ShouldRunCommand("/bin/ps", "", []string{"ax", "-o", "pid,command"}, psCmdOut[0], nil)
	cmdRunMock.ShouldRunCommand("/bin/ps", "", []string{"ax", "-c", "-o", "pid,ppid,user,state,utime,stime,etime,rss,vsize,pagein,command"}, psOut[0], nil)

	ttl := time.Second * 10
	ret := NewProcessRetrieverCached(ttl)
	itemsFirstCall, err := ret.processesFromCache()
	assert.Nil(t, err)
	itemsSecondCall, err := ret.processesFromCache()
	assert.Nil(t, err)
	assert.Equal(t, itemsFirstCall, itemsSecondCall)

	//mocked objects assertions
	mock.AssertExpectationsForObjects(t, cmdRunMock)
}

func Test_ProcessRetrieverCached_processesFromCache_cleanCacheIfTtlExpired(t *testing.T) {

	cmdRunMock := &commandRunnerMock{}
	commandRunner = cmdRunMock.run
	cmdRunMock.ShouldRunCommand("/bin/ps", "", []string{"ax", "-M", "-c"}, psThreadsOut[0], nil)
	cmdRunMock.ShouldRunCommand("/bin/ps", "", []string{"ax", "-o", "pid,command"}, psCmdOut[0], nil)
	cmdRunMock.ShouldRunCommand("/bin/ps", "", []string{"ax", "-c", "-o", "pid,ppid,user,state,utime,stime,etime,rss,vsize,pagein,command"}, psOut[0], nil)
	cmdRunMock.ShouldRunCommand("/bin/ps", "", []string{"ax", "-M", "-c"}, psThreadsOut[1], nil)
	cmdRunMock.ShouldRunCommand("/bin/ps", "", []string{"ax", "-o", "pid,command"}, psCmdOut[1], nil)
	cmdRunMock.ShouldRunCommand("/bin/ps", "", []string{"ax", "-c", "-o", "pid,ppid,user,state,utime,stime,etime,rss,vsize,pagein,command"}, psOut[1], nil)

	ttl := time.Second * 0
	ret := NewProcessRetrieverCached(ttl)
	itemsFirstCall, err := ret.processesFromCache()
	assert.Nil(t, err)
	itemsSecondCall, err := ret.processesFromCache()
	assert.Nil(t, err)
	assert.Len(t, itemsFirstCall, 4)
	assert.Len(t, itemsSecondCall, 3)
	assert.Equal(t, itemsSecondCall[74].stime, "0:20.09")

	//mocked objects assertions
	mock.AssertExpectationsForObjects(t, cmdRunMock)
}

func Test_addThreadsAndCmdToPsItems(t *testing.T) {

	tests := []struct {
		name             string
		items            map[int32]psItem
		processesThreads map[int32]int32
		processesCmd     map[int32]string
		expectedItems    map[int32]psItem
	}{
		{
			name:             "empty items",
			items:            map[int32]psItem{},
			processesThreads: map[int32]int32{},
			processesCmd:     map[int32]string{},
			expectedItems:    map[int32]psItem{},
		},
		{
			name:             "empty items but info in threads and cmd",
			items:            map[int32]psItem{},
			processesThreads: map[int32]int32{1: 12, 343: 23},
			processesCmd:     map[int32]string{1: "/some/command"},
			expectedItems:    map[int32]psItem{},
		},
		{
			name:             "non items should not change original",
			items:            map[int32]psItem{1: {pid: 1, command: "some_command"}, 2: {pid: 2, command: "another_command"}},
			processesThreads: map[int32]int32{1: 12, 2: 4, 5: 343},
			processesCmd:     map[int32]string{1: "/bin/some_command", 5: "already_dead_command", 2: "/bin/another_command"},
			expectedItems: map[int32]psItem{
				1: {
					pid:        1,
					command:    "some_command",
					numThreads: 12,
					cmdLine:    "/bin/some_command",
				}, 2: {
					pid:        2,
					command:    "another_command",
					numThreads: 4,
					cmdLine:    "/bin/another_command",
				}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origItems := copyItems(tt.items)
			fullInfoItems := addThreadsAndCmdToPsItems(tt.items, tt.processesThreads, tt.processesCmd)
			assert.Equal(t, tt.expectedItems, fullInfoItems)
			assert.Equal(t, tt.items, origItems)
		})
	}
}

func copyItems(origItems map[int32]psItem) map[int32]psItem {
	dest := make(map[int32]psItem)
	for pid, item := range origItems {
		dest[pid] = item
	}
	return dest
}

func Test_ProcessRetrieverCached_retrieveProcesses(t *testing.T) {
	expected := map[int32]psItem{

		1: {
			pid:        1,
			ppid:       0,
			username:   "root",
			state:      []string{process2.Sleep},
			utime:      "3:56.38",
			stime:      "18:41.21",
			etime:      "07-21:03:49",
			rss:        12000,
			vsize:      4481064,
			pagein:     0,
			numThreads: 0,
			command:    "launchd",
			cmdLine:    "",
		},
		68: {
			pid:        68,
			ppid:       1,
			username:   "joe",
			state:      []string{process2.Sleep},
			utime:      "0:20.99",
			stime:      "0:38.18",
			etime:      "07-21:03:41",
			rss:        920,
			vsize:      4471000,
			pagein:     0,
			numThreads: 0,
			command:    "Google Chrome",
			cmdLine:    "",
		},
		73: {
			pid:        73,
			ppid:       1,
			username:   "root",
			state:      []string{process2.Sleep},
			utime:      "2:06.17",
			stime:      "4:13.62",
			etime:      "07-21:03:41",
			rss:        3108,
			vsize:      4477816,
			pagein:     0,
			numThreads: 0,
			command:    "fseventsd",
			cmdLine:    "",
		},
		74: {
			pid:        74,
			ppid:       48,
			username:   "pam",
			state:      []string{process2.Sleep},
			utime:      "0:00.02",
			stime:      "0:00.09",
			etime:      "07-21:03:41",
			rss:        64,
			vsize:      4322064,
			pagein:     0,
			numThreads: 0,
			command:    "systemstats",
			cmdLine:    "",
		},
	}

	cmdRunMock := &commandRunnerMock{}
	commandRunner = cmdRunMock.run
	cmdRunMock.ShouldRunCommand("/bin/ps", "", []string{"ax", "-c", "-o", "pid,ppid,user,state,utime,stime,etime,rss,vsize,pagein,command"}, psOut[0], nil)

	ttl := time.Second * 10
	ret := NewProcessRetrieverCached(ttl)
	psItems, err := ret.retrieveProcesses("/bin/ps")

	assert.Nil(t, err)
	assert.Len(t, psItems, 4)
	for pid, expectedPsItem := range expected {
		assert.Equal(t, psItems[pid], expectedPsItem)
	}
	//mocked objects assertions
	mock.AssertExpectationsForObjects(t, cmdRunMock)
}

func benchmark_ProcessRetrieverCached_getProcessThreads(psThreadsOut string, b *testing.B) {
	cmdRunMock := &commandRunnerMock{}
	commandRunner = cmdRunMock.run
	cmdRunMock.ShouldRunCommandMultipleTimes("/bin/ps", "", []string{"ax", "-M", "-c"}, psThreadsOut, nil)

	ttl := time.Second * 10
	ret := NewProcessRetrieverCached(ttl)

	// run the Fib function b.N times
	for n := 0; n < b.N; n++ {
		ret.getProcessThreads("/bin/ps")
	}
}

func Benchmark_ProcessRetrieverCached_getProcessThreads10(b *testing.B) {
	benchmark_ProcessRetrieverCached_getProcessThreads(psOutThreads10, b)
}
func Benchmark_ProcessRetrieverCached_getProcessThreads100(b *testing.B) {
	benchmark_ProcessRetrieverCached_getProcessThreads(psOutThreads100, b)
}
func Benchmark_ProcessRetrieverCached_getProcessThreads1000(b *testing.B) {
	benchmark_ProcessRetrieverCached_getProcessThreads(psOutThreads500, b)
}

func benchmark_ProcessRetrieverCached_retrieveProcesses(psOut string, b *testing.B) {
	cmdRunMock := &commandRunnerMock{}
	commandRunner = cmdRunMock.run
	cmdRunMock.ShouldRunCommandMultipleTimes("/bin/ps", "", []string{"ax", "-c", "-o", "pid,ppid,user,state,utime,stime,etime,rss,vsize,pagein,command"}, psOut, nil)

	ttl := time.Second * 0
	ret := NewProcessRetrieverCached(ttl)

	// run the Fib function b.N times
	for n := 0; n < b.N; n++ {
		ret.retrieveProcesses("/bin/ps")
	}
}

func Benchmark_ProcessRetrieverCached_retrieveProcesses10(b *testing.B) {
	benchmark_ProcessRetrieverCached_retrieveProcesses(psOut10, b)
}
func Benchmark_ProcessRetrieverCached_retrieveProcesses100(b *testing.B) {
	benchmark_ProcessRetrieverCached_retrieveProcesses(psOut100, b)
}
func Benchmark_ProcessRetrieverCached_retrieveProcesses1000(b *testing.B) {
	benchmark_ProcessRetrieverCached_retrieveProcesses(psOut500, b)
}

func noError(i interface{}, _ error) interface{} {
	return i
}

var psOut10 = `PID  PPID USER             STAT     UTIME     STIME     ELAPSED    RSS      VSZ PAGEIN COMMAND
    1     0 root             Ss     4:11.67  20:07.54 08-14:58:33  14376  4480016      0 /sbin/launchd
   68     1 root             Ss     0:22.59   0:41.16 08-14:58:25    852  4471000      0 /usr/bin/some_command with some parameters
   69     1 root             Ss     0:21.18   0:38.61 08-14:58:25   4416  4503784      0 /usr/bin/some_command with some parameters
   72     1 root             Ss     0:01.86   0:04.56 08-14:58:25    464  4403040      0 /usr/bin/some_command with some parameters
   73     1 root             Ss     2:15.80   4:35.94 08-14:58:25   2976  4477292      0 /usr/bin/some_command with some parameters
   74     1 root             Ss     0:00.02   0:00.10 08-14:58:25     64  4322064      0 /usr/bin/some_command with some parameters
   75     1 root             Ss     0:13.98   0:11.16 08-14:58:25   3572  4504692      0 /usr/bin/some_command with some parameters
   81     1 root             Ss     0:00.02   0:00.10 08-14:58:25     72  4312320      0 /usr/bin/some_command with some parameters
   82     1 root             Ss     2:38.05   1:57.49 08-14:58:25   4396  4515104      0 /usr/bin/some_command with some parameters
   84     1 root             Ss     0:22.27   0:41.25 08-14:58:25   3224  4506768      0 /usr/bin/some_command with some parameters`

var psOut100 = `PID  PPID USER             STAT     UTIME     STIME     ELAPSED    RSS      VSZ PAGEIN COMMAND
    1     0 root             Ss     4:11.67  20:07.54 08-14:58:33  14376  4480016      0 /sbin/launchd
   68     1 root             Ss     0:22.59   0:41.16 08-14:58:25    852  4471000      0 /usr/bin/some_command with some parameters
   69     1 root             Ss     0:21.18   0:38.61 08-14:58:25   4416  4503784      0 /usr/bin/some_command with some parameters
   72     1 root             Ss     0:01.86   0:04.56 08-14:58:25    464  4403040      0 /usr/bin/some_command with some parameters
   73     1 root             Ss     2:15.80   4:35.94 08-14:58:25   2976  4477292      0 /usr/bin/some_command with some parameters
   74     1 root             Ss     0:00.02   0:00.10 08-14:58:25     64  4322064      0 /usr/bin/some_command with some parameters
   75     1 root             Ss     0:13.98   0:11.16 08-14:58:25   3572  4504692      0 /usr/bin/some_command with some parameters
   81     1 root             Ss     0:00.02   0:00.10 08-14:58:25     72  4312320      0 /usr/bin/some_command with some parameters
   82     1 root             Ss     2:38.05   1:57.49 08-14:58:25   4396  4515104      0 /usr/bin/some_command with some parameters
   84     1 root             Ss     0:22.27   0:41.25 08-14:58:25   3224  4506768      0 /usr/bin/some_command with some parameters
   86     1 root             Ss     0:39.19   1:53.93 08-14:58:25   4808  4503136      0 /usr/bin/some_command with some parameters
   88     1 root             Ss    21:00.91  24:52.86 08-14:58:25  17640  4579384      0 /usr/bin/some_command with some parameters
   91     1 root             Ss     0:10.63   0:15.49 08-14:58:25   1632  4515168      0 /usr/bin/some_command with some parameters
   93     1 root             Ss     2:11.10   2:51.66 08-14:58:25  10816  4586644      0 /usr/bin/some_command with some parameters
   99     1 root             Ss     0:03.12   0:04.29 08-14:58:25   1584  4469432      0 /usr/bin/some_command with some parameters
  103     1 root             Ss    10:21.66  15:23.52 08-14:58:25  12592  4814408      0 /usr/bin/some_command with some parameters
  104     1 root             RNs  224:31.63  95:24.02 08-14:58:25 148944 10665428      0 /usr/bin/some_command with some parameters
  106     1 root             Ss     0:08.78   0:09.93 08-14:58:25   2148  4522824      0 /usr/bin/some_command with some parameters
  107     1 root             Ss     0:41.81   0:24.94 08-14:58:25   2188  4500416      0 /usr/bin/some_command with some parameters
  114     1 root             Ss     0:00.00   0:00.03 08-14:58:25      8  4409456      0 /usr/bin/some_command with some parameters
  115     1 root             Ss     2:07.05   0:56.41 08-14:58:25   7844  4509284      0 /usr/bin/some_command with some parameters
  116     1 root             Ss    11:16.42  11:07.60 08-14:58:25   8596  4532768      0 /usr/bin/some_command with some parameters
  117     1 root             Ss     0:11.28   0:11.58 08-14:58:25   5508  4517024      0 /usr/bin/some_command with some parameters
  118     1 root             Ss     0:00.11   0:00.24 08-14:58:25    232  5017516      0 /usr/bin/some_command with some parameters
  119     1 root             Ss     4:09.83   4:01.65 08-14:58:25   6028  4502240      0 /usr/bin/some_command with some parameters
  120     1 _timed           Ss     0:01.47   0:07.47 08-14:58:25   1244  4500700      0 /usr/bin/some_command with some parameters
  123     1 root             Ss     0:15.88   0:05.03 08-14:58:25   4320  4504936      0 /usr/bin/some_command with some parameters
  124     1 root             Ss     0:00.00   0:00.05 08-14:58:25     36  4403280      0 /usr/bin/some_command with some parameters
  126     1 _locationd       Ss     1:05.54   1:07.10 08-14:58:25   5500  4522344      0 /usr/bin/some_command with some parameters
  128     1 root             Ss     0:00.00   0:00.05 08-14:58:25     56  4436712      0 /usr/bin/some_command with some parameters
  129     1 _displaypolicyd  Ss     0:00.20   0:02.01 08-14:58:25    380  4472456      0 /usr/bin/some_command with some parameters
  132     1 root             Ss     1:03.47   0:34.12 08-14:58:25   7100  4506616      0 /usr/bin/some_command with some parameters
  135     1 _distnote        Ss     0:05.55   0:03.92 08-14:58:25    892  4367444      0 /usr/bin/some_command with some parameters
  139     1 root             SNs    0:56.36   1:31.65 08-14:58:25   3392  4403952      0 /usr/bin/some_command with some parameters
  140     1 root             Ss     0:00.09   0:00.46 08-14:58:25   1128  4468904      0 /usr/bin/some_command with some parameters
  141     1 root             Ss     0:00.18   0:01.91 08-14:58:25   1268  4502020      0 /usr/bin/some_command with some parameters
  142     1 root             Ss     0:00.00   0:00.03 08-14:58:25     80  4411744      0 /usr/bin/some_command with some parameters
  144     1 root             Ss     0:23.44   0:34.43 08-14:58:25   4004  4504992      0 /usr/bin/some_command with some parameters
  145     1 root             Ss     0:33.93   1:17.70 08-14:58:25   1984  4469284      0 /usr/bin/some_command with some parameters
  147     1 root             Ss     0:41.57   0:49.94 08-14:58:25   3380  4501864      0 /usr/bin/some_command with some parameters
  148     1 root             Ss     0:01.39   0:03.99 08-14:58:25   1356  4502052      0 /usr/bin/some_command with some parameters
  151     1 root             Ss     4:33.07   1:27.82 08-14:58:25   8772  4544432      0 /usr/bin/some_command with some parameters
  152     1 root             Ss     0:49.94   1:25.03 08-14:58:25   2808  4469628      0 /usr/bin/some_command with some parameters
  153     1 root             Ss     0:02.71   0:05.10 08-14:58:25   1540  4517692      0 /usr/bin/some_command with some parameters
  156     1 _analyticsd      Ss     0:08.73   0:11.37 08-14:58:25   4536  4511792      0 /usr/bin/some_command with some parameters
  191     1 root             Ss     1:12.18   0:45.09 08-14:58:25   7972  4508044      0 /usr/bin/some_command with some parameters
  195     1 root             Ss     0:16.43   0:14.18 08-14:58:24   4872  4503448      0 /usr/bin/some_command with some parameters
  199     1 root             S      0:00.32   0:00.52 08-14:58:24     92  4367444      0 /usr/bin/some_command with some parameters
  206     1 root             Ss     0:19.05   0:15.72 08-14:58:24   6592  4511260      0 /usr/bin/some_command with some parameters
  208     1 _trustd          Ss     3:19.93   0:39.78 08-14:58:24   6948  4518924      0 /usr/bin/some_command with some parameters
  215     1 _networkd        Ss     0:56.22   2:25.35 08-14:58:24   5692  4512388      0 /usr/bin/some_command with some parameters
  232     1 _mdnsresponder   Ss     0:50.06   1:34.61 08-14:58:22   5168  4515992      0 /usr/bin/some_command with some parameters
  248     1 root             Ss     0:03.37   0:05.61 08-14:58:22    288  4501552      0 /usr/bin/some_command with some parameters
  250     1 root             Ss     0:00.18   0:01.24 08-14:58:22    896  4506016      0 /usr/bin/some_command with some parameters
  252     1 root             Ss     0:00.00   0:00.01 08-14:58:22     12  4400400      0 /usr/bin/some_command with some parameters
  254     1 root             Ss     0:00.14   0:00.62 08-14:58:22    548  4468908      0 /usr/bin/some_command with some parameters
  255     1 root             Ss     3:23.68   2:37.34 08-14:58:22   9636  4514220      0 /usr/bin/some_command with some parameters
  256     1 _coreaudiod      Ss    19:18.84  12:29.64 08-14:58:22   6700  4531492      0 /usr/bin/some_command with some parameters
  257     1 _nsurlsessiond   Ss     0:06.68   0:19.85 08-14:58:22   4332  4521772      0 /usr/bin/some_command with some parameters
  263     1 root             Ss     0:02.09   0:07.21 08-14:58:22   1436  4503404      0 /usr/bin/some_command with some parameters
  264     1 _cmiodalassistants Ss     5:01.51   2:35.11 08-14:58:22   8700  4556188      0 /usr/bin/some_command with some parameters
  269     1 root             Ss     1:39.02   1:56.92 08-14:58:22   2132  4502064      0 /usr/bin/some_command with some parameters
  271     1 _coreaudiod      S      0:00.24   0:00.52 08-14:58:22     92  4367408      0 /usr/bin/some_command with some parameters
  272     1 root             Ss     0:00.14   0:01.46 08-14:58:22    456  4501676      0 /usr/bin/some_command with some parameters
  279     1 _locationd       S      0:00.29   0:00.57 08-14:58:22     96  4367444      0 /usr/bin/some_command with some parameters
  300     1 root             Ss     0:01.46   0:05.79 08-14:58:21   2236  4514480      0 /usr/bin/some_command with some parameters
  307     1 _softwareupdate  S      0:00.24   0:00.55 08-14:58:21     92  4367408      0 /usr/bin/some_command with some parameters
  313     1 root             Ss     0:00.64   0:01.36 08-14:58:21    128  4524496      0 /usr/bin/some_command with some parameters
  322     1 root             Ss     0:01.54   0:04.68 08-14:58:21   5552  4516592      0 /usr/bin/some_command with some parameters
  337     1 root             Ss     0:00.24   0:01.86 08-14:58:19    428  4501512      0 /usr/bin/some_command with some parameters
  397     1 root             Ss   102:37.16  33:46.59 08-14:58:17 135092  4975516      0 /usr/bin/some_command with some parameters
  398     1 _nsurlsessiond   S      0:00.23   0:00.54 08-14:58:16     92  4367408      0 /usr/bin/some_command with some parameters
  419     1 root             Ss    37:27.33   9:27.48 08-14:58:10  61484  8032180      0 /usr/bin/some_command with some parameters
  422     1 _driverkit       Ss     0:01.03   0:02.65 08-14:58:10    708  4810472      0 /usr/bin/some_command with some parameters
  423     1 _driverkit       Ss     0:00.33   0:01.21 08-14:58:10    676  4810472      0 /usr/bin/some_command with some parameters
  425     1 _driverkit       Ss     0:00.00   0:00.03 08-14:58:10      8  4801256      0 /usr/bin/some_command with some parameters
  427     1 _driverkit       Ss     0:21.25   0:48.49 08-14:58:10    996  4810488      0 /usr/bin/some_command with some parameters
  428     1 _driverkit       Ss     0:00.00   0:00.02 08-14:58:10      8  4801256      0 /usr/bin/some_command with some parameters
  430     1 _driverkit       Ss     0:00.02   0:00.08 08-14:58:10      8  4808424      0 /usr/bin/some_command with some parameters
  432     1 _driverkit       Ss     0:00.31   0:00.95 08-14:58:10    676  4810472      0 /usr/bin/some_command with some parameters
  434     1 _driverkit       Ss     0:00.02   0:00.04 08-14:58:10     20  4816640      0 /usr/bin/some_command with some parameters
  435     1 _driverkit       Ss     0:00.00   0:00.00 08-14:58:10      8  4800252      0 /usr/bin/some_command with some parameters
  437     1 _spotlight       S      0:00.43   0:00.65 08-14:58:09    256  4367444      0 /usr/bin/some_command with some parameters
  460     1 root             Ss     0:00.13   0:00.95 08-14:58:06    196  4384904      0 /usr/bin/some_command with some parameters
  474     1 _windowserver    S      0:00.22   0:00.52 08-14:57:56     92  4367408      0 /usr/bin/some_command with some parameters
  481     1 _appinstalld     S      0:00.22   0:00.50 08-14:57:54     92  4367408      0 /usr/bin/some_command with some parameters
  492     1 root             Ss     2:58.80   4:36.41 08-14:57:50   9684  4585224      0 /usr/bin/some_command with some parameters
  501     1 _appleevents     Ss     0:02.48   0:03.54 08-14:57:47   2896  4501716      0 /usr/bin/some_command with some parameters
  503     1 root             Ss     0:00.01   0:00.05 08-14:57:47    148  4436644      0 /usr/bin/some_command with some parameters
  508     1 root             Ss    69:22.80 284:56.76 08-14:57:47  29604  4491692      0 /usr/bin/some_command with some parameters
  515    82 root             S      0:00.43   0:02.99 08-14:57:41    764  4502752      0 /usr/bin/some_command with some parameters
  528     1 root             Ss     0:00.15   0:01.08 08-14:57:39   1104  4502164      0 /usr/bin/some_command with some parameters
  541     1 _appleevents     S      0:00.21   0:00.50 08-14:57:36     92  4367408      0 /usr/bin/some_command with some parameters
  555     1 root             Ss     0:00.89   0:02.12 08-14:57:33   2816  4501864      0 /usr/bin/some_command with some parameters
  558     1 someuser     S      0:22.12   0:10.91 08-14:57:32   2344  4368112      0 /usr/bin/some_command with some parameters
  583     1 root             Ss     0:00.29   0:00.83 08-14:57:31    864  4500984      0 /usr/bin/some_command with some parameters
  631     1 root             Ss     0:00.04   0:00.02 08-14:57:28     32  4418196      0 /usr/bin/some_command with some parameters
  638     1 someuser     S      0:49.92   1:27.51 08-14:57:28   2968  4469948      0 /usr/bin/some_command with some parameters
  673     1 someuser     Ss     0:24.13   0:25.01 08-14:57:27  19868  4782072      0 /usr/bin/some_command with some parameters`

var psOut500 = `PID  PPID USER             STAT     UTIME     STIME     ELAPSED    RSS      VSZ PAGEIN COMMAND
    1     0 root             Ss     4:11.67  20:07.54 08-14:58:33  14376  4480016      0 /sbin/launchd
   68     1 root             Ss     0:22.59   0:41.16 08-14:58:25    852  4471000      0 /usr/bin/some_command with some parameters
   69     1 root             Ss     0:21.18   0:38.61 08-14:58:25   4416  4503784      0 /usr/bin/some_command with some parameters
   72     1 root             Ss     0:01.86   0:04.56 08-14:58:25    464  4403040      0 /usr/bin/some_command with some parameters
   73     1 root             Ss     2:15.80   4:35.94 08-14:58:25   2976  4477292      0 /usr/bin/some_command with some parameters
   74     1 root             Ss     0:00.02   0:00.10 08-14:58:25     64  4322064      0 /usr/bin/some_command with some parameters
   75     1 root             Ss     0:13.98   0:11.16 08-14:58:25   3572  4504692      0 /usr/bin/some_command with some parameters
   81     1 root             Ss     0:00.02   0:00.10 08-14:58:25     72  4312320      0 /usr/bin/some_command with some parameters
   82     1 root             Ss     2:38.05   1:57.49 08-14:58:25   4396  4515104      0 /usr/bin/some_command with some parameters
   84     1 root             Ss     0:22.27   0:41.25 08-14:58:25   3224  4506768      0 /usr/bin/some_command with some parameters
   86     1 root             Ss     0:39.19   1:53.93 08-14:58:25   4808  4503136      0 /usr/bin/some_command with some parameters
   88     1 root             Ss    21:00.91  24:52.86 08-14:58:25  17640  4579384      0 /usr/bin/some_command with some parameters
   91     1 root             Ss     0:10.63   0:15.49 08-14:58:25   1632  4515168      0 /usr/bin/some_command with some parameters
   93     1 root             Ss     2:11.10   2:51.66 08-14:58:25  10816  4586644      0 /usr/bin/some_command with some parameters
   99     1 root             Ss     0:03.12   0:04.29 08-14:58:25   1584  4469432      0 /usr/bin/some_command with some parameters
  103     1 root             Ss    10:21.66  15:23.52 08-14:58:25  12592  4814408      0 /usr/bin/some_command with some parameters
  104     1 root             RNs  224:31.63  95:24.02 08-14:58:25 148944 10665428      0 /usr/bin/some_command with some parameters
  106     1 root             Ss     0:08.78   0:09.93 08-14:58:25   2148  4522824      0 /usr/bin/some_command with some parameters
  107     1 root             Ss     0:41.81   0:24.94 08-14:58:25   2188  4500416      0 /usr/bin/some_command with some parameters
  114     1 root             Ss     0:00.00   0:00.03 08-14:58:25      8  4409456      0 /usr/bin/some_command with some parameters
  115     1 root             Ss     2:07.05   0:56.41 08-14:58:25   7844  4509284      0 /usr/bin/some_command with some parameters
  116     1 root             Ss    11:16.42  11:07.60 08-14:58:25   8596  4532768      0 /usr/bin/some_command with some parameters
  117     1 root             Ss     0:11.28   0:11.58 08-14:58:25   5508  4517024      0 /usr/bin/some_command with some parameters
  118     1 root             Ss     0:00.11   0:00.24 08-14:58:25    232  5017516      0 /usr/bin/some_command with some parameters
  119     1 root             Ss     4:09.83   4:01.65 08-14:58:25   6028  4502240      0 /usr/bin/some_command with some parameters
  120     1 _timed           Ss     0:01.47   0:07.47 08-14:58:25   1244  4500700      0 /usr/bin/some_command with some parameters
  123     1 root             Ss     0:15.88   0:05.03 08-14:58:25   4320  4504936      0 /usr/bin/some_command with some parameters
  124     1 root             Ss     0:00.00   0:00.05 08-14:58:25     36  4403280      0 /usr/bin/some_command with some parameters
  126     1 _locationd       Ss     1:05.54   1:07.10 08-14:58:25   5500  4522344      0 /usr/bin/some_command with some parameters
  128     1 root             Ss     0:00.00   0:00.05 08-14:58:25     56  4436712      0 /usr/bin/some_command with some parameters
  129     1 _displaypolicyd  Ss     0:00.20   0:02.01 08-14:58:25    380  4472456      0 /usr/bin/some_command with some parameters
  132     1 root             Ss     1:03.47   0:34.12 08-14:58:25   7100  4506616      0 /usr/bin/some_command with some parameters
  135     1 _distnote        Ss     0:05.55   0:03.92 08-14:58:25    892  4367444      0 /usr/bin/some_command with some parameters
  139     1 root             SNs    0:56.36   1:31.65 08-14:58:25   3392  4403952      0 /usr/bin/some_command with some parameters
  140     1 root             Ss     0:00.09   0:00.46 08-14:58:25   1128  4468904      0 /usr/bin/some_command with some parameters
  141     1 root             Ss     0:00.18   0:01.91 08-14:58:25   1268  4502020      0 /usr/bin/some_command with some parameters
  142     1 root             Ss     0:00.00   0:00.03 08-14:58:25     80  4411744      0 /usr/bin/some_command with some parameters
  144     1 root             Ss     0:23.44   0:34.43 08-14:58:25   4004  4504992      0 /usr/bin/some_command with some parameters
  145     1 root             Ss     0:33.93   1:17.70 08-14:58:25   1984  4469284      0 /usr/bin/some_command with some parameters
  147     1 root             Ss     0:41.57   0:49.94 08-14:58:25   3380  4501864      0 /usr/bin/some_command with some parameters
  148     1 root             Ss     0:01.39   0:03.99 08-14:58:25   1356  4502052      0 /usr/bin/some_command with some parameters
  151     1 root             Ss     4:33.07   1:27.82 08-14:58:25   8772  4544432      0 /usr/bin/some_command with some parameters
  152     1 root             Ss     0:49.94   1:25.03 08-14:58:25   2808  4469628      0 /usr/bin/some_command with some parameters
  153     1 root             Ss     0:02.71   0:05.10 08-14:58:25   1540  4517692      0 /usr/bin/some_command with some parameters
  156     1 _analyticsd      Ss     0:08.73   0:11.37 08-14:58:25   4536  4511792      0 /usr/bin/some_command with some parameters
  191     1 root             Ss     1:12.18   0:45.09 08-14:58:25   7972  4508044      0 /usr/bin/some_command with some parameters
  195     1 root             Ss     0:16.43   0:14.18 08-14:58:24   4872  4503448      0 /usr/bin/some_command with some parameters
  199     1 root             S      0:00.32   0:00.52 08-14:58:24     92  4367444      0 /usr/bin/some_command with some parameters
  206     1 root             Ss     0:19.05   0:15.72 08-14:58:24   6592  4511260      0 /usr/bin/some_command with some parameters
  208     1 _trustd          Ss     3:19.93   0:39.78 08-14:58:24   6948  4518924      0 /usr/bin/some_command with some parameters
  215     1 _networkd        Ss     0:56.22   2:25.35 08-14:58:24   5692  4512388      0 /usr/bin/some_command with some parameters
  232     1 _mdnsresponder   Ss     0:50.06   1:34.61 08-14:58:22   5168  4515992      0 /usr/bin/some_command with some parameters
  248     1 root             Ss     0:03.37   0:05.61 08-14:58:22    288  4501552      0 /usr/bin/some_command with some parameters
  250     1 root             Ss     0:00.18   0:01.24 08-14:58:22    896  4506016      0 /usr/bin/some_command with some parameters
  252     1 root             Ss     0:00.00   0:00.01 08-14:58:22     12  4400400      0 /usr/bin/some_command with some parameters
  254     1 root             Ss     0:00.14   0:00.62 08-14:58:22    548  4468908      0 /usr/bin/some_command with some parameters
  255     1 root             Ss     3:23.68   2:37.34 08-14:58:22   9636  4514220      0 /usr/bin/some_command with some parameters
  256     1 _coreaudiod      Ss    19:18.84  12:29.64 08-14:58:22   6700  4531492      0 /usr/bin/some_command with some parameters
  257     1 _nsurlsessiond   Ss     0:06.68   0:19.85 08-14:58:22   4332  4521772      0 /usr/bin/some_command with some parameters
  263     1 root             Ss     0:02.09   0:07.21 08-14:58:22   1436  4503404      0 /usr/bin/some_command with some parameters
  264     1 _cmiodalassistants Ss     5:01.51   2:35.11 08-14:58:22   8700  4556188      0 /usr/bin/some_command with some parameters
  269     1 root             Ss     1:39.02   1:56.92 08-14:58:22   2132  4502064      0 /usr/bin/some_command with some parameters
  271     1 _coreaudiod      S      0:00.24   0:00.52 08-14:58:22     92  4367408      0 /usr/bin/some_command with some parameters
  272     1 root             Ss     0:00.14   0:01.46 08-14:58:22    456  4501676      0 /usr/bin/some_command with some parameters
  279     1 _locationd       S      0:00.29   0:00.57 08-14:58:22     96  4367444      0 /usr/bin/some_command with some parameters
  300     1 root             Ss     0:01.46   0:05.79 08-14:58:21   2236  4514480      0 /usr/bin/some_command with some parameters
  307     1 _softwareupdate  S      0:00.24   0:00.55 08-14:58:21     92  4367408      0 /usr/bin/some_command with some parameters
  313     1 root             Ss     0:00.64   0:01.36 08-14:58:21    128  4524496      0 /usr/bin/some_command with some parameters
  322     1 root             Ss     0:01.54   0:04.68 08-14:58:21   5552  4516592      0 /usr/bin/some_command with some parameters
  337     1 root             Ss     0:00.24   0:01.86 08-14:58:19    428  4501512      0 /usr/bin/some_command with some parameters
  397     1 root             Ss   102:37.16  33:46.59 08-14:58:17 135092  4975516      0 /usr/bin/some_command with some parameters
  398     1 _nsurlsessiond   S      0:00.23   0:00.54 08-14:58:16     92  4367408      0 /usr/bin/some_command with some parameters
  419     1 root             Ss    37:27.33   9:27.48 08-14:58:10  61484  8032180      0 /usr/bin/some_command with some parameters
  422     1 _driverkit       Ss     0:01.03   0:02.65 08-14:58:10    708  4810472      0 /usr/bin/some_command with some parameters
  423     1 _driverkit       Ss     0:00.33   0:01.21 08-14:58:10    676  4810472      0 /usr/bin/some_command with some parameters
  425     1 _driverkit       Ss     0:00.00   0:00.03 08-14:58:10      8  4801256      0 /usr/bin/some_command with some parameters
  427     1 _driverkit       Ss     0:21.25   0:48.49 08-14:58:10    996  4810488      0 /usr/bin/some_command with some parameters
  428     1 _driverkit       Ss     0:00.00   0:00.02 08-14:58:10      8  4801256      0 /usr/bin/some_command with some parameters
  430     1 _driverkit       Ss     0:00.02   0:00.08 08-14:58:10      8  4808424      0 /usr/bin/some_command with some parameters
  432     1 _driverkit       Ss     0:00.31   0:00.95 08-14:58:10    676  4810472      0 /usr/bin/some_command with some parameters
  434     1 _driverkit       Ss     0:00.02   0:00.04 08-14:58:10     20  4816640      0 /usr/bin/some_command with some parameters
  435     1 _driverkit       Ss     0:00.00   0:00.00 08-14:58:10      8  4800252      0 /usr/bin/some_command with some parameters
  437     1 _spotlight       S      0:00.43   0:00.65 08-14:58:09    256  4367444      0 /usr/bin/some_command with some parameters
  460     1 root             Ss     0:00.13   0:00.95 08-14:58:06    196  4384904      0 /usr/bin/some_command with some parameters
  474     1 _windowserver    S      0:00.22   0:00.52 08-14:57:56     92  4367408      0 /usr/bin/some_command with some parameters
  481     1 _appinstalld     S      0:00.22   0:00.50 08-14:57:54     92  4367408      0 /usr/bin/some_command with some parameters
  492     1 root             Ss     2:58.80   4:36.41 08-14:57:50   9684  4585224      0 /usr/bin/some_command with some parameters
  501     1 _appleevents     Ss     0:02.48   0:03.54 08-14:57:47   2896  4501716      0 /usr/bin/some_command with some parameters
  503     1 root             Ss     0:00.01   0:00.05 08-14:57:47    148  4436644      0 /usr/bin/some_command with some parameters
  508     1 root             Ss    69:22.80 284:56.76 08-14:57:47  29604  4491692      0 /usr/bin/some_command with some parameters
  515    82 root             S      0:00.43   0:02.99 08-14:57:41    764  4502752      0 /usr/bin/some_command with some parameters
  528     1 root             Ss     0:00.15   0:01.08 08-14:57:39   1104  4502164      0 /usr/bin/some_command with some parameters
  541     1 _appleevents     S      0:00.21   0:00.50 08-14:57:36     92  4367408      0 /usr/bin/some_command with some parameters
  555     1 root             Ss     0:00.89   0:02.12 08-14:57:33   2816  4501864      0 /usr/bin/some_command with some parameters
  558     1 someuser     S      0:22.12   0:10.91 08-14:57:32   2344  4368112      0 /usr/bin/some_command with some parameters
  583     1 root             Ss     0:00.29   0:00.83 08-14:57:31    864  4500984      0 /usr/bin/some_command with some parameters
  631     1 root             Ss     0:00.04   0:00.02 08-14:57:28     32  4418196      0 /usr/bin/some_command with some parameters
  638     1 someuser     S      0:49.92   1:27.51 08-14:57:28   2968  4469948      0 /usr/bin/some_command with some parameters
  673     1 someuser     Ss     0:24.13   0:25.01 08-14:57:27  19868  4782072      0 /usr/bin/some_command with some parameters
  677     1 _windowserver    Ss   273:54.03 183:35.46 08-14:57:27  84708 11097548      0 /usr/bin/some_command with some parameters
  735     1 _securityagent   S      0:00.20   0:00.48 08-14:57:23     92  4367408      0 /usr/bin/some_command with some parameters
  762     1 root             Ss     0:00.07   0:00.24 08-14:57:22    344  4468988      0 /usr/bin/some_command with some parameters
  860     1 root             Ss     0:37.02   0:09.34 08-14:57:16   1792  4501828      0 /usr/bin/some_command with some parameters
  978  2828 someuser     S      0:03.61   0:04.06 01-00:22:51  19400 30027412      0 /usr/bin/some_command with some parameters
 2054     1 someuser     S      0:21.49   0:26.70 08-14:56:26   5044  4508552      0 /usr/bin/some_command with some parameters
 2059     1 someuser     S      1:38.52   0:24.47 08-14:56:25   6868  4522040      0 /usr/bin/some_command with some parameters
 2142     1 _appstore        S      0:00.20   0:00.47 08-14:55:24     92  4367408      0 /usr/bin/some_command with some parameters
 2155     1 _assetcache      S      0:00.20   0:00.46 08-14:55:20     92  4367408      0 /usr/bin/some_command with some parameters
 2156     1 someuser     SN     0:13.00   0:20.89 08-14:55:07   3424  4508336      0 /usr/bin/some_command with some parameters
 2157     1 _spotlight       SN     0:12.93   0:20.55 08-14:55:07   2916  4509148      0 /usr/bin/some_command with some parameters
 2165     1 _spotlight       S      0:00.06   0:00.14 08-14:55:03    200  4453292      0 /usr/bin/some_command with some parameters
 2316     1 someuser     S      0:14.93   0:17.03 08-14:54:54   5132  4504040      0 /usr/bin/some_command with some parameters
 2324     1 someuser     S      0:02.52   0:03.70 08-14:54:53   3316  4476480      0 /usr/bin/some_command with some parameters
 2325     1 someuser     S      0:02.67   0:10.56 08-14:54:53   3468  4513940      0 /usr/bin/some_command with some parameters
 2328     1 someuser     S      0:09.30   0:22.60 08-14:54:53   5180  4551980      0 /usr/bin/some_command with some parameters
 2329     1 someuser     S      0:01.98   0:04.14 08-14:54:53   2624  4501644      0 /usr/bin/some_command with some parameters
 2330     1 someuser     S      1:32.26   0:32.06 08-14:54:53  14524  5183340      0 /usr/bin/some_command with some parameters
 2331     1 someuser     S      0:04.71   0:07.80 08-14:54:53   7152  4509632      0 /usr/bin/some_command with some parameters
 2332     1 someuser     S      0:13.12   0:12.46 08-14:54:53   9296  4526744      0 /usr/bin/some_command with some parameters
 2334     1 someuser     S      0:22.69   0:16.18 08-14:54:53   5976  4699464      0 /usr/bin/some_command with some parameters
 2348     1 someuser     S      0:02.28   0:07.72 08-14:54:51   3436  4517492      0 /usr/bin/some_command with some parameters
 2349     1 someuser     S      0:00.90   0:01.91 08-14:54:50   2592  4502988      0 /usr/bin/some_command with some parameters
 2350     1 someuser     S      0:27.60   0:32.25 08-14:54:50  18180  5390300      0 /usr/bin/some_command with some parameters
 2361     1 someuser     S      0:00.02   0:00.13 08-14:54:47    188  4429328      0 /usr/bin/some_command with some parameters
 2363     1 someuser     S      0:04.66   0:09.83 08-14:54:44   6200  4520040      0 /usr/bin/some_command with some parameters
 2364     1 someuser     S      0:42.31   0:18.23 08-14:54:44   1880  4502788      0 /usr/bin/some_command with some parameters
 2367     1 someuser     S      0:00.27   0:01.99 08-14:54:44    748  4502224      0 /usr/bin/some_command with some parameters
 2369     1 someuser     Ss     0:09.77   0:13.68 08-14:54:43   5776  4982052      0 /usr/bin/some_command with some parameters
 2371     1 someuser     S      0:22.72   0:23.78 08-14:54:43   4388  4502616      0 /usr/bin/some_command with some parameters
 2383     1 someuser     S      0:00.30   0:00.68 08-14:54:42    128  4524688      0 /usr/bin/some_command with some parameters
 2389     1 someuser     S      0:02.71   0:06.13 08-14:54:41   5080  4555908      0 /usr/bin/some_command with some parameters
 2391     1 someuser     S      0:00.52   0:03.02 08-14:54:40   3400  4502792      0 /usr/bin/some_command with some parameters
 2397     1 someuser     S      0:01.87   0:04.29 08-14:54:37   2140  4502668      0 /usr/bin/some_command with some parameters
 2399     1 someuser     Ss     0:40.92   0:24.48 08-14:54:37   9528  5349444      0 /usr/bin/some_command with some parameters
 2402     1 root             Ss     0:00.64   0:01.66 08-14:54:37   3036  4475828      0 /usr/bin/some_command with some parameters
 2411     1 someuser     S      0:13.29   0:30.20 08-14:54:34   5852  4558504      0 /usr/bin/some_command with some parameters
 2412     1 someuser     S      0:20.66   0:27.38 08-14:54:33   4020  4502560      0 /usr/bin/some_command with some parameters
 2414     1 someuser     S      0:01.99   0:05.92 08-14:54:33   2620  4516816      0 /usr/bin/some_command with some parameters
 2417     1 someuser     S      0:01.15   0:04.26 08-14:54:32   2556  4802024      0 /usr/bin/some_command with some parameters
 2420     1 someuser     S      0:15.13   0:16.16 08-14:54:30   3516  4503164      0 /usr/bin/some_command with some parameters
 2421     1 someuser     S      0:00.68   0:01.09 08-14:54:30    524  4468844      0 /usr/bin/some_command with some parameters
 2425     1 someuser     S      0:21.08   0:36.98 08-14:54:30   5288  4513816      0 /usr/bin/some_command with some parameters
 2430     1 someuser     S      0:01.20   0:05.17 08-14:54:28   3080  4514368      0 /usr/bin/some_command with some parameters
 2441     1 someuser     S      0:02.28   0:09.12 08-14:54:25   2728  4501860      0 /usr/bin/some_command with some parameters
 2448     1 someuser     S      0:00.05   0:00.11 08-14:54:25    632  4463028      0 /usr/bin/some_command with some parameters
 2456     1 _reportmemoryexception S      0:00.20   0:00.44 08-14:54:20     92  4367408      0 /usr/bin/some_command with some parameters
 2458     1 root             Ss     0:00.02   0:00.08 08-14:54:19    648  4468844      0 /usr/bin/some_command with some parameters
 2478     1 _applepay        S      0:00.20   0:00.44 08-14:54:10     92  4367408      0 /usr/bin/some_command with some parameters
 2532     1 _fpsd            Ss     0:00.49   0:01.17 08-14:52:15     88  4389624      0 /usr/bin/some_command with some parameters
 2555     1 666              S      0:00.43   0:00.53 08-14:51:26    236  4367444      0 /usr/bin/some_command with some parameters
 2556     1 newrelic         S      0:00.42   0:00.52 08-14:51:25    236  4367444      0 /usr/bin/some_command with some parameters
 2730     1 newrelic         SN     0:11.91   0:18.84 08-14:48:59   1856  4507356      0 /usr/bin/some_command with some parameters
 2731     1 666              SN     0:11.94   0:18.87 08-14:48:59   1856  4507352      0 /usr/bin/some_command with some parameters
 2736     1 666              S      0:21.02   0:21.51 08-14:48:58   1416  4507568      0 /usr/bin/some_command with some parameters
 2737     1 newrelic         S      0:21.17   0:21.43 08-14:48:58   1416  4507572      0 /usr/bin/some_command with some parameters
 2827     1 someuser     S     30:58.89  10:27.94 08-14:42:42  81748  5816616      0 /usr/bin/some_command with some parameters
 2828     1 someuser     S     90:43.25  36:25.00 08-14:42:41 243936  6135992      0 /usr/bin/some_command with some parameters
 2832     1 someuser     S     12:42.13   7:03.75 08-14:42:40  61980 43791692      0 /usr/bin/some_command with some parameters
 2834     1 someuser     S     11:17.00  10:16.84 08-14:42:40  33144 10090544      0 /usr/bin/some_command with some parameters
 2836     1 someuser     S     31:11.18  15:32.71 08-14:42:40  61296  5733652      0 /usr/bin/some_command with some parameters
 2838     1 someuser     S    244:03.96  87:55.31 08-14:42:39 347524  6441364      0 /usr/bin/some_command with some parameters
 2839     1 someuser     T      0:00.00   0:00.00 08-14:42:38      4  4260072      0 /usr/bin/some_command with some parameters
 2840     1 someuser     S      0:06.80   0:11.98 08-14:42:37   6368  5391612      0 /usr/bin/some_command with some parameters
 2842     1 someuser     S      1:45.21   1:09.08 08-14:42:37  16584  5192932      0 /usr/bin/some_command with some parameters
 2843     1 someuser     S      0:35.97   0:29.42 08-14:42:36   5276  5154488      0 /usr/bin/some_command with some parameters
 2844     1 someuser     S      2:16.88   1:55.23 08-14:42:36  21520  5473872      0 /usr/bin/some_command with some parameters
 2848     1 someuser     S      0:18.41   0:19.18 08-14:42:36   6056  5188224      0 /usr/bin/some_command with some parameters
 2861     1 someuser     S      0:00.05   0:00.37 08-14:42:35    260  4464252      0 /usr/bin/some_command with some parameters
 2872     1 someuser     S      0:01.13   0:05.69 08-14:42:34   1212  4510572      0 /usr/bin/some_command with some parameters
 2882     1 root             Ss     0:00.05   0:00.17 08-14:42:33    132  4428416      0 /usr/bin/some_command with some parameters
 2885     1 someuser     S      0:00.05   0:00.35 08-14:42:33    248  4464252      0 /usr/bin/some_command with some parameters
 2889     1 someuser     S      0:04.63   0:08.78 08-14:42:30   4540  4534984      0 /usr/bin/some_command with some parameters
 2892  2832 someuser     S     42:37.65  16:27.26 08-14:42:29  29456  5027544      0 /usr/bin/some_command with some parameters
 2899  2832 someuser     S      1:22.11   1:04.56 08-14:42:29  10328  4714188      0 /usr/bin/some_command with some parameters
 2913     1 someuser     S      0:00.05   0:00.33 08-14:42:28    256  4472508      0 /usr/bin/some_command with some parameters
 2915  2832 someuser     S    116:23.29  14:11.11 08-14:42:27 224592 47242100      0 /usr/bin/some_command with some parameters
 2924  2834 someuser     S      3:57.25   1:44.85 08-14:42:27   7540  5165308      0 /usr/bin/some_command with some parameters
 2925  2834 someuser     S      0:34.10   0:28.53 08-14:42:27   8392  4703840      0 /usr/bin/some_command with some parameters
 2928     1 someuser     S      0:00.14   0:01.05 08-14:42:27    708  4669756      0 /usr/bin/some_command with some parameters
 2930     1 someuser     S      0:00.93   0:01.42 08-14:42:25   1736  4501280      0 /usr/bin/some_command with some parameters
 2948     1 root             Ss     0:04.21   0:10.50 08-14:42:24   1664  4501036      0 /usr/bin/some_command with some parameters
 2949  2827 someuser     S      0:00.01   0:00.02 08-14:42:24      8  4311692      0 /usr/bin/some_command with some parameters
 2984  2828 someuser     S     58:50.54  27:06.48 08-14:42:20  76684  7939928      0 /usr/bin/some_command with some parameters
 2986  2828 someuser     S     29:43.51  13:05.10 08-14:42:20  42148  4812112      0 /usr/bin/some_command with some parameters
 2991  2828 someuser     S      1:00.32   0:37.67 08-14:42:19   5548  4747448      0 /usr/bin/some_command with some parameters
 2997  2828 someuser     S      2:23.76   0:43.92 08-14:42:18  32048 29994144      0 /usr/bin/some_command with some parameters
 2998  2828 someuser     S      0:05.01   0:05.43 08-14:42:18   4672 29984524      0 /usr/bin/some_command with some parameters
 2999  2828 someuser     S      3:23.90   1:52.55 08-14:42:18  36272 30024356      0 /usr/bin/some_command with some parameters
 3016     1 someuser     S      0:00.01   0:00.12 08-14:42:17     52  4469476      0 /usr/bin/some_command with some parameters
 3033  2836 someuser     S      8:11.46   2:45.88 08-14:42:12   7912  4855280      0 /usr/bin/some_command with some parameters
 3059     1 someuser     Ss     0:04.76   0:06.36 08-14:42:08    552  4470796      0 /usr/bin/some_command with some parameters
 3062     1 someuser     S      0:01.74   0:05.01 08-14:42:08   1552  4515872      0 /usr/bin/some_command with some parameters
 3063     1 someuser     S      1:30.60   0:37.89 08-14:42:08   7528  4506740      0 /usr/bin/some_command with some parameters
 3071     1 someuser     S<     0:00.03   0:00.20 08-14:42:08    128  4501628      0 /usr/bin/some_command with some parameters
 3073     1 someuser     S     17:32.46  11:44.81 08-14:42:08  25632  5352928      0 /usr/bin/some_command with some parameters
 3080     1 someuser     S      0:01.60   0:05.41 08-14:42:08   3480  4968212      0 /usr/bin/some_command with some parameters
 3083     1 someuser     S      0:06.43   0:09.02 08-14:42:08   2016  4500992      0 /usr/bin/some_command with some parameters
 3088     1 someuser     S      3:32.35   3:59.93 08-14:42:08  16712  6625084      0 /usr/bin/some_command with some parameters
 3091     1 someuser     S      0:00.08   0:00.23 08-14:42:08    580  4469020      0 /usr/bin/some_command with some parameters
 3093  2836 someuser     S      0:00.51   0:01.06 08-14:42:07   1160  4719516      0 /usr/bin/some_command with some parameters
 3094  2836 someuser     S      1:02.52   0:53.95 08-14:42:07  10076  4738620      0 /usr/bin/some_command with some parameters
 3095  2836 someuser     S     21:28.85   5:06.94 08-14:42:07  36928 47125408      0 /usr/bin/some_command with some parameters
 3146     1 someuser     S      0:31.08   0:29.05 08-14:42:01   9736  5409664      0 /usr/bin/some_command with some parameters
 3181     1 someuser     S     12:19.70  10:55.35 08-14:41:57  21268  5190672      0 /usr/bin/some_command with some parameters
 3211  3073 someuser     S     17:41.68   6:32.44 08-14:41:54   1456  4732408      0 /usr/bin/some_command with some parameters
 3288  3073 someuser     S      2:51.70   1:11.08 08-14:41:52   6856  4686332      0 /usr/bin/some_command with some parameters
 3312  2828 someuser     S      4:06.39   0:56.98 08-14:41:49  18672 34530964      0 /usr/bin/some_command with some parameters
 3337  2828 someuser     S      3:42.05   1:53.09 08-14:41:48  42672 30220176      0 /usr/bin/some_command with some parameters
 3543  2834 someuser     S      1:34.97   0:32.71 08-14:41:36   3084  8908360      0 /usr/bin/some_command with some parameters
 3544  2834 someuser     S      1:04.96   0:30.34 08-14:41:36   9656  8995708      0 /usr/bin/some_command with some parameters
 3545  2834 someuser     S      0:33.10   0:16.46 08-14:41:36  10096  8986332      0 /usr/bin/some_command with some parameters
 3564  2834 someuser     S     13:31.51   3:18.03 08-14:41:35  52736  9309328      0 /usr/bin/some_command with some parameters
 3566  2834 someuser     S      0:00.88   0:02.21 08-14:41:35   2744  8995380      0 /usr/bin/some_command with some parameters
 3569  2834 someuser     S     17:07.58   3:54.01 08-14:41:34  89788  9460448      0 /usr/bin/some_command with some parameters
 3571  2834 someuser     S      0:00.91   0:02.28 08-14:41:34   2904  8994356      0 /usr/bin/some_command with some parameters
 3623  3073 someuser     S     52:17.67  11:34.11 08-14:41:18  51392  5076344      0 /usr/bin/some_command with some parameters
 3656     1 someuser     S      0:00.02   0:00.14 08-14:41:01   2204  4461572      0 /usr/bin/some_command with some parameters
 3732     1 root             S      7:12.99   1:10.20 08-14:40:36   1584  4476304      0 /usr/bin/some_command with some parameters
 3736     1 someuser     S      4:22.99   1:24.41 08-14:40:36   2716  4512484      0 /usr/bin/some_command with some parameters
 3742     1 root             Ss     7:29.21   6:04.37 08-14:40:36   3888  4494528      0 /usr/bin/some_command with some parameters
 3743     1 someuser     S      0:13.27   0:13.21 08-14:40:36   4040  4733128      0 /usr/bin/some_command with some parameters
 3747     1 root             Ss     8:05.21   2:59.27 08-14:40:36   3408  4483984      0 /usr/bin/some_command with some parameters
 3769     1 root             Ss     1:26.36   3:15.75 08-14:40:33    788  4477924      0 /usr/bin/some_command with some parameters
 3811     1 _driverkit       Ss     0:12.28   0:11.01 08-14:40:30   1120  4826876      0 /usr/bin/some_command with some parameters
 3813     1 _driverkit       Ss     0:00.00   0:00.01 08-14:40:30      8  4808448      0 /usr/bin/some_command with some parameters
 3834     1 someuser     S      0:05.59   0:17.21 08-14:40:26   5236  4660040      0 /usr/bin/some_command with some parameters
 3857     1 someuser     S      0:00.07   0:00.37 08-14:34:54    140  4469332      0 /usr/bin/some_command with some parameters
 4074     1 root             Ss     0:34.56   0:54.92 08-13:54:53   2040  4505404      0 /usr/bin/some_command with some parameters
 4168     1 someuser     S      0:00.23   0:01.53 08-09:51:17   1164  4501232      0 /usr/bin/some_command with some parameters
 5222  2828 someuser     S     16:02.55   4:18.96 08-04:00:15 117528 34562148      0 /usr/bin/some_command with some parameters
 5252  2828 someuser     S      0:14.30   0:19.63 08-04:00:13   3400  4736224      0 /usr/bin/some_command with some parameters
 5347     1 _fpsd            Ss     0:00.04   0:00.17 08-03:59:11   1036  4444676      0 /usr/bin/some_command with some parameters
 5407     1 someuser     S      0:00.30   0:00.89 08-03:58:41    284  4504764      0 /usr/bin/some_command with some parameters
 6280     1 nobody           S      0:00.18   0:00.40 08-03:18:55     92  4367408      0 /usr/bin/some_command with some parameters
 6305     1 someuser     S    282:50.93  82:22.21 08-03:17:56 2292124 18217416      0 /usr/bin/some_command with some parameters
 6351  6305 someuser     S      0:11.88   0:24.93 08-03:17:53    404  4403508      0 /usr/bin/some_command with some parameters
 6365  6305 someuser     S      0:04.48   0:04.98 08-03:17:47   2524  4892876      0 /usr/bin/some_command with some parameters
 6368  6305 someuser     S      0:00.73   0:02.15 08-03:17:46   1916  4730504      0 /usr/bin/some_command with some parameters
 6774     1 someuser     S      1:14.28   0:54.60 08-03:15:45  11608  6030076      0 /usr/bin/some_command with some parameters
 6796     1 someuser     Ss     0:01.93   0:06.99 08-03:15:42   5352  5006176      0 /usr/bin/some_command with some parameters
 6947     1 someuser     Ss     0:23.99   0:26.77 08-03:12:59  14192  4400464      0 /usr/bin/some_command with some parameters
 7649  2838 someuser     S      0:02.69   0:08.67 07-22:38:33   4660  4716376      0 /usr/bin/some_command with some parameters
 7651     1 someuser     S      0:01.60   0:05.57 07-22:38:31   4752  5132776      0 /usr/bin/some_command with some parameters
 7961     1 someuser     S      0:02.56   0:00.59 08-02:58:43    432  4371696      0 /usr/bin/some_command with some parameters
 9260 25257 someuser     S      3:51.10  15:40.43 02-01:11:16 558980  5146896      0 /usr/bin/some_command with some parameters
12403     1 someuser     S      0:03.22   0:07.88 08-02:12:17   4604  4767956      0 /usr/bin/some_command with some parameters
13175     1 someuser     S      0:22.98   0:34.21 07-22:17:23   6344  5200676      0 /usr/bin/some_command with some parameters
13178 13175 someuser     S      5:12.88   4:16.86 07-22:17:23  21612  6243308      0 /usr/bin/some_command with some parameters
13179 13175 someuser     S      0:03.66   0:04.15 07-22:17:23   4196  5014868      0 /usr/bin/some_command with some parameters
13201 13178 someuser     S      0:04.69   0:05.74 07-22:17:18   4668  5177360      0 /usr/bin/some_command with some parameters
13207 13201 someuser     S      0:16.94   0:25.36 07-22:17:17   2108  4446856      0 /usr/bin/some_command with some parameters
13208 13201 someuser     S      0:13.28   0:12.44 07-22:17:17   7412  5051112      0 /usr/bin/some_command with some parameters
13209 13201 someuser     S      3:11.69   5:39.34 07-22:17:17   7780  5011776      0 /usr/bin/some_command with some parameters
13210 13201 someuser     S      0:35.56   0:49.66 07-22:17:17   9224  5048820      0 /usr/bin/some_command with some parameters
13213 13207 someuser     Z      0:00.00   0:00.00 07-22:17:16      0 /usr/bin/some_command with some parameters
13219 13210 someuser     S     62:01.45 273:27.39 07-22:17:13   8684  6685852      0 /usr/bin/some_command with some parameters
13565  2832 someuser     S      0:07.72   0:10.21 08-02:05:51   3224  4704560      0 /usr/bin/some_command with some parameters
15552  2828 someuser     S      0:21.59   0:09.03    22:23:01  52380 34493004      0 /usr/bin/some_command with some parameters
20135  2828 someuser     S      0:07.21   0:10.85 08-01:34:55  21200 30212992      0 /usr/bin/some_command with some parameters
22878     1 someuser     S      0:03.53   0:06.54 07-16:03:13   4464  4715080      0 /usr/bin/some_command with some parameters
23677     1 root             Ss     0:08.84   0:10.65 05-21:56:12   6440  4508224      0 /usr/bin/some_command with some parameters
25255     1 someuser     S      0:41.36   6:19.76 07-03:55:41    352  4338244      0 /usr/bin/some_command with some parameters
25257     1 someuser     S      6:47.93  10:51.33 07-03:55:41   4000  4557808      0 /usr/bin/some_command with some parameters
25320 25257 someuser     S      0:03.25   0:05.20 07-03:55:33    600  4329640      0 /usr/bin/some_command with some parameters
27923     1 root             SNs    0:00.08   0:00.25 01-22:35:02   1204  4469016      0 /usr/bin/some_command with some parameters
29226     1 someuser     S      0:23.33   0:58.42 05-21:48:02   6600  4613240      0 /usr/bin/some_command with some parameters
29631  2828 someuser     S      0:46.31   0:35.11 04-19:33:24  41232 30292244      0 /usr/bin/some_command with some parameters
29686  2828 someuser     S      5:01.84   1:31.59 04-19:33:06  65136 30334312      0 /usr/bin/some_command with some parameters
29894  2828 someuser     S      0:13.88   0:05.57 01-22:27:32   6896 30011808      0 /usr/bin/some_command with some parameters
31499  2828 someuser     S      0:42.96   0:37.98 04-19:17:27  51460 30313196      0 /usr/bin/some_command with some parameters
31632  2828 someuser     S      5:00.31   1:03.01 04-19:16:15  42316 30307640      0 /usr/bin/some_command with some parameters
32179     1 someuser     Ss     0:46.91   0:33.35 07-00:25:38   9824  5290628      0 /usr/bin/some_command with some parameters
32424  2828 someuser     S      0:04.34   0:02.46 01-22:11:47   9352 30013604      0 /usr/bin/some_command with some parameters
33878     1 someuser     S      1:11.98   2:05.21 04-19:05:27  12044  5461036      0 /usr/bin/some_command with some parameters
33945 25257 someuser     S      4:06.13  49:50.93 04-19:05:09 1084480  5695004      0 /usr/bin/some_command with some parameters
37665     1 someuser     S      0:09.40   0:08.78    19:56:02  18148  4738308      0 /usr/bin/some_command with some parameters
37728  2828 someuser     S      0:01.70   0:01.72 01-21:26:00   6720 29984528      0 /usr/bin/some_command with some parameters
38532     1 someuser     S      0:00.18   0:00.34    19:12:29   4148  4507568      0 /usr/bin/some_command with some parameters
38747     1 root             Ss     0:01.51   0:01.02    19:02:32   6952  4507708      0 /usr/bin/some_command with some parameters
40037     1 someuser     S      0:11.66   0:17.17 06-19:11:03   6660  5376404      0 /usr/bin/some_command with some parameters
40686  2828 someuser     S      0:05.48   0:06.76 01-21:05:59  20752 30001376      0 /usr/bin/some_command with some parameters
40698  2828 someuser     S      0:10.13   0:05.07 01-21:05:52  12364 30248656      0 /usr/bin/some_command with some parameters
40707  2828 someuser     S      0:01.26   0:02.23 01-21:05:49  16620 29990580      0 /usr/bin/some_command with some parameters
41159  2828 someuser     S      0:01.59   0:01.43 01-21:01:44   4488 30007584      0 /usr/bin/some_command with some parameters
41458     1 root             Ss     0:00.23   0:00.58    17:31:36   8844  4502512      0 /usr/bin/some_command with some parameters
41491     1 root             Ss     0:01.84   0:03.01    17:31:03   2428  4462264      0 /usr/bin/some_command with some parameters
41501     1 someuser     S      0:00.25   0:00.38    17:01:05   7196  4507212      0 /usr/bin/some_command with some parameters
41507     1 someuser     Ss     0:02.07   0:01.29    17:01:04  39712  5001496      0 /usr/bin/some_command with some parameters
41513     1 root             Ss     0:00.07   0:00.32    17:01:04   4624  4506916      0 /usr/bin/some_command with some parameters
41520     1 root             Ss     0:00.10   0:00.09    17:01:03   3408  4501336      0 /usr/bin/some_command with some parameters
41747     1 someuser     S      0:00.56   0:01.09    15:16:53  25600  4553952      0 /usr/bin/some_command with some parameters
41837     1 root             Ss     0:03.48   0:01.11    13:14:29   9504  4508288      0 /usr/bin/some_command with some parameters
41852     1 root             Ss     0:00.06   0:00.15    11:14:25   2240  4469368      0 /usr/bin/some_command with some parameters
41855     1 root             Ss     0:00.12   0:00.10    11:14:23   4268  4469548      0 /usr/bin/some_command with some parameters
41869     1 someuser     S      0:00.34   0:00.27    11:14:21   3032  4501416      0 /usr/bin/some_command with some parameters
41875     1 someuser     S      0:00.17   0:00.15    11:14:20   7516  4501204      0 /usr/bin/some_command with some parameters
41878     1 someuser     S      0:00.51   0:00.58    11:14:20  34728  4939584      0 /usr/bin/some_command with some parameters
41886     1 root             Ss     0:06.23   0:00.47    11:14:12   2740  4558804      0 /usr/bin/some_command with some parameters
41890     1 root             Ss     0:00.65   0:02.81    11:14:11   4040  4470284      0 /usr/bin/some_command with some parameters
41897     1 root             Ss     0:00.07   0:00.17    11:14:08  10828  4442748      0 /usr/bin/some_command with some parameters
41908     1 someuser     Ss     0:00.17   0:00.39    11:13:56   2316  4472152      0 /usr/bin/some_command with some parameters
41912     1 root             Ss     0:00.04   0:00.20    11:13:39   3524  4469036      0 /usr/bin/some_command with some parameters
41926     1 root             Ss     0:01.47   0:03.00    09:13:37   3596  4504084      0 /usr/bin/some_command with some parameters
42029     1 _netbios         SNs    0:00.06   0:00.18    07:11:50   3056  4469768      0 /usr/bin/some_command with some parameters
42082     1 someuser     S      0:00.38   0:00.55    05:10:33  10624  4709112      0 /usr/bin/some_command with some parameters
42094     1 _driverkit       Ss     0:00.00   0:00.01    04:06:08   1240  4802280      0 /usr/bin/some_command with some parameters
42095     1 _driverkit       Ss     0:00.00   0:00.01    04:06:08   1248  4803304      0 /usr/bin/some_command with some parameters
42096     1 _driverkit       Ss     0:00.29   0:00.72    04:06:08   1676  4810472      0 /usr/bin/some_command with some parameters
42097     1 _driverkit       Ss     0:00.01   0:00.03    04:06:08   1276  4807400      0 /usr/bin/some_command with some parameters
42098     1 _driverkit       Ss     0:00.00   0:00.01    04:06:08   1236  4801256      0 /usr/bin/some_command with some parameters
42100     1 _driverkit       Ss     0:00.00   0:00.01    04:06:08   1248  4826876      0 /usr/bin/some_command with some parameters
42115     1 root             Ss     0:00.01   0:00.04    04:06:07   1168  4419408      0 /usr/bin/some_command with some parameters
42121     1 someuser     S      0:00.71   0:00.98    04:06:07  18876  4672452      0 /usr/bin/some_command with some parameters
42139     1 someuser     S      0:00.18   0:00.28    04:06:03  12144  4512888      0 /usr/bin/some_command with some parameters
42155     1 someuser     S      0:00.07   0:00.17    04:06:02   5080  4635844      0 /usr/bin/some_command with some parameters
42306     1 _spotlight       S      0:00.93   0:00.47    04:05:57   3272  4503812      0 /usr/bin/some_command with some parameters
42930     1 newrelic         S      0:00.66   0:00.20    04:05:33   3060  4503644      0 /usr/bin/some_command with some parameters
42931     1 666              S      0:00.75   0:00.26    04:05:33   3308  4503780      0 /usr/bin/some_command with some parameters
42958     1 someuser     S      0:02.07   0:07.75 06-18:12:41   4012  4560160      0 /usr/bin/some_command with some parameters
43266     1 someuser     S      0:00.28   0:00.53    04:05:22  10800  5133048      0 /usr/bin/some_command with some parameters
43267     1 someuser     S      0:00.31   0:00.30    04:05:22   5900  4521780      0 /usr/bin/some_command with some parameters
43686     1 someuser     S      0:00.31   0:00.19    04:05:06   6176  4500888      0 /usr/bin/some_command with some parameters
43718  2828 someuser     S      0:21.05   0:06.89    04:04:51  61656 29988608      0 /usr/bin/some_command with some parameters
43719     1 _gamecontrollerd Ss     0:35.23   0:34.34    04:04:50   6484  4501660      0 /usr/bin/some_command with some parameters
43720     1 _coreaudiod      Ss     0:00.27   0:00.28    04:04:49   1784  4470408      0 /usr/bin/some_command with some parameters
43724     1 someuser     S      0:00.35   0:00.50    04:04:40  13356  4555412      0 /usr/bin/some_command with some parameters
43725     1 someuser     S      0:00.35   0:00.27    04:04:39   7656  4504552      0 /usr/bin/some_command with some parameters
43726     1 someuser     S      0:00.05   0:00.10    04:04:38   4756  4469172      0 /usr/bin/some_command with some parameters
43728  2828 someuser     S      0:01.16   0:00.50    04:04:36  33280 29981708      0 /usr/bin/some_command with some parameters
43729  2828 someuser     S      0:00.96   0:00.56    04:04:32  39820 30201408      0 /usr/bin/some_command with some parameters
43731     1 root             Ss     0:00.07   0:00.12    04:04:31   5112  4501764      0 /usr/bin/some_command with some parameters
43865     1 someuser     Ss     0:00.20   0:00.26    04:01:01  11512  4513268      0 /usr/bin/some_command with some parameters
43867     1 someuser     S      0:00.11   0:00.14    04:01:01   2668  4501528      0 /usr/bin/some_command with some parameters
43868     1 root             Ss     4:07.09   1:17.30    04:01:01   9064  4510512      0 /usr/bin/some_command with some parameters
43869     1 someuser     S      0:00.09   0:00.10    04:01:01   6516  4503240      0 /usr/bin/some_command with some parameters
43871     1 someuser     S      0:00.27   0:00.39    04:01:01   9324  4510864      0 /usr/bin/some_command with some parameters
43873     1 root             Ss     0:00.05   0:00.03    04:01:00   2604  4469424      0 /usr/bin/some_command with some parameters
43874     1 _fpsd            Ss     0:00.02   0:00.03    04:01:00   2580  4462948      0 /usr/bin/some_command with some parameters
43880     1 root             Ss     0:00.01   0:00.02    04:01:00   1172  4428420      0 /usr/bin/some_command with some parameters
43881     1 someuser     S      0:00.03   0:00.04    04:01:00   5300  4501132      0 /usr/bin/some_command with some parameters
43882     1 someuser     S      0:00.95   0:00.91    04:01:00  14520  5154420      0 /usr/bin/some_command with some parameters
43883     1 root             Ss     0:00.10   0:00.15    04:01:00   5856  4501964      0 /usr/bin/some_command with some parameters
43889     1 someuser     S      0:00.19   0:00.44    04:00:59  12500  4559048      0 /usr/bin/some_command with some parameters
43890     1 someuser     S      0:00.01   0:00.04    04:00:59   3476  4469156      0 /usr/bin/some_command with some parameters
43892     1 root             Ss     0:00.13   0:00.08    04:00:59   6208  4505372      0 /usr/bin/some_command with some parameters
43893   139 root             SN     6:02.86   1:53.28    04:00:59  56592  4579620      0 /usr/bin/some_command with some parameters
43895     1 someuser     S      0:00.42   0:01.13    04:00:59  10948  4525368      0 /usr/bin/some_command with some parameters
43896     1 someuser     S      0:00.03   0:00.03    04:00:58   4056  4460904      0 /usr/bin/some_command with some parameters
43898     1 someuser     S      0:00.21   0:00.57    04:00:58  10428  4517276      0 /usr/bin/some_command with some parameters
43901     1 someuser     S      0:00.15   0:00.36    04:00:57  10512  4983912      0 /usr/bin/some_command with some parameters
43904     1 someuser     S      0:00.28   0:00.88    04:00:57  15404  4508360      0 /usr/bin/some_command with some parameters
43907     1 someuser     S      0:00.07   0:00.07    04:00:56   8780  4501212      0 /usr/bin/some_command with some parameters
43908     1 _installcoordinationd Ss     0:00.03   0:00.04    04:00:56   3548  4461340      0 /usr/bin/some_command with some parameters
43910     1 root             Ss     0:00.08   0:00.05    04:00:56   2204  4469212      0 /usr/bin/some_command with some parameters
43916     1 root             Ss     0:00.01   0:00.02    04:00:55   2456  4428548      0 /usr/bin/some_command with some parameters
43918     1 root             Ss     0:00.17   0:00.22    04:00:51   4868  4502444      0 /usr/bin/some_command with some parameters
43936     1 someuser     S      0:13.05   0:02.34    04:00:45 102644  4904648      0 /usr/bin/some_command with some parameters
43941     1 someuser     S      0:00.03   0:00.06    04:00:45   6680  4505292      0 /usr/bin/some_command with some parameters
43942     1 root             Ss     0:00.01   0:00.05    04:00:44   1216  4387164      0 /usr/bin/some_command with some parameters
43956     1 root             Ss     0:00.11   0:00.16    04:00:12   7552  4501572      0 /usr/bin/some_command with some parameters
43957     1 root             Ss     0:00.01   0:00.03    04:00:12   2224  4469360      0 /usr/bin/some_command with some parameters
43966     1 someuser     S      0:00.22   0:00.41    03:59:56   9244  4502860      0 /usr/bin/some_command with some parameters
43971     1 someuser     S      0:00.46   0:00.84    03:59:39  14664  4514540      0 /usr/bin/some_command with some parameters
43973     1 someuser     S      0:00.07   0:00.08    03:59:38   6744  4501644      0 /usr/bin/some_command with some parameters
43974     1 someuser     S      0:00.12   0:00.19    03:59:38   9636  4534772      0 /usr/bin/some_command with some parameters
43975     1 someuser     S      0:00.03   0:00.11    03:59:38   2436  4501720      0 /usr/bin/some_command with some parameters
43976     1 someuser     S      0:00.07   0:00.21    03:59:38   6548  4504276      0 /usr/bin/some_command with some parameters
43977     1 _assetcache      Ss     0:00.04   0:00.06    03:59:38   4788  4462272      0 /usr/bin/some_command with some parameters
43978     1 root             Ss     0:00.04   0:00.03    03:59:38   3144  4472376      0 /usr/bin/some_command with some parameters
43983     1 root             SNs    0:00.00   0:00.01    03:59:21    396  4383348      0 /usr/bin/some_command with some parameters
43984     1 root             Ss     0:00.00   0:00.01    03:59:21   1200  4418664      0 /usr/bin/some_command with some parameters
44067     1 someuser     S      0:00.05   0:00.08    03:59:06   6920  5019924      0 /usr/bin/some_command with some parameters
44068     1 someuser     S      0:00.38   0:00.92    03:59:06  12356  4511004      0 /usr/bin/some_command with some parameters
44070     1 someuser     Ss     0:00.02   0:00.04    03:59:05   7044  4526648      0 /usr/bin/some_command with some parameters
44072     1 someuser     S      0:00.38   0:00.88    03:59:05  25828  4555100      0 /usr/bin/some_command with some parameters
44073     1 someuser     S      0:00.02   0:00.04    03:59:05   4544  4451212      0 /usr/bin/some_command with some parameters
44074     1 someuser     S      0:00.05   0:00.05    03:59:05   6052  4486044      0 /usr/bin/some_command with some parameters
44075     1 someuser     Ss     0:00.01   0:00.01    03:59:04   2360  4404832      0 /usr/bin/some_command with some parameters
44076     1 someuser     S      0:00.02   0:00.04    03:59:04   6496  4489536      0 /usr/bin/some_command with some parameters
44083     1 someuser     S      0:00.07   0:00.08    03:58:50   7508  4505784      0 /usr/bin/some_command with some parameters
44084     1 someuser     S      0:00.01   0:00.01    03:58:50   3188  4484560      0 /usr/bin/some_command with some parameters
44085     1 someuser     S      0:00.13   0:00.07    03:58:50   5084  4502116      0 /usr/bin/some_command with some parameters
44086     1 root             Ss     0:00.08   0:00.18    03:58:50   4188  4475624      0 /usr/bin/some_command with some parameters
44090     1 someuser     S      0:00.16   0:00.33    03:58:49  12008  4712592      0 /usr/bin/some_command with some parameters
44098     1 someuser     Ss     0:34.74   0:36.48    03:58:36   4884  4544372      0 /usr/bin/some_command with some parameters
44099     1 root             Ss     0:00.06   0:00.06    03:58:35   5176  4501788      0 /usr/bin/some_command with some parameters
44100     1 someuser     S      0:00.24   0:00.58    03:58:35  13316  4717696      0 /usr/bin/some_command with some parameters
44101     1 root             Ss     0:00.04   0:00.01    03:58:35   1204  4414572      0 /usr/bin/some_command with some parameters
44103     1 someuser     S      0:00.17   0:00.38    03:58:19  12108  4984140      0 /usr/bin/some_command with some parameters
44153     1 root             Ss     0:00.20   0:00.23    03:52:58   2776  4471612      0 /usr/bin/some_command with some parameters
44167     1 root             Ss     0:00.33   0:00.21    03:52:37   3912  4514384      0 /usr/bin/some_command with some parameters
44185     1 someuser     Ss     0:00.74   0:00.41    03:51:04  38244  4967236      0 /usr/bin/some_command with some parameters
44520     1 root             Ss     0:21.43   0:01.69    03:37:59   3624  4478804      0 /usr/bin/some_command with some parameters
44805     1 someuser     Ss     0:00.78   0:00.37    03:25:11  40244  5132076      0 /usr/bin/some_command with some parameters
44913     1 root             Ss     0:00.02   0:00.02    03:23:40    992  4409696      0 /usr/bin/some_command with some parameters
45056     1 root             Ss     0:00.01   0:00.03    03:16:33   3544  4457836      0 /usr/bin/some_command with some parameters
45060     1 root             Ss     0:00.03   0:00.02    03:16:16   2480  4484908      0 /usr/bin/some_command with some parameters
45062     1 root             Ss     0:00.00   0:00.01    03:16:16   1616  4428404      0 /usr/bin/some_command with some parameters
45063     1 root             Ss     0:00.01   0:00.02    03:16:16   3164  4493296      0 /usr/bin/some_command with some parameters
45064     1 someuser     S      0:00.03   0:00.02    03:16:16   5876  4469764      0 /usr/bin/some_command with some parameters
45065     1 someuser     Ss     0:00.01   0:00.04    03:16:15   8272  4482376      0 /usr/bin/some_command with some parameters
45066     1 root             Ss     0:00.00   0:00.01    03:16:15   2820  4452456      0 /usr/bin/some_command with some parameters
45067     1 root             Ss     0:00.00   0:00.01    03:16:15   2868  4452456      0 /usr/bin/some_command with some parameters
45068     1 root             Ss     0:00.03   0:00.02    03:16:15   2740  4493316      0 /usr/bin/some_command with some parameters
45069     1 someuser     Ss     0:00.02   0:00.02    03:16:15   9216  4457000      0 /usr/bin/some_command with some parameters
45070     1 someuser     Ss     0:00.08   0:00.17    03:16:14  31604  4614864      0 /usr/bin/some_command with some parameters
45071     1 someuser     Ss     0:00.02   0:00.02    03:16:14   9204  4490792      0 /usr/bin/some_command with some parameters
45073     1 root             Ss     0:00.01   0:00.02    03:16:05   2704  4434688      0 /usr/bin/some_command with some parameters
45096     1 _appstore        Ss     0:00.20   0:00.47    03:15:29  11272  4512396      0 /usr/bin/some_command with some parameters
45097     1 someuser     S      0:00.07   0:00.09    03:15:29   5152  4461828      0 /usr/bin/some_command with some parameters
45098     1 root             Ss     0:00.06   0:00.03    03:15:28   4412  4502452      0 /usr/bin/some_command with some parameters
45101     1 someuser     S      0:00.24   0:00.10    03:15:12   8556  4505324      0 /usr/bin/some_command with some parameters
45104     1 root             Ss     0:00.01   0:00.02    03:14:56   2960  4436732      0 /usr/bin/some_command with some parameters
45105     1 root             Ss     0:00.01   0:00.02    03:14:56   1996  4436764      0 /usr/bin/some_command with some parameters
45106     1 root             Ss     0:00.02   0:00.03    03:14:55   4512  4448868      0 /usr/bin/some_command with some parameters
45111     1 _applepay        Ss     0:00.06   0:00.11    03:14:39   4036  4465524      0 /usr/bin/some_command with some parameters
45174     1 someuser     S      0:00.36   0:00.38    03:10:31   2328  4469464      0 /usr/bin/some_command with some parameters
45206  2828 someuser     S      0:13.66   0:09.04 08-00:49:53  12592 29970564      0 /usr/bin/some_command with some parameters
45624     1 someuser     S      0:00.01   0:00.03    02:54:41   6752  4436088      0 /usr/bin/some_command with some parameters
45782     1 someuser     S      0:00.02   0:00.04    02:49:03   2348  4500936      0 /usr/bin/some_command with some parameters
45792  2828 someuser     S      0:02.15   0:01.37    02:48:40  50716 29998868      0 /usr/bin/some_command with some parameters
45933     1 someuser     S      0:00.11   0:00.11    02:43:47   5596  4500920      0 /usr/bin/some_command with some parameters
45982     1 _iconservices    Ss     0:00.03   0:00.01    02:40:31   1884  4426912      0 /usr/bin/some_command with some parameters
46122 25257 someuser     S      3:58.32  55:53.41 05-19:37:35 1090964  5687776      0 /usr/bin/some_command with some parameters
46396     1 someuser     S      0:03.56   0:04.82 05-19:35:48   3460  4508436      0 /usr/bin/some_command with some parameters
46645  2828 someuser     S      0:00.85   0:00.34    02:17:06  44544 30006608      0 /usr/bin/some_command with some parameters
46738  2828 someuser     S      0:02.09   0:01.33    02:16:11  58224 30072984      0 /usr/bin/some_command with some parameters
47353  2828 someuser     S      0:09.82   0:01.73    01:56:34  54452 30222164      0 /usr/bin/some_command with some parameters
47355  2828 someuser     S      0:04.39   0:00.96    01:56:29  47800 30005420      0 /usr/bin/some_command with some parameters
49788     1 root             Ss     0:00.03   0:00.07    01:06:50   7128  4470308      0 /usr/bin/some_command with some parameters
51166     1 _softwareupdate  Ss     1:26.27   1:40.78 06-16:20:59   7132  4600944      0 /usr/bin/some_command with some parameters
51168     1 root             Ss     0:00.25   0:01.68 06-16:20:58    644  4504988      0 /usr/bin/some_command with some parameters
51169     1 _atsserver       Ss     0:00.25   0:00.74 06-16:20:58    788  4470832      0 /usr/bin/some_command with some parameters
51368     1 someuser     S      0:04.07   0:09.22 06-15:27:09   6624  4537084      0 /usr/bin/some_command with some parameters
52356  2828 someuser     S      0:01.51   0:00.48       31:56  58868 34199560      0 /usr/bin/some_command with some parameters
52359  2828 someuser     S      0:06.29   0:01.36       31:53  55940 30230764      0 /usr/bin/some_command with some parameters
53270     1 root             Ss     0:00.03   0:00.04       30:48   3076  4460200      0 /usr/bin/some_command with some parameters
53628     1 root             Ss     0:00.01   0:00.02       29:30   3176  4425516      0 /usr/bin/some_command with some parameters
53631     1 root             Ss     0:00.03   0:00.02       29:29   1476  4424424      0 /usr/bin/some_command with some parameters
53753     1 someuser     S      0:00.06   0:00.06       23:38   4072  4476468      0 /usr/bin/some_command with some parameters
53792     1 root             Ss     0:00.03   0:00.08       21:02   3104  4479136      0 /usr/bin/some_command with some parameters
53793     1 root             Ss     0:00.00   0:00.01       21:02   2372  4405596      0 /usr/bin/some_command with some parameters
53835  2838 someuser     S      2:02.77   0:49.41       20:45  40960  4694608      0 /usr/bin/some_command with some parameters
53836  2838 someuser     S      1:14.02   0:24.45       20:43  29924  4802016      0 /usr/bin/some_command with some parameters
53837     1 someuser     Ss     0:00.12   0:00.13       20:43   5212  4550420      0 /usr/bin/some_command with some parameters
53838     1 someuser     Ss     0:00.03   0:00.13       20:43   2288  4892308      0 /usr/bin/some_command with some parameters
53839     1 someuser     Ss     0:00.04   0:00.24       20:42   1752  4849368      0 /usr/bin/some_command with some parameters
53885  2828 someuser     S      0:01.36   0:00.27       17:24  53856 30073136      0 /usr/bin/some_command with some parameters
53929  2828 someuser     S      0:01.62   0:00.37       14:25  49896 30006408      0 /usr/bin/some_command with some parameters
53931  2828 someuser     S      0:00.09   0:00.04       14:20  20312 29973136      0 /usr/bin/some_command with some parameters
54166     1 someuser     S      0:00.17   0:00.23       12:08  14300  4862340      0 /usr/bin/some_command with some parameters
54402     1 someuser     S      0:00.08   0:00.05       02:40   9952  4477448      0 /usr/bin/some_command with some parameters
54840     1 someuser     S      0:00.05   0:00.02       00:14   5132  4444152      0 /usr/bin/some_command with some parameters
55706     1 root             Ss     0:00.01   0:00.06 01-19:23:23    264  4452756      0 /usr/bin/some_command with some parameters
56786  2828 someuser     S      2:44.32   0:46.63 01-19:17:22 101724 30335308      0 /usr/bin/some_command with some parameters
67087     1 someuser     S<     0:00.02   0:00.13 05-12:33:55    128  4502220      0 /usr/bin/some_command with some parameters
70071     1 root             Ss     0:00.09   0:00.22 01-03:34:12   2100  4485696      0 /usr/bin/some_command with some parameters
70682     1 _usbmuxd         Ss     0:00.05   0:00.15 01-03:32:05   1596  4464252      0 /usr/bin/some_command with some parameters
70696     1 someuser     S      0:00.47   0:01.53 01-03:32:04   6708  4703432      0 /usr/bin/some_command with some parameters
70752     1 someuser     S      0:00.07   0:00.32 01-03:31:59   2964  4507376      0 /usr/bin/some_command with some parameters
70896     1 _driverkit       Ss     0:00.00   0:00.02 01-03:30:59    220  4800232      0 /usr/bin/some_command with some parameters
70898     1 _driverkit       Ss     0:31.53   1:25.95 01-03:30:59    756  4810996      0 /usr/bin/some_command with some parameters
70899     1 _driverkit       Ss     0:24.49   0:36.97 01-03:30:59    684  4810496      0 /usr/bin/some_command with some parameters
71311     1 root             Ss     0:14.93   0:25.21 01-03:27:30  11168  4506632      0 /usr/bin/some_command with some parameters
75951  2828 someuser     S      0:07.09   0:05.92 05-23:52:24   8116 29977444      0 /usr/bin/some_command with some parameters
76232  2828 someuser     S      0:32.61   0:25.42 05-23:50:45  22396 30003880      0 /usr/bin/some_command with some parameters
79317  2828 someuser     S      0:12.80   0:09.77 05-01:26:20   7100 30014992      0 /usr/bin/some_command with some parameters
79623  2828 someuser     S      0:27.32   0:15.83 01-02:17:54  39500 34189824      0 /usr/bin/some_command with some parameters
79636  2828 someuser     S      0:23.39   0:15.08 01-02:17:50  38148 34197540      0 /usr/bin/some_command with some parameters
79637  2828 someuser     S      0:00.31   0:00.60 01-02:17:50   6348 29973680      0 /usr/bin/some_command with some parameters
79692  2828 someuser     S      0:41.06   0:19.53 01-02:17:38 105872 30086076      0 /usr/bin/some_command with some parameters
79727     1 someuser     S     13:34.28  13:44.94 06-20:37:35  26636  5376912      0 /usr/bin/some_command with some parameters
79738  2828 someuser     S      0:51.34   0:25.93 01-02:17:16  62400 30105596      0 /usr/bin/some_command with some parameters
80172  2828 someuser     S      0:10.71   0:04.62 01-02:13:44  30536 30002272      0 /usr/bin/some_command with some parameters
87090  6305 someuser     ?Es    0:00.00   0:00.00 07-23:41:16      0 /usr/bin/some_command with some parameters
87324 87090 someuser     Z      0:00.00   0:00.00 07-23:41:12      0 /usr/bin/some_command with some parameters
87339  2828 someuser     S      2:04.19   0:29.69 01-01:22:11  47436 34221640      0 /usr/bin/some_command with some parameters
89436     1 someuser     S      0:05.20   0:06.94 05-23:11:51   5904  4538312      0 /usr/bin/some_command with some parameters
89517  2828 someuser     S     20:37.55   3:52.48 04-00:35:47 209016 63653976      0 /usr/bin/some_command with some parameters
92412  2828 someuser     S      1:40.63   0:34.70 01-00:57:02  79664 42633048      0 /usr/bin/some_command with some parameters
96559     1 someuser     S      0:27.56   0:15.84 04-23:43:59  18544  5430400      0 /usr/bin/some_command with some parameters
97411  2828 someuser     S      0:02.14   0:02.34 02-02:46:46   4928 29984652      0 /usr/bin/some_command with some parameters
98939  2828 someuser     S      0:34.14   0:09.05 01-00:34:12  51468 30021300      0 /usr/bin/some_command with some parameters
99779  2828 someuser     S      0:12.27   0:04.10 01-00:29:06  24548 30019412      0 /usr/bin/some_command with some parameters
99817  6305 someuser     S      0:00.38   0:01.25 04-23:18:44   2604 42554704      0 /usr/bin/some_command with some parameters
99889  2828 someuser     S      0:05.75   0:05.06 01-00:28:17  27912 30287484      0 /usr/bin/some_command with some parameters
 2956  2949 root             Ss     0:00.02   0:00.03 08-14:42:23     12  4469120      0 /usr/bin/some_command with some parameters
 2959  2956 someuser     S      0:00.26   0:00.30 08-14:42:22      8  4370964      0 /usr/bin/some_command with some parameters
 6945  2959 someuser     S+     0:00.01   0:00.05 08-03:13:00    112  4297872      0 /usr/bin/some_command with some parameters
 6948  6947 someuser     Ss+    0:00.38   0:00.58 08-03:12:59    200  4362720      0 /usr/bin/some_command with some parameters
 6999  6947 someuser     Ss+    0:00.29   0:00.52 08-03:12:57      8  4348436      0 /usr/bin/some_command with some parameters
 7049  6947 someuser     Ss+    0:00.20   0:00.20 08-03:12:56      8  4338196      0 /usr/bin/some_command with some parameters
11147  6947 someuser     Ss+    0:00.46   0:00.42 08-02:35:38      8  4338196      0 /usr/bin/some_command with some parameters
65815  6947 someuser     Ss+    0:00.67   0:01.10 08-00:18:51   3016  4362844      0 /usr/bin/some_command with some parameters
 1393  6947 someuser     Ss+    0:00.31   0:00.36 07-23:15:08      8  4338064      0 /usr/bin/some_command with some parameters
26136  6305 someuser     Ss+    0:00.33   0:00.54 07-03:31:53    228  4370964      0 /usr/bin/some_command with some parameters
42855  6947 someuser     Ss     0:00.33   0:00.61 01-20:49:21   3192  4355472      0 /usr/bin/some_command with some parameters
54887 42855 root             R+     0:00.00   0:00.01       00:01   1076  4269016      0 /usr/bin/some_command with some parameters`

var psOutThreads10 = `USER               PID   TT   %CPU STAT PRI     STIME     UTIME COMMAND
root                 1   ??    0.0 S    31T   0:00.39   0:00.09 /usr/bin/some_command with some parameters
                     1         0.0 S    20T   0:00.15   0:00.04 
                     1         0.6 S    37T   0:00.01   0:00.00 
root                68   ??    0.0 S     4T   0:01.24   0:00.33 /usr/bin/some_command with some parameters
                    68         0.0 S     4T   0:00.00   0:00.00 
                    68         0.0 S     4T   0:00.00   0:00.00 
                    68         0.0 S     4T   0:00.00   0:00.00 
root                69   ??    0.0 S    31T   0:00.20   0:00.08 /usr/bin/some_command with some parameters
                    69         0.0 S    31T   0:00.00   0:00.00 
                    69         0.0 S    31T   0:00.00   0:00.00 
                    69         0.0 S     4T   0:00.01   0:00.00 
root                72   ??    0.0 S    20T   0:00.98   0:00.94 /usr/bin/some_command with some parameters
                    72         0.0 S    20T   0:00.00   0:00.00 
root                73   ??    0.0 S    49T   0:27.84   1:22.66 /usr/bin/some_command with some parameters
                    73         0.0 S    31T   0:00.00   0:00.00 
                    73         0.0 S    31T   0:00.02   0:00.01 
                    73         0.0 S    50R   0:16.31   0:03.31 
                    73         0.0 S    31T   0:01.93   0:07.66 
                    73         0.0 S    31T   0:13.32   0:04.10 
                    73         0.0 S    31T   0:57.43   0:05.99 
                    73         0.0 S    31T   0:13.38   0:01.60 
                    73         0.0 S    31T   0:09.00   0:00.96 
                    73         0.0 S    31T   0:02.29   0:00.64 
                    73         0.0 S    31T   0:08.64   0:01.02 
                    73         0.0 S    31T   0:00.01   0:00.00 
                    73         0.0 S    31T   0:00.00   0:00.00 
                    73         0.0 S    31T   0:00.00   0:00.00 
root                74   ??    0.0 S    20T   0:00.05   0:00.02 /usr/bin/some_command with some parameters
                    74         0.0 S    20T   0:00.04   0:00.01 
root                75   ??    0.0 S     4T   0:04.35   0:07.60 /usr/bin/some_command with some parameters
                    75         0.0 S     4T   0:00.00   0:00.00 
                    75         0.0 S     4T   0:00.00   0:00.00 
root                81   ??    0.0 S    20T   0:00.05   0:00.02 /usr/bin/some_command with some parameters
                    81         0.0 S    20T   0:00.05   0:00.01 
root                82   ??    0.0 S     4T   0:06.92   0:05.91 /usr/bin/some_command with some parameters
                    82         0.0 S     4T   0:00.00   0:00.00 
                    82         0.0 S     4T   0:00.00   0:00.00 
root                84   ??    0.0 S    31T   0:04.14   0:02.10 /usr/bin/some_command with some parameters
                    84         0.0 S    31T   0:00.12   0:00.03 
                    84         0.0 S    31T   0:00.25   0:00.13 
                    84         0.0 S    31T   0:00.65   0:00.28 
                    84         0.0 S    31T   0:00.21   0:00.10 
                    84         0.0 S    31T   0:00.33   0:00.18 
                    84         0.0 S    31T   0:00.37   0:00.16 
                    84         0.0 S    31T   0:00.01   0:00.00 
root                86   ??    0.0 S    31T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                    86         0.0 S    37T   0:00.01   0:00.01 
                    86         0.0 S    37T   0:00.00   0:00.00 
root                88   ??    0.0 S    20T   0:10.90   0:10.20 /usr/bin/some_command with some parameters
                    88         0.0 S    20T  24:38.78  20:49.45 
                    88         0.0 S    20T   0:00.00   0:00.00 
                    88         0.0 S    20T   0:00.00   0:00.00 
root                91   ??    0.0 S    31T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                    91         0.0 S    31T   0:00.00   0:00.00 
                    91         0.0 S    31T   0:00.00   0:00.00 
                    91         0.0 S    31T   0:00.00   0:00.00 
root                93   ??    0.0 S    31T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                    93         0.0 S    20T   0:00.01   0:00.01 
                    93         0.0 S    20T   0:00.01   0:00.00 
                    93         0.0 S    20T   0:00.00   0:00.00 
root                99   ??    0.0 S    31T   0:00.04   0:00.01 /usr/bin/some_command with some parameters
                    99         0.0 S    97R   0:00.16   0:00.06 
                    99         0.0 S    31T   0:00.04   0:00.06
`

var psOutThreads100 = `USER               PID   TT   %CPU STAT PRI     STIME     UTIME COMMAND
root                 1   ??    0.0 S    31T   0:00.39   0:00.09 /usr/bin/some_command with some parameters
                     1         0.0 S    20T   0:00.15   0:00.04 
                     1         0.6 S    37T   0:00.01   0:00.00 
root                68   ??    0.0 S     4T   0:01.24   0:00.33 /usr/bin/some_command with some parameters
                    68         0.0 S     4T   0:00.00   0:00.00 
                    68         0.0 S     4T   0:00.00   0:00.00 
                    68         0.0 S     4T   0:00.00   0:00.00 
root                69   ??    0.0 S    31T   0:00.20   0:00.08 /usr/bin/some_command with some parameters
                    69         0.0 S    31T   0:00.00   0:00.00 
                    69         0.0 S    31T   0:00.00   0:00.00 
                    69         0.0 S     4T   0:00.01   0:00.00 
root                72   ??    0.0 S    20T   0:00.98   0:00.94 /usr/bin/some_command with some parameters
                    72         0.0 S    20T   0:00.00   0:00.00 
root                73   ??    0.0 S    49T   0:27.84   1:22.66 /usr/bin/some_command with some parameters
                    73         0.0 S    31T   0:00.00   0:00.00 
                    73         0.0 S    31T   0:00.02   0:00.01 
                    73         0.0 S    50R   0:16.31   0:03.31 
                    73         0.0 S    31T   0:01.93   0:07.66 
                    73         0.0 S    31T   0:13.32   0:04.10 
                    73         0.0 S    31T   0:57.43   0:05.99 
                    73         0.0 S    31T   0:13.38   0:01.60 
                    73         0.0 S    31T   0:09.00   0:00.96 
                    73         0.0 S    31T   0:02.29   0:00.64 
                    73         0.0 S    31T   0:08.64   0:01.02 
                    73         0.0 S    31T   0:00.01   0:00.00 
                    73         0.0 S    31T   0:00.00   0:00.00 
                    73         0.0 S    31T   0:00.00   0:00.00 
root                74   ??    0.0 S    20T   0:00.05   0:00.02 /usr/bin/some_command with some parameters
                    74         0.0 S    20T   0:00.04   0:00.01 
root                75   ??    0.0 S     4T   0:04.35   0:07.60 /usr/bin/some_command with some parameters
                    75         0.0 S     4T   0:00.00   0:00.00 
                    75         0.0 S     4T   0:00.00   0:00.00 
root                81   ??    0.0 S    20T   0:00.05   0:00.02 /usr/bin/some_command with some parameters
                    81         0.0 S    20T   0:00.05   0:00.01 
root                82   ??    0.0 S     4T   0:06.92   0:05.91 /usr/bin/some_command with some parameters
                    82         0.0 S     4T   0:00.00   0:00.00 
                    82         0.0 S     4T   0:00.00   0:00.00 
root                84   ??    0.0 S    31T   0:04.14   0:02.10 /usr/bin/some_command with some parameters
                    84         0.0 S    31T   0:00.12   0:00.03 
                    84         0.0 S    31T   0:00.25   0:00.13 
                    84         0.0 S    31T   0:00.65   0:00.28 
                    84         0.0 S    31T   0:00.21   0:00.10 
                    84         0.0 S    31T   0:00.33   0:00.18 
                    84         0.0 S    31T   0:00.37   0:00.16 
                    84         0.0 S    31T   0:00.01   0:00.00 
root                86   ??    0.0 S    31T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                    86         0.0 S    37T   0:00.01   0:00.01 
                    86         0.0 S    37T   0:00.00   0:00.00 
root                88   ??    0.0 S    20T   0:10.90   0:10.20 /usr/bin/some_command with some parameters
                    88         0.0 S    20T  24:38.78  20:49.45 
                    88         0.0 S    20T   0:00.00   0:00.00 
                    88         0.0 S    20T   0:00.00   0:00.00 
root                91   ??    0.0 S    31T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                    91         0.0 S    31T   0:00.00   0:00.00 
                    91         0.0 S    31T   0:00.00   0:00.00 
                    91         0.0 S    31T   0:00.00   0:00.00 
root                93   ??    0.0 S    31T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                    93         0.0 S    20T   0:00.01   0:00.01 
                    93         0.0 S    20T   0:00.01   0:00.00 
                    93         0.0 S    20T   0:00.00   0:00.00 
root                99   ??    0.0 S    31T   0:00.04   0:00.01 /usr/bin/some_command with some parameters
                    99         0.0 S    97R   0:00.16   0:00.06 
                    99         0.0 S    31T   0:00.04   0:00.06 
root               103   ??    0.0 S    31T   0:00.15   0:00.09 /usr/bin/some_command with some parameters
                   103         0.0 S    50R   0:24.25   0:09.17 
                   103         0.0 S    31T   0:00.00   0:00.00 
                   103         0.0 S     4T   0:00.03   0:00.02 
                   103         0.0 S    37T   0:00.00   0:00.00 
                   103         0.0 S    20T   0:00.01   0:00.00 
                   103         0.0 S    31T   0:00.00   0:00.00 
                   103         0.0 S    37T   0:00.00   0:00.00 
                   103         0.0 S     4T   0:00.00   0:00.00 
root               104   ??    0.0 S     4T   0:01.01   0:09.28 /usr/bin/some_command with some parameters
                   104         0.0 S     4T   2:14.81   5:02.47 
                   104         0.0 S     4T   0:00.44   0:01.08 
                   104         0.0 S     4T   0:12.12   2:53.73 
                   104         0.0 S     4T   0:00.02   0:00.01 
                   104         0.0 S     4T   0:15.99   0:06.45 
                   104         0.0 S     4T   1:28.59   2:46.98 
                   104         0.0 S     4T   0:04.30   0:12.81 
                   104         0.0 S     4T   0:08.71   0:17.49 
                   104         0.0 S     4T   0:00.00   0:00.00 
                   104         0.0 S     4T   0:59.96   6:08.35 
                   104         0.0 S     4T   0:23.11   0:36.48 
                   104         0.0 S     4T   1:34.48   2:09.53 
                   104         0.0 S     4T   0:00.00   0:00.00 
                   104         0.0 S     4T   0:44.10   0:19.85 
                   104         0.0 S     4T   0:00.52   0:00.17 
                   104         0.0 S     4T   2:14.01   5:01.32 
                   104         0.0 S     4T   2:13.19   5:01.40 
                   104         0.0 S     4T   2:13.78   5:03.91 
                   104         0.0 S     4T   2:15.10   5:04.41 
                   104         0.0 S     4T   2:12.32   5:03.10 
                   104         0.0 S     4T   0:12.37   2:53.81 
                   104         0.0 S     4T   0:12.10   2:53.81 
                   104         0.0 S     4T   2:14.30   5:02.53 
                   104         0.0 S     4T   2:10.42   5:00.82 
                   104         0.0 S     4T   2:14.03   5:02.43 
                   104         0.0 S     4T   2:11.48   5:03.86 
                   104         0.0 S     4T   0:00.00   0:00.00 
                   104         0.0 S     4T   0:00.00   0:00.00 
                   104         0.0 S     4T   0:08.54   0:06.59 
                   104         0.0 S     4T   0:00.00   0:00.00 
                   104         0.0 S     4T   0:00.00   0:00.00 
                   104         0.0 S     4T   0:00.00   0:00.00 
                   104         0.0 S     4T   0:00.00   0:00.00 
                   104         0.0 S     4T   0:05.34   0:01.55 
                   104         0.0 S     4T   0:03.66   0:01.06 
                   104         0.0 S     4T   0:00.18   0:00.03 
                   104         0.0 S     4T   0:37.36   0:06.80 
                   104         0.0 S     4T   0:01.95   0:01.44 
                   104         0.0 S     4T   0:37.35   0:40.82 
                   104         0.0 S     4T   0:12.91   0:09.45 
                   104         0.0 S     4T   0:02.40   0:00.68 
                   104         0.0 S     4T   0:00.00   0:00.00 
                   104         0.0 S     4T   0:08.22   0:07.64 
                   104         0.0 S     4T   0:00.17   0:00.02 
                   104         0.0 S     4T   0:00.00   0:00.00 
                   104         0.0 S     4T   0:00.10   0:00.03 
                   104         0.0 S     4T   0:01.59   0:01.74 
                   104         0.0 S     4T   0:01.66   0:00.43 
                   104         0.0 S     4T   0:00.98   0:00.21 
                   104         0.0 S     4T   0:01.56   0:00.92 
                   104         0.0 S     4T   0:00.02   0:00.00 
                   104         0.0 S     4T   0:00.38   0:00.14 
                   104         0.0 S     4T   0:00.92   0:00.25 
                   104         0.0 S     4T   0:17.54   0:09.81 
                   104         0.0 S     4T   0:05.13   0:01.18 
                   104         0.0 S     4T   0:11.10   1:14.80 
                   104         0.0 S     4T   2:27.08  11:01.59 
                   104         0.0 S     4T   0:00.00   0:00.00 
                   104         0.0 S     4T   0:00.76   0:00.28 
                   104         0.3 S     4T  21:15.35  38:57.00 
                   104         0.0 S     4T   0:01.84   0:00.31 
                   104         0.0 S     4T   0:17.74   0:28.64 
                   104         0.0 S     4T   0:00.00   0:00.00 
                   104         0.0 S     4T   0:00.00   0:00.00 
                   104         0.0 S     4T   0:00.00   0:00.00 
                   104         0.0 S     4T   0:00.00   0:00.00 
                   104         0.0 S     4T   0:00.00   0:00.00 
                   104         0.0 S     4T   0:00.00   0:00.00 
                   104         0.0 S     4T   0:15.35   0:45.24 
                   104         0.0 S     4T   0:00.70   0:00.30 
                   104         0.0 S     4T   0:00.62   0:00.27 
                   104         0.0 S     4T   0:00.64   0:00.31 
                   104         0.0 S     4T   0:00.55   0:00.28 
                   104         0.0 S     4T   0:02.64   0:04.64 
                   104         0.0 S     4T   0:03.42   0:01.28 
                   104         0.0 S     4T   0:05.43   0:02.17 
                   104         0.0 S     4T   0:00.18   0:00.05 
                   104         0.0 S     4T   0:00.00   0:00.00 
                   104         0.0 S     4T   0:00.18   0:00.05 
                   104         0.0 S     4T   0:00.00   0:00.00 
                   104         0.0 S     4T   0:33.60   0:37.38 
                   104         0.0 S     4T   0:24.14   0:08.43 
                   104         0.0 S     4T   2:35.92   4:31.62 
                   104         0.0 S     4T   0:04.54   0:03.01 
                   104         0.0 S     4T   1:29.91   1:00.41 
                   104         0.0 S     4T   0:04.88   0:01.94 
                   104         0.0 S     4T   0:07.19   0:05.44 
                   104         0.0 S     4T   0:02.68   0:00.83 
                   104         0.0 S     4T   0:56.96   1:49.87 
                   104         0.0 S     4T   0:12.03   0:07.99 
                   104         0.0 S     4T   0:15.67   0:12.93 
                   104         0.0 S     4T   0:25.82   1:14.97 
                   104         0.0 S     4T   0:01.66   0:02.08 
                   104         0.0 S     4T   0:08.01   0:40.99 
                   104         0.0 S     4T   0:00.00   0:00.00 
                   104         0.0 S     4T   0:02.42   0:02.15 
                   104         0.0 S     4T   0:00.00   0:00.00 
                   104         0.0 S     4T   0:01.54   0:01.59 
                   104         0.0 S     4T   0:01.13   0:00.29 
                   104         0.0 S     4T   0:02.33   0:00.85 
                   104         0.0 S     4T   0:20.38   0:20.06 
                   104         0.0 S     4T   1:52.14  25:52.43 
                   104         0.0 S     4T   2:07.78   2:26.81 
                   104         0.0 S     4T   4:04.54   4:24.85 
                   104         0.0 S     4T   0:00.01   0:00.00 
                   104         0.0 S     4T   0:00.88   0:02.39 
                   104         0.0 S     4T   0:00.98   0:02.32 
                   104         0.0 S     4T   0:00.83   0:02.10 
                   104         0.3 S     4T   0:00.87   0:02.00 
                   104         0.0 S     4T   0:00.62   0:01.89 
                   104         0.0 S     4T   0:00.24   0:00.51 
                   104         0.0 S     4T   0:00.85   0:04.37 
                   104         0.0 S     4T   0:00.01   0:00.01 
                   104         0.1 S     4T   0:00.11   0:00.17 
                   104         0.0 S     4T   0:00.07   0:00.11 
                   104         0.0 S     4T   0:00.02   0:00.03 
                   104         0.0 S     4T   0:00.01   0:00.01 
                   104         0.0 S     4T   0:00.00   0:00.00 
root               106   ??    0.0 S    31T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                   106         0.0 S    31T   0:00.00   0:00.00 
root               107   ??    0.0 S    31T   0:24.80   0:41.84 /usr/bin/some_command with some parameters
                   107         0.0 S    37T   0:00.00   0:00.00 
root               114   ??    0.0 S    37T   0:00.03   0:00.00 /usr/bin/some_command with some parameters
root               115   ??    0.0 S     4T   0:00.78   0:00.70 /usr/bin/some_command with some parameters
                   115         0.0 S     4T   0:00.00   0:00.01 
                   115         0.0 S     4T   0:00.00   0:00.00 
                   115         0.0 S     4T   0:00.00   0:00.00 
                   115         0.0 S     4T   0:00.01   0:00.02 
root               116   ??    0.0 S    20T   0:00.42   0:00.96 /usr/bin/some_command with some parameters
                   116         0.0 S    31T   0:00.00   0:00.00 
                   116         0.0 S    20T   0:00.00   0:00.00 
                   116         0.0 S    31T   0:00.20   0:00.07 
                   116         0.0 S    31T   0:00.00   0:00.00 
                   116         0.0 S    31T   0:00.00   0:00.00 
                   116         0.0 S    31T   0:00.00   0:00.00 
root               117   ??    0.0 S    31T   0:06.27   0:08.00 /usr/bin/some_command with some parameters
                   117         0.0 S    31T   0:00.00   0:00.00 
                   117         0.0 S    31T   0:00.01   0:00.00 
root               118   ??    0.0 S    20T   0:00.02   0:00.01 /usr/bin/some_command with some parameters
                   118         0.0 S    20T   0:00.22   0:00.11 
                   118         0.0 S    20T   0:00.00   0:00.00 
                   118         0.0 S    20T   0:00.00   0:00.00 
                   118         0.0 S    20T   0:00.00   0:00.00 
                   118         0.0 S    20T   0:00.00   0:00.00 
root               119   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                   119         0.0 S     4T   0:00.00   0:00.00 
                   119         0.0 S     4T   0:00.01   0:00.01 
_timed             120   ??    0.0 S    31T   0:03.13   0:00.61 /usr/bin/some_command with some parameters
                   120         0.0 S     4T   0:00.02   0:00.00 
root               123   ??    0.0 S    31T   0:01.98   0:06.46 /usr/bin/some_command with some parameters
                   123         0.0 S    31T   0:00.17   0:00.03 
                   123         0.0 S    31T   0:00.00   0:00.00 
root               124   ??    0.0 S    20T   0:00.00   0:00.00 auditd -l
                   124         0.0 S    20T   0:00.04   0:00.00 
_locationd         126   ??    0.0 S     4T   0:00.62   0:00.12 /usr/bin/some_command with some parameters
                   126         0.0 S     4T   0:00.04   0:00.05 
                   126         0.0 S     4T   0:00.01   0:00.00 
                   126         0.0 S     4T   0:00.00   0:00.00 
root               128   ??    0.0 S    20T   0:00.00   0:00.00 autofsd
                   128         0.0 S    20T   0:00.00   0:00.00 
_displaypolicyd    129   ??    0.0 S    20T   0:00.43   0:00.05 /usr/bin/some_command with some parameters
                   129         0.0 S    20T   0:00.00   0:00.00 
                   129         0.0 S    20T   0:00.16   0:00.08 
                   129         0.0 S    20T   0:00.93   0:00.02 
                   129         0.0 S    20T   0:00.05   0:00.00 
                   129         0.0 S    20T   0:00.01   0:00.00 
root               132   ??    0.0 S     4T   0:00.05   0:00.06 /usr/bin/some_command with some parameters
                   132         0.0 S     4T   0:00.00   0:00.00 
                   132         0.0 S     4T   0:00.00   0:00.00 
_distnote          135   ??    0.0 S    31T   0:00.01   0:00.03 /usr/bin/some_command with some parameters
                   135         0.0 S    31T   0:00.76   0:01.09 
root               139   ??    0.0 S    20T   0:00.06   0:00.02 /usr/bin/some_command with some parameters
                   139         0.0 S    20T   1:27.75   0:55.96 
                   139         0.0 S    20T   0:04.08   0:00.52 
root               140   ??    0.0 S    31T   0:00.05   0:00.00 /usr/bin/some_command with some parameters
                   140         0.0 S    31T   0:00.00   0:00.00 
root               141   ??    0.0 S     4T   0:00.07   0:00.03 /usr/bin/some_command with some parameters
                   141         0.0 S     4T   0:00.00   0:00.00 
                   141         0.0 S     4T   0:00.00   0:00.00 
root               142   ??    0.0 S    31T   0:00.02   0:00.00 /usr/bin/some_command with some parameters
                   142         0.0 S    31T   0:00.01   0:00.00 
                   142         0.0 S    31T   0:00.00   0:00.00 
root               144   ??    0.0 S    31T   0:19.66   0:16.97 /usr/bin/some_command with some parameters
                   144         0.0 S    31T   0:11.46   0:04.77 
                   144         0.0 S    37T   0:00.03   0:00.01 
root               145   ??    0.0 S    31T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                   145         0.0 S    37T   0:00.08   0:00.04 
root               147   ??    0.0 S    31T   0:00.30   0:00.25 /usr/bin/some_command with some parameters
                   147         0.0 S    31T   0:00.00   0:00.00 
root               148   ??    0.0 S    55R   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                   148         0.0 S    19T   0:00.00   0:00.00 
                   148         0.0 S    31T   0:00.00   0:00.00 
                   148         0.0 S    31T   0:00.01   0:00.00 
root               151   ??    0.0 S    31T   0:00.19   0:00.27 /usr/bin/some_command with some parameters
                   151         0.0 S    31T   0:00.43   0:00.77 
                   151         0.0 S    31T   0:00.01   0:00.00 
root               152   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                   152         0.0 S     4T   0:00.00   0:00.00 
                   152         0.0 S     4T   0:00.00   0:00.00 
root               153   ??    0.0 S    31T   0:04.59   0:02.48 /usr/bin/some_command with some parameters
                   153         0.0 S    31T   0:00.16   0:00.16 
                   153         0.0 S    31T   0:00.07   0:00.01 
                   153         0.0 S    31T   0:00.01   0:00.00 
_analyticsd        156   ??    0.0 S    31T   0:00.23   0:00.16 /usr/bin/some_command with some parameters
                   156         0.0 S    31T   0:00.01   0:00.00 
root               191   ??    0.0 S     4T   0:00.05   0:00.04 /usr/bin/some_command with some parameters
                   191         0.0 S     4T   0:00.00   0:00.01 
                   191         0.0 S     4T   0:00.00   0:00.00 
                   191         0.0 S     4T   0:00.00   0:00.00 
                   191         0.0 S     4T   0:00.00   0:00.00 
root               195   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                   195         0.0 S     4T   0:00.27   0:00.03 
                   195         0.0 S     4T   0:00.03   0:00.06 
root               199   ??    0.0 S    31T   0:00.00   0:00.03 /usr/bin/some_command with some parameters
                   199         0.0 S    31T   0:00.51   0:00.29 
root               206   ??    0.0 S     4T   0:01.29   0:01.82 /usr/bin/some_command with some parameters
                   206         0.0 S     4T   0:00.00   0:00.00 
_trustd            208   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                   208         0.0 S     4T   0:00.00   0:00.00 
_networkd          215   ??    0.0 S     4T   0:01.52   0:00.19 /usr/bin/some_command with some parameters
                   215         0.0 S     4T   0:00.01   0:00.00 
                   215         0.0 S     4T   0:00.00   0:00.00 
_mdnsresponder     232   ??    0.0 S    31T   0:02.58   0:03.05 /usr/bin/some_command with some parameters
                   232         0.0 S    31T   1:14.24   0:37.44 
                   232         0.0 S    37T   0:00.00   0:00.00 
root               248   ??    0.0 S    31T   0:05.23   0:03.32 /usr/bin/some_command with some parameters
                   248         0.0 S    31T   0:00.00   0:00.00 
                   248         0.0 S    37T   0:00.00   0:00.00 
root               250   ??    0.0 S     4T   0:00.14   0:00.05 /usr/bin/some_command with some parameters
                   250         0.0 S     4T   0:00.00   0:00.00 
root               252   ??    0.0 S    31T   0:00.01   0:00.00 /usr/bin/some_command with some parameters
                   252         0.0 S    31T   0:00.00   0:00.00 
root               254   ??    0.0 S    20T   0:00.49   0:00.12 /usr/bin/some_command with some parameters
                   254         0.0 S    20T   0:00.00   0:00.00 
root               255   ??    0.0 S    31T   0:25.65   0:13.33 /usr/bin/some_command with some parameters
                   255         0.0 S    31T   0:00.25   0:00.03 
                   255         0.0 S    31T   0:20.97   0:06.65 
                   255         0.0 S    31T   0:00.00   0:00.00 
                   255         0.0 S    31T   0:02.38   0:01.51 
                   255         0.0 S    31T   0:00.00   0:00.00 
                   255         0.0 S    31T   0:00.00   0:00.00 
                   255         0.0 S    31T   0:00.00   0:00.00 
                   255         0.0 S    31T   0:00.00   0:00.00 
                   255         0.0 S    31T   0:00.00   0:00.00 
                   255         0.0 S    31T   0:00.00   0:00.00 
_coreaudiod        256   ??    0.0 S    63T   0:00.26   0:00.11 /usr/bin/some_command with some parameters
                   256         0.0 S    19T   0:00.00   0:00.00 
                   256         0.0 S    31T   0:00.00   0:00.00 
                   256         0.0 S    31T   0:00.95   0:00.05 
                   256         0.3 S    97R   0:02.08   0:05.95 
                   256         0.3 S    97R   0:02.04   0:05.63 
                   256         0.3 S    61T   0:00.70   0:00.25 
                   256         0.0 S    31T   0:00.00   0:00.00 
                   256         0.8 S    61R   0:00.40   0:00.27 
_nsurlsessiond     257   ??    0.0 S     4T   0:00.38   0:00.15 /usr/bin/some_command with some parameters
                   257         0.0 S     4T   0:00.00   0:00.00 
root               263   ??    0.0 S     4T   0:00.69   0:00.11 /usr/bin/some_command with some parameters
                   263         0.0 S     4T   0:00.01   0:00.00 
                   263         0.0 S     4T   0:00.00   0:00.00 
_cmiodalassistants   264   ??    0.0 S    31T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                   264         1.1 S    97R   2:00.26   4:45.36 
                   264         0.1 S    31T   0:01.94   0:01.28 
                   264         0.0 S    31T   0:00.00   0:00.00 
root               269   ??    0.0 S    20T   1:55.12   1:38.27 /usr/bin/some_command with some parameters
                   269         0.0 S    20T   0:00.94   0:00.31 
                   269         0.0 S    20T   0:00.00   0:00.00 
_coreaudiod        271   ??    0.0 S    31T   0:00.00   0:00.03 /usr/bin/some_command with some parameters
                   271         0.0 S    31T   0:00.52   0:00.21 
root               272   ??    0.0 S     4T   0:00.06   0:00.01 /usr/bin/some_command with some parameters
                   272         0.0 S     4T   0:00.00   0:00.00 
_locationd         279   ??    0.0 S    31T   0:00.00   0:00.03 /usr/bin/some_command with some parameters
                   279         0.0 S    31T   0:00.56   0:00.26 
root               300   ??    0.0 S     4T   0:00.05   0:00.01 /usr/bin/some_command with some parameters
                   300         0.0 S     4T   0:00.07   0:00.01 
_softwareupdate    307   ??    0.0 S    31T   0:00.00   0:00.03 /usr/bin/some_command with some parameters
                   307         0.0 S    31T   0:00.54   0:00.21 
root               313   ??    0.0 S    31T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                   313         0.0 S    31T   0:00.00   0:00.00 
root               322   ??    0.0 S    20T   0:00.03   0:00.03 /usr/bin/some_command with some parameters
                   322         0.0 S    20T   0:00.00   0:00.00 
                   322         0.0 S    20T   0:00.00   0:00.00 
root               337   ??    0.0 S     4T   0:00.08   0:00.03 /usr/bin/some_command with some parameters
                   337         0.0 S     4T   0:00.00   0:00.00 
root               397   ??    0.0 S    31T   0:14.02   0:12.57 /usr/bin/some_command with some parameters
                   397         0.0 S    31T   0:00.00   0:00.00 
                   397         0.0 S    31T   0:00.00   0:00.00 
                   397         0.0 S    31T   1:32.16   7:28.27 
                   397         0.0 R    31T   1:32.29   7:28.11 
                   397         0.0 S    31T   1:33.32   7:28.98 
                   397         0.0 S    31T   1:32.30   7:28.34 
                   397         0.0 S    31T   1:32.30   7:28.44 
                   397         0.0 S    31T   1:32.33   7:27.11 
                   397         0.0 S    31T   0:10.06   0:22.50 
                   397         0.0 S    31T   0:00.25   0:01.70 
                   397         0.0 S    31T   2:20.84   5:59.52 
                   397         0.0 S    31T   0:00.29   0:00.12 
                   397         0.0 S    31T   5:05.54   5:08.26 
                   397         0.0 S     4T   0:00.16   0:00.34 
                   397         0.0 S    31T   0:00.04   0:00.02 
                   397         0.0 S    31T   0:43.11   1:10.88 
                   397         0.0 S    31T   0:00.72   0:00.56 
                   397         0.0 S    31T   0:13.98   0:26.76 
                   397         0.0 S    31T   0:01.40   0:01.34 
                   397         0.0 S    31T   0:02.07   0:01.84 
                   397         0.0 S    31T   0:00.59   0:00.76 
                   397         0.0 S    31T   0:00.37   0:00.67 
                   397         0.0 S    31T   0:00.15   0:00.13 
                   397         0.0 S    31T   0:00.02   0:00.02 
                   397         0.0 R    54R   0:00.01   0:00.02 
                   397         0.0 S    31T   0:00.03   0:00.01 
_nsurlsessiond     398   ??    0.0 S    31T   0:00.00   0:00.02 /usr/bin/some_command with some parameters
                   398         0.0 S    31T   0:00.53   0:00.21 
root               419   ??    0.0 S    31T   0:00.71   0:00.84 /usr/bin/some_command with some parameters
                   419         0.0 S    31T   0:00.00   0:00.00 
                   419         0.0 S     4T   0:00.00   0:00.00 
                   419         0.0 S     4T   0:00.01   0:00.00 
                   419         0.0 S    31T   0:00.01   0:00.01 
                   419         0.0 S    37T   0:00.00   0:00.00 
                   419         0.0 S     4T   0:00.00   0:00.00 
                   419         0.0 S     4T   0:00.00   0:00.00 
                   419         0.0 S     4T   0:00.00   0:00.00 
                   419         0.0 S     4T   0:00.00   0:00.00 
                   419         0.0 S     4T   0:00.00   0:00.00 
                   419         0.0 S     4T   0:00.00   0:00.01 
                   419         0.0 S    31T   0:00.00   0:00.00 
_driverkit         422   ??    0.0 S    31T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                   422         0.0 S    63R   0:00.09   0:00.03 
_driverkit         423   ??    0.0 S    31T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                   423         0.0 S    63R   0:00.00   0:00.00 
_driverkit         425   ??    0.0 S    63R   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                   425         0.0 S    31T   0:00.00   0:00.00 
_driverkit         427   ??    0.0 S    31T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                   427         0.0 S    63R   0:03.41   0:01.46 
_driverkit         428   ??    0.0 S    63R   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                   428         0.0 S    31T   0:00.00   0:00.00 
_driverkit         430   ??    0.0 S    31T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                   430         0.0 S    63R   0:00.00   0:00.00 
_driverkit         432   ??    0.0 S    63R   0:00.94   0:00.30 /usr/bin/some_command with some parameters
                   432         0.0 S    31T   0:00.00   0:00.00 
_driverkit         434   ??    0.0 S    63R   0:00.04   0:00.02 /usr/bin/some_command with some parameters
                   434         0.0 S    31T   0:00.00   0:00.00 
_driverkit         435   ??    0.0 S    63R   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                   435         0.0 S    31T   0:00.00   0:00.00 
_spotlight         437   ??    0.0 S    31T   0:00.00   0:00.02 /usr/bin/some_command with some parameters
                   437         0.0 S    31T   0:00.13   0:00.08 
root               460   ??    0.0 S    63R   0:00.88   0:00.12 /usr/bin/some_command with some parameters
                   460         0.0 S    31T   0:00.00   0:00.00 
_windowserver      474   ??    0.0 S    31T   0:00.00   0:00.02 /usr/bin/some_command with some parameters
                   474         0.0 S    31T   0:00.52   0:00.20 
_appinstalld       481   ??    0.0 S    31T   0:00.01   0:00.03 /usr/bin/some_command with some parameters
                   481         0.0 S    31T   0:00.50   0:00.19 
root               492   ??    0.0 S    51R   0:17.61   0:22.47 /usr/bin/some_command with some parameters
                   492         0.1 S    55R   4:03.41   2:28.94 
                   492         0.0 S    37T   0:03.98   0:03.88 
                   492         0.0 S    51T   0:00.00   0:00.00 
                   492         0.0 S    37T   0:00.00   0:00.00 
                   492         0.0 S    31T   0:00.00   0:00.00 
                   492         0.0 S    51R   0:00.00   0:00.00 
_appleevents       501   ??    0.0 S    31T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                   501         0.0 S    31T   0:00.00   0:00.00 
root               503   ??    0.0 S    31T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                   503         0.0 S     4T   0:00.00   0:00.00 
root               508   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                   508        23.4 S     4T   0:06.35   0:01.50 
                   508         0.0 S     4T   0:00.60   0:00.14 
root               515   ??    0.0 S     4T   0:00.12   0:00.03 /usr/bin/some_command with some parameters
                   515         0.0 S     4T   0:00.00   0:00.00 
                   515         0.0 S     4T   0:00.00   0:00.00 
root               528   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                   528         0.0 S     4T   0:00.00   0:00.00 
_appleevents       541   ??    0.0 S    31T   0:00.01   0:00.02 /usr/bin/some_command with some parameters
                   541         0.0 S    31T   0:00.50   0:00.19 
root               555   ??    0.0 S     4T   0:00.04   0:00.01 /usr/bin/some_command with some parameters
                   555         0.0 S     4T   0:00.00   0:00.00 
someuser       558   ??    0.0 S    31T   0:00.01   0:00.03 /usr/bin/some_command with some parameters
                   558         0.0 S    20T   0:00.86   0:01.75 
root               583   ??    0.0 S     4T   0:00.06   0:00.01 /usr/bin/some_command with some parameters
                   583         0.0 S     4T   0:00.00   0:00.00 
root               631   ??    0.0 S    20T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                   631         0.0 S    20T   0:00.01   0:00.00 
someuser       638   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                   638         0.0 S     4T   0:00.01   0:00.00 
                   638         0.0 S     4T   0:00.00   0:00.00 
someuser       673   ??    0.0 S    47T   0:10.83   0:08.96 /usr/bin/some_command with some parameters
                   673         0.0 S    19T   0:00.00   0:00.00 
                   673         0.0 S    31T   0:00.00   0:00.00 
                   673         0.0 S    37T   0:00.00   0:00.00 
_windowserver      677   ??   26.8 S    79R 100:32.78 206:51.42 /usr/bin/some_command with some parameters
                   677         2.8 S    79R  42:18.54  27:27.26 
                   677         0.0 S    37T   0:00.00   0:00.00 
                   677         0.0 S    79R   0:00.00   0:00.00 
                   677         0.0 S    31T   0:00.01   0:00.00 
                   677         0.0 S    31T   0:00.16   0:00.20 
                   677         0.0 S    31T   0:28.55   0:11.03 
                   677         1.7 U    31T   0:23.73   0:19.24 
                   677         1.9 S    31T   0:14.59   0:11.88 
                   677         0.0 S    79R   0:13.48   0:11.02 
                   677         0.6 S    79R   0:01.43   0:00.84 
                   677         0.2 S    79T   0:04.30   0:03.51 
                   677        21.0 S    79T   0:04.35   0:03.53 
                   677         1.2 S    79R   0:00.53   0:00.29 
                   677         0.0 S    31T   0:00.00   0:00.00 
                   677         1.2 S    79R   0:00.09   0:00.05 
_securityagent     735   ??    0.0 S    31T   0:00.00   0:00.02 /usr/bin/some_command with some parameters
                   735         0.0 S    31T   0:00.47   0:00.18 
root               762   ??    0.0 S     4T   0:00.01   0:00.03 /usr/bin/some_command with some parameters
                   762         0.0 S     4T   0:00.01   0:00.00 
root               860   ??    0.0 S    31T   0:01.12   0:01.52 /usr/bin/some_command with some parameters
                   860         0.0 S    31T   0:00.58   0:00.39 
                   860         0.0 S    31T   0:00.00   0:00.01 
someuser       978   ??    0.0 S    31T   0:03.65   0:02.88 /usr/bin/some_command with some parameters
                   978         0.0 S    31T   0:00.00   0:00.00 
                   978         0.0 S     0T   0:00.02   0:00.02 
                   978         0.0 S    31T   0:00.13   0:00.06 
                   978         0.0 S    31T   0:00.00   0:00.00 
                   978         0.0 S    31T   0:00.00   0:00.00 
                   978         0.0 S    31T   0:00.00   0:00.00 
                   978         0.0 S    31T   0:00.00   0:00.00 
                   978         0.0 S    31T   0:00.00   0:00.00 
                   978         0.0 S    31T   0:00.00   0:00.00 
                   978         0.0 S    31T   0:00.00   0:00.00 
                   978         0.0 S    31T   0:00.00   0:00.00 
                   978         0.0 S    31T   0:00.10   0:00.02 
                   978         0.0 S    31T   0:00.02   0:00.00 
                   978         0.0 S    31T   0:00.01   0:00.00 
someuser      2054   ??    0.0 S     4T   0:01.04   0:01.49 /usr/bin/some_command with some parameters
                  2054         0.0 S     4T   0:00.01   0:00.00 
                  2054         0.0 S     4T   0:00.00   0:00.00
`

var psOutThreads500 = `USER               PID   TT   %CPU STAT PRI     STIME     UTIME COMMAND
root                 1   ??    0.0 S    31T   0:00.39   0:00.09 /usr/bin/some_command with some parameters
                     1         0.0 S    20T   0:00.15   0:00.04 
                     1         0.6 S    37T   0:00.01   0:00.00 
root                68   ??    0.0 S     4T   0:01.24   0:00.33 /usr/bin/some_command with some parameters
                    68         0.0 S     4T   0:00.00   0:00.00 
                    68         0.0 S     4T   0:00.00   0:00.00 
                    68         0.0 S     4T   0:00.00   0:00.00 
root                69   ??    0.0 S    31T   0:00.20   0:00.08 /usr/bin/some_command with some parameters
                    69         0.0 S    31T   0:00.00   0:00.00 
                    69         0.0 S    31T   0:00.00   0:00.00 
                    69         0.0 S     4T   0:00.01   0:00.00 
root                72   ??    0.0 S    20T   0:00.98   0:00.94 /usr/bin/some_command with some parameters
                    72         0.0 S    20T   0:00.00   0:00.00 
root                73   ??    0.0 S    49T   0:27.84   1:22.66 /usr/bin/some_command with some parameters
                    73         0.0 S    31T   0:00.00   0:00.00 
                    73         0.0 S    31T   0:00.02   0:00.01 
                    73         0.0 S    50R   0:16.31   0:03.31 
                    73         0.0 S    31T   0:01.93   0:07.66 
                    73         0.0 S    31T   0:13.32   0:04.10 
                    73         0.0 S    31T   0:57.43   0:05.99 
                    73         0.0 S    31T   0:13.38   0:01.60 
                    73         0.0 S    31T   0:09.00   0:00.96 
                    73         0.0 S    31T   0:02.29   0:00.64 
                    73         0.0 S    31T   0:08.64   0:01.02 
                    73         0.0 S    31T   0:00.01   0:00.00 
                    73         0.0 S    31T   0:00.00   0:00.00 
                    73         0.0 S    31T   0:00.00   0:00.00 
root                74   ??    0.0 S    20T   0:00.05   0:00.02 /usr/bin/some_command with some parameters
                    74         0.0 S    20T   0:00.04   0:00.01 
root                75   ??    0.0 S     4T   0:04.35   0:07.60 /usr/bin/some_command with some parameters
                    75         0.0 S     4T   0:00.00   0:00.00 
                    75         0.0 S     4T   0:00.00   0:00.00 
root                81   ??    0.0 S    20T   0:00.05   0:00.02 /usr/bin/some_command with some parameters
                    81         0.0 S    20T   0:00.05   0:00.01 
root                82   ??    0.0 S     4T   0:06.92   0:05.91 /usr/bin/some_command with some parameters
                    82         0.0 S     4T   0:00.00   0:00.00 
                    82         0.0 S     4T   0:00.00   0:00.00 
root                84   ??    0.0 S    31T   0:04.14   0:02.10 /usr/bin/some_command with some parameters
                    84         0.0 S    31T   0:00.12   0:00.03 
                    84         0.0 S    31T   0:00.25   0:00.13 
                    84         0.0 S    31T   0:00.65   0:00.28 
                    84         0.0 S    31T   0:00.21   0:00.10 
                    84         0.0 S    31T   0:00.33   0:00.18 
                    84         0.0 S    31T   0:00.37   0:00.16 
                    84         0.0 S    31T   0:00.01   0:00.00 
root                86   ??    0.0 S    31T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                    86         0.0 S    37T   0:00.01   0:00.01 
                    86         0.0 S    37T   0:00.00   0:00.00 
root                88   ??    0.0 S    20T   0:10.90   0:10.20 /usr/bin/some_command with some parameters
                    88         0.0 S    20T  24:38.78  20:49.45 
                    88         0.0 S    20T   0:00.00   0:00.00 
                    88         0.0 S    20T   0:00.00   0:00.00 
root                91   ??    0.0 S    31T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                    91         0.0 S    31T   0:00.00   0:00.00 
                    91         0.0 S    31T   0:00.00   0:00.00 
                    91         0.0 S    31T   0:00.00   0:00.00 
root                93   ??    0.0 S    31T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                    93         0.0 S    20T   0:00.01   0:00.01 
                    93         0.0 S    20T   0:00.01   0:00.00 
                    93         0.0 S    20T   0:00.00   0:00.00 
root                99   ??    0.0 S    31T   0:00.04   0:00.01 /usr/bin/some_command with some parameters
                    99         0.0 S    97R   0:00.16   0:00.06 
                    99         0.0 S    31T   0:00.04   0:00.06 
root               103   ??    0.0 S    31T   0:00.15   0:00.09 /usr/bin/some_command with some parameters
                   103         0.0 S    50R   0:24.25   0:09.17 
                   103         0.0 S    31T   0:00.00   0:00.00 
                   103         0.0 S     4T   0:00.03   0:00.02 
                   103         0.0 S    37T   0:00.00   0:00.00 
                   103         0.0 S    20T   0:00.01   0:00.00 
                   103         0.0 S    31T   0:00.00   0:00.00 
                   103         0.0 S    37T   0:00.00   0:00.00 
                   103         0.0 S     4T   0:00.00   0:00.00 
root               104   ??    0.0 S     4T   0:01.01   0:09.28 /usr/bin/some_command with some parameters
                   104         0.0 S     4T   2:14.81   5:02.47 
                   104         0.0 S     4T   0:00.44   0:01.08 
                   104         0.0 S     4T   0:12.12   2:53.73 
                   104         0.0 S     4T   0:00.02   0:00.01 
                   104         0.0 S     4T   0:15.99   0:06.45 
                   104         0.0 S     4T   1:28.59   2:46.98 
                   104         0.0 S     4T   0:04.30   0:12.81 
                   104         0.0 S     4T   0:08.71   0:17.49 
                   104         0.0 S     4T   0:00.00   0:00.00 
                   104         0.0 S     4T   0:59.96   6:08.35 
                   104         0.0 S     4T   0:23.11   0:36.48 
                   104         0.0 S     4T   1:34.48   2:09.53 
                   104         0.0 S     4T   0:00.00   0:00.00 
                   104         0.0 S     4T   0:44.10   0:19.85 
                   104         0.0 S     4T   0:00.52   0:00.17 
                   104         0.0 S     4T   2:14.01   5:01.32 
                   104         0.0 S     4T   2:13.19   5:01.40 
                   104         0.0 S     4T   2:13.78   5:03.91 
                   104         0.0 S     4T   2:15.10   5:04.41 
                   104         0.0 S     4T   2:12.32   5:03.10 
                   104         0.0 S     4T   0:12.37   2:53.81 
                   104         0.0 S     4T   0:12.10   2:53.81 
                   104         0.0 S     4T   2:14.30   5:02.53 
                   104         0.0 S     4T   2:10.42   5:00.82 
                   104         0.0 S     4T   2:14.03   5:02.43 
                   104         0.0 S     4T   2:11.48   5:03.86 
                   104         0.0 S     4T   0:00.00   0:00.00 
                   104         0.0 S     4T   0:00.00   0:00.00 
                   104         0.0 S     4T   0:08.54   0:06.59 
                   104         0.0 S     4T   0:00.00   0:00.00 
                   104         0.0 S     4T   0:00.00   0:00.00 
                   104         0.0 S     4T   0:00.00   0:00.00 
                   104         0.0 S     4T   0:00.00   0:00.00 
                   104         0.0 S     4T   0:05.34   0:01.55 
                   104         0.0 S     4T   0:03.66   0:01.06 
                   104         0.0 S     4T   0:00.18   0:00.03 
                   104         0.0 S     4T   0:37.36   0:06.80 
                   104         0.0 S     4T   0:01.95   0:01.44 
                   104         0.0 S     4T   0:37.35   0:40.82 
                   104         0.0 S     4T   0:12.91   0:09.45 
                   104         0.0 S     4T   0:02.40   0:00.68 
                   104         0.0 S     4T   0:00.00   0:00.00 
                   104         0.0 S     4T   0:08.22   0:07.64 
                   104         0.0 S     4T   0:00.17   0:00.02 
                   104         0.0 S     4T   0:00.00   0:00.00 
                   104         0.0 S     4T   0:00.10   0:00.03 
                   104         0.0 S     4T   0:01.59   0:01.74 
                   104         0.0 S     4T   0:01.66   0:00.43 
                   104         0.0 S     4T   0:00.98   0:00.21 
                   104         0.0 S     4T   0:01.56   0:00.92 
                   104         0.0 S     4T   0:00.02   0:00.00 
                   104         0.0 S     4T   0:00.38   0:00.14 
                   104         0.0 S     4T   0:00.92   0:00.25 
                   104         0.0 S     4T   0:17.54   0:09.81 
                   104         0.0 S     4T   0:05.13   0:01.18 
                   104         0.0 S     4T   0:11.10   1:14.80 
                   104         0.0 S     4T   2:27.08  11:01.59 
                   104         0.0 S     4T   0:00.00   0:00.00 
                   104         0.0 S     4T   0:00.76   0:00.28 
                   104         0.3 S     4T  21:15.35  38:57.00 
                   104         0.0 S     4T   0:01.84   0:00.31 
                   104         0.0 S     4T   0:17.74   0:28.64 
                   104         0.0 S     4T   0:00.00   0:00.00 
                   104         0.0 S     4T   0:00.00   0:00.00 
                   104         0.0 S     4T   0:00.00   0:00.00 
                   104         0.0 S     4T   0:00.00   0:00.00 
                   104         0.0 S     4T   0:00.00   0:00.00 
                   104         0.0 S     4T   0:00.00   0:00.00 
                   104         0.0 S     4T   0:15.35   0:45.24 
                   104         0.0 S     4T   0:00.70   0:00.30 
                   104         0.0 S     4T   0:00.62   0:00.27 
                   104         0.0 S     4T   0:00.64   0:00.31 
                   104         0.0 S     4T   0:00.55   0:00.28 
                   104         0.0 S     4T   0:02.64   0:04.64 
                   104         0.0 S     4T   0:03.42   0:01.28 
                   104         0.0 S     4T   0:05.43   0:02.17 
                   104         0.0 S     4T   0:00.18   0:00.05 
                   104         0.0 S     4T   0:00.00   0:00.00 
                   104         0.0 S     4T   0:00.18   0:00.05 
                   104         0.0 S     4T   0:00.00   0:00.00 
                   104         0.0 S     4T   0:33.60   0:37.38 
                   104         0.0 S     4T   0:24.14   0:08.43 
                   104         0.0 S     4T   2:35.92   4:31.62 
                   104         0.0 S     4T   0:04.54   0:03.01 
                   104         0.0 S     4T   1:29.91   1:00.41 
                   104         0.0 S     4T   0:04.88   0:01.94 
                   104         0.0 S     4T   0:07.19   0:05.44 
                   104         0.0 S     4T   0:02.68   0:00.83 
                   104         0.0 S     4T   0:56.96   1:49.87 
                   104         0.0 S     4T   0:12.03   0:07.99 
                   104         0.0 S     4T   0:15.67   0:12.93 
                   104         0.0 S     4T   0:25.82   1:14.97 
                   104         0.0 S     4T   0:01.66   0:02.08 
                   104         0.0 S     4T   0:08.01   0:40.99 
                   104         0.0 S     4T   0:00.00   0:00.00 
                   104         0.0 S     4T   0:02.42   0:02.15 
                   104         0.0 S     4T   0:00.00   0:00.00 
                   104         0.0 S     4T   0:01.54   0:01.59 
                   104         0.0 S     4T   0:01.13   0:00.29 
                   104         0.0 S     4T   0:02.33   0:00.85 
                   104         0.0 S     4T   0:20.38   0:20.06 
                   104         0.0 S     4T   1:52.14  25:52.43 
                   104         0.0 S     4T   2:07.78   2:26.81 
                   104         0.0 S     4T   4:04.54   4:24.85 
                   104         0.0 S     4T   0:00.01   0:00.00 
                   104         0.0 S     4T   0:00.88   0:02.39 
                   104         0.0 S     4T   0:00.98   0:02.32 
                   104         0.0 S     4T   0:00.83   0:02.10 
                   104         0.3 S     4T   0:00.87   0:02.00 
                   104         0.0 S     4T   0:00.62   0:01.89 
                   104         0.0 S     4T   0:00.24   0:00.51 
                   104         0.0 S     4T   0:00.85   0:04.37 
                   104         0.0 S     4T   0:00.01   0:00.01 
                   104         0.1 S     4T   0:00.11   0:00.17 
                   104         0.0 S     4T   0:00.07   0:00.11 
                   104         0.0 S     4T   0:00.02   0:00.03 
                   104         0.0 S     4T   0:00.01   0:00.01 
                   104         0.0 S     4T   0:00.00   0:00.00 
root               106   ??    0.0 S    31T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                   106         0.0 S    31T   0:00.00   0:00.00 
root               107   ??    0.0 S    31T   0:24.80   0:41.84 /usr/bin/some_command with some parameters
                   107         0.0 S    37T   0:00.00   0:00.00 
root               114   ??    0.0 S    37T   0:00.03   0:00.00 /usr/bin/some_command with some parameters
root               115   ??    0.0 S     4T   0:00.78   0:00.70 /usr/bin/some_command with some parameters
                   115         0.0 S     4T   0:00.00   0:00.01 
                   115         0.0 S     4T   0:00.00   0:00.00 
                   115         0.0 S     4T   0:00.00   0:00.00 
                   115         0.0 S     4T   0:00.01   0:00.02 
root               116   ??    0.0 S    20T   0:00.42   0:00.96 /usr/bin/some_command with some parameters
                   116         0.0 S    31T   0:00.00   0:00.00 
                   116         0.0 S    20T   0:00.00   0:00.00 
                   116         0.0 S    31T   0:00.20   0:00.07 
                   116         0.0 S    31T   0:00.00   0:00.00 
                   116         0.0 S    31T   0:00.00   0:00.00 
                   116         0.0 S    31T   0:00.00   0:00.00 
root               117   ??    0.0 S    31T   0:06.27   0:08.00 /usr/bin/some_command with some parameters
                   117         0.0 S    31T   0:00.00   0:00.00 
                   117         0.0 S    31T   0:00.01   0:00.00 
root               118   ??    0.0 S    20T   0:00.02   0:00.01 /usr/bin/some_command with some parameters
                   118         0.0 S    20T   0:00.22   0:00.11 
                   118         0.0 S    20T   0:00.00   0:00.00 
                   118         0.0 S    20T   0:00.00   0:00.00 
                   118         0.0 S    20T   0:00.00   0:00.00 
                   118         0.0 S    20T   0:00.00   0:00.00 
root               119   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                   119         0.0 S     4T   0:00.00   0:00.00 
                   119         0.0 S     4T   0:00.01   0:00.01 
_timed             120   ??    0.0 S    31T   0:03.13   0:00.61 /usr/bin/some_command with some parameters
                   120         0.0 S     4T   0:00.02   0:00.00 
root               123   ??    0.0 S    31T   0:01.98   0:06.46 /usr/bin/some_command with some parameters
                   123         0.0 S    31T   0:00.17   0:00.03 
                   123         0.0 S    31T   0:00.00   0:00.00 
root               124   ??    0.0 S    20T   0:00.00   0:00.00 auditd -l
                   124         0.0 S    20T   0:00.04   0:00.00 
_locationd         126   ??    0.0 S     4T   0:00.62   0:00.12 /usr/bin/some_command with some parameters
                   126         0.0 S     4T   0:00.04   0:00.05 
                   126         0.0 S     4T   0:00.01   0:00.00 
                   126         0.0 S     4T   0:00.00   0:00.00 
root               128   ??    0.0 S    20T   0:00.00   0:00.00 autofsd
                   128         0.0 S    20T   0:00.00   0:00.00 
_displaypolicyd    129   ??    0.0 S    20T   0:00.43   0:00.05 /usr/bin/some_command with some parameters
                   129         0.0 S    20T   0:00.00   0:00.00 
                   129         0.0 S    20T   0:00.16   0:00.08 
                   129         0.0 S    20T   0:00.93   0:00.02 
                   129         0.0 S    20T   0:00.05   0:00.00 
                   129         0.0 S    20T   0:00.01   0:00.00 
root               132   ??    0.0 S     4T   0:00.05   0:00.06 /usr/bin/some_command with some parameters
                   132         0.0 S     4T   0:00.00   0:00.00 
                   132         0.0 S     4T   0:00.00   0:00.00 
_distnote          135   ??    0.0 S    31T   0:00.01   0:00.03 /usr/bin/some_command with some parameters
                   135         0.0 S    31T   0:00.76   0:01.09 
root               139   ??    0.0 S    20T   0:00.06   0:00.02 /usr/bin/some_command with some parameters
                   139         0.0 S    20T   1:27.75   0:55.96 
                   139         0.0 S    20T   0:04.08   0:00.52 
root               140   ??    0.0 S    31T   0:00.05   0:00.00 /usr/bin/some_command with some parameters
                   140         0.0 S    31T   0:00.00   0:00.00 
root               141   ??    0.0 S     4T   0:00.07   0:00.03 /usr/bin/some_command with some parameters
                   141         0.0 S     4T   0:00.00   0:00.00 
                   141         0.0 S     4T   0:00.00   0:00.00 
root               142   ??    0.0 S    31T   0:00.02   0:00.00 /usr/bin/some_command with some parameters
                   142         0.0 S    31T   0:00.01   0:00.00 
                   142         0.0 S    31T   0:00.00   0:00.00 
root               144   ??    0.0 S    31T   0:19.66   0:16.97 /usr/bin/some_command with some parameters
                   144         0.0 S    31T   0:11.46   0:04.77 
                   144         0.0 S    37T   0:00.03   0:00.01 
root               145   ??    0.0 S    31T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                   145         0.0 S    37T   0:00.08   0:00.04 
root               147   ??    0.0 S    31T   0:00.30   0:00.25 /usr/bin/some_command with some parameters
                   147         0.0 S    31T   0:00.00   0:00.00 
root               148   ??    0.0 S    55R   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                   148         0.0 S    19T   0:00.00   0:00.00 
                   148         0.0 S    31T   0:00.00   0:00.00 
                   148         0.0 S    31T   0:00.01   0:00.00 
root               151   ??    0.0 S    31T   0:00.19   0:00.27 /usr/bin/some_command with some parameters
                   151         0.0 S    31T   0:00.43   0:00.77 
                   151         0.0 S    31T   0:00.01   0:00.00 
root               152   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                   152         0.0 S     4T   0:00.00   0:00.00 
                   152         0.0 S     4T   0:00.00   0:00.00 
root               153   ??    0.0 S    31T   0:04.59   0:02.48 /usr/bin/some_command with some parameters
                   153         0.0 S    31T   0:00.16   0:00.16 
                   153         0.0 S    31T   0:00.07   0:00.01 
                   153         0.0 S    31T   0:00.01   0:00.00 
_analyticsd        156   ??    0.0 S    31T   0:00.23   0:00.16 /usr/bin/some_command with some parameters
                   156         0.0 S    31T   0:00.01   0:00.00 
root               191   ??    0.0 S     4T   0:00.05   0:00.04 /usr/bin/some_command with some parameters
                   191         0.0 S     4T   0:00.00   0:00.01 
                   191         0.0 S     4T   0:00.00   0:00.00 
                   191         0.0 S     4T   0:00.00   0:00.00 
                   191         0.0 S     4T   0:00.00   0:00.00 
root               195   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                   195         0.0 S     4T   0:00.27   0:00.03 
                   195         0.0 S     4T   0:00.03   0:00.06 
root               199   ??    0.0 S    31T   0:00.00   0:00.03 /usr/bin/some_command with some parameters
                   199         0.0 S    31T   0:00.51   0:00.29 
root               206   ??    0.0 S     4T   0:01.29   0:01.82 /usr/bin/some_command with some parameters
                   206         0.0 S     4T   0:00.00   0:00.00 
_trustd            208   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                   208         0.0 S     4T   0:00.00   0:00.00 
_networkd          215   ??    0.0 S     4T   0:01.52   0:00.19 /usr/bin/some_command with some parameters
                   215         0.0 S     4T   0:00.01   0:00.00 
                   215         0.0 S     4T   0:00.00   0:00.00 
_mdnsresponder     232   ??    0.0 S    31T   0:02.58   0:03.05 /usr/bin/some_command with some parameters
                   232         0.0 S    31T   1:14.24   0:37.44 
                   232         0.0 S    37T   0:00.00   0:00.00 
root               248   ??    0.0 S    31T   0:05.23   0:03.32 /usr/bin/some_command with some parameters
                   248         0.0 S    31T   0:00.00   0:00.00 
                   248         0.0 S    37T   0:00.00   0:00.00 
root               250   ??    0.0 S     4T   0:00.14   0:00.05 /usr/bin/some_command with some parameters
                   250         0.0 S     4T   0:00.00   0:00.00 
root               252   ??    0.0 S    31T   0:00.01   0:00.00 /usr/bin/some_command with some parameters
                   252         0.0 S    31T   0:00.00   0:00.00 
root               254   ??    0.0 S    20T   0:00.49   0:00.12 /usr/bin/some_command with some parameters
                   254         0.0 S    20T   0:00.00   0:00.00 
root               255   ??    0.0 S    31T   0:25.65   0:13.33 /usr/bin/some_command with some parameters
                   255         0.0 S    31T   0:00.25   0:00.03 
                   255         0.0 S    31T   0:20.97   0:06.65 
                   255         0.0 S    31T   0:00.00   0:00.00 
                   255         0.0 S    31T   0:02.38   0:01.51 
                   255         0.0 S    31T   0:00.00   0:00.00 
                   255         0.0 S    31T   0:00.00   0:00.00 
                   255         0.0 S    31T   0:00.00   0:00.00 
                   255         0.0 S    31T   0:00.00   0:00.00 
                   255         0.0 S    31T   0:00.00   0:00.00 
                   255         0.0 S    31T   0:00.00   0:00.00 
_coreaudiod        256   ??    0.0 S    63T   0:00.26   0:00.11 /usr/bin/some_command with some parameters
                   256         0.0 S    19T   0:00.00   0:00.00 
                   256         0.0 S    31T   0:00.00   0:00.00 
                   256         0.0 S    31T   0:00.95   0:00.05 
                   256         0.3 S    97R   0:02.08   0:05.95 
                   256         0.3 S    97R   0:02.04   0:05.63 
                   256         0.3 S    61T   0:00.70   0:00.25 
                   256         0.0 S    31T   0:00.00   0:00.00 
                   256         0.8 S    61R   0:00.40   0:00.27 
_nsurlsessiond     257   ??    0.0 S     4T   0:00.38   0:00.15 /usr/bin/some_command with some parameters
                   257         0.0 S     4T   0:00.00   0:00.00 
root               263   ??    0.0 S     4T   0:00.69   0:00.11 /usr/bin/some_command with some parameters
                   263         0.0 S     4T   0:00.01   0:00.00 
                   263         0.0 S     4T   0:00.00   0:00.00 
_cmiodalassistants   264   ??    0.0 S    31T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                   264         1.1 S    97R   2:00.26   4:45.36 
                   264         0.1 S    31T   0:01.94   0:01.28 
                   264         0.0 S    31T   0:00.00   0:00.00 
root               269   ??    0.0 S    20T   1:55.12   1:38.27 /usr/bin/some_command with some parameters
                   269         0.0 S    20T   0:00.94   0:00.31 
                   269         0.0 S    20T   0:00.00   0:00.00 
_coreaudiod        271   ??    0.0 S    31T   0:00.00   0:00.03 /usr/bin/some_command with some parameters
                   271         0.0 S    31T   0:00.52   0:00.21 
root               272   ??    0.0 S     4T   0:00.06   0:00.01 /usr/bin/some_command with some parameters
                   272         0.0 S     4T   0:00.00   0:00.00 
_locationd         279   ??    0.0 S    31T   0:00.00   0:00.03 /usr/bin/some_command with some parameters
                   279         0.0 S    31T   0:00.56   0:00.26 
root               300   ??    0.0 S     4T   0:00.05   0:00.01 /usr/bin/some_command with some parameters
                   300         0.0 S     4T   0:00.07   0:00.01 
_softwareupdate    307   ??    0.0 S    31T   0:00.00   0:00.03 /usr/bin/some_command with some parameters
                   307         0.0 S    31T   0:00.54   0:00.21 
root               313   ??    0.0 S    31T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                   313         0.0 S    31T   0:00.00   0:00.00 
root               322   ??    0.0 S    20T   0:00.03   0:00.03 /usr/bin/some_command with some parameters
                   322         0.0 S    20T   0:00.00   0:00.00 
                   322         0.0 S    20T   0:00.00   0:00.00 
root               337   ??    0.0 S     4T   0:00.08   0:00.03 /usr/bin/some_command with some parameters
                   337         0.0 S     4T   0:00.00   0:00.00 
root               397   ??    0.0 S    31T   0:14.02   0:12.57 /usr/bin/some_command with some parameters
                   397         0.0 S    31T   0:00.00   0:00.00 
                   397         0.0 S    31T   0:00.00   0:00.00 
                   397         0.0 S    31T   1:32.16   7:28.27 
                   397         0.0 R    31T   1:32.29   7:28.11 
                   397         0.0 S    31T   1:33.32   7:28.98 
                   397         0.0 S    31T   1:32.30   7:28.34 
                   397         0.0 S    31T   1:32.30   7:28.44 
                   397         0.0 S    31T   1:32.33   7:27.11 
                   397         0.0 S    31T   0:10.06   0:22.50 
                   397         0.0 S    31T   0:00.25   0:01.70 
                   397         0.0 S    31T   2:20.84   5:59.52 
                   397         0.0 S    31T   0:00.29   0:00.12 
                   397         0.0 S    31T   5:05.54   5:08.26 
                   397         0.0 S     4T   0:00.16   0:00.34 
                   397         0.0 S    31T   0:00.04   0:00.02 
                   397         0.0 S    31T   0:43.11   1:10.88 
                   397         0.0 S    31T   0:00.72   0:00.56 
                   397         0.0 S    31T   0:13.98   0:26.76 
                   397         0.0 S    31T   0:01.40   0:01.34 
                   397         0.0 S    31T   0:02.07   0:01.84 
                   397         0.0 S    31T   0:00.59   0:00.76 
                   397         0.0 S    31T   0:00.37   0:00.67 
                   397         0.0 S    31T   0:00.15   0:00.13 
                   397         0.0 S    31T   0:00.02   0:00.02 
                   397         0.0 R    54R   0:00.01   0:00.02 
                   397         0.0 S    31T   0:00.03   0:00.01 
_nsurlsessiond     398   ??    0.0 S    31T   0:00.00   0:00.02 /usr/bin/some_command with some parameters
                   398         0.0 S    31T   0:00.53   0:00.21 
root               419   ??    0.0 S    31T   0:00.71   0:00.84 /usr/bin/some_command with some parameters
                   419         0.0 S    31T   0:00.00   0:00.00 
                   419         0.0 S     4T   0:00.00   0:00.00 
                   419         0.0 S     4T   0:00.01   0:00.00 
                   419         0.0 S    31T   0:00.01   0:00.01 
                   419         0.0 S    37T   0:00.00   0:00.00 
                   419         0.0 S     4T   0:00.00   0:00.00 
                   419         0.0 S     4T   0:00.00   0:00.00 
                   419         0.0 S     4T   0:00.00   0:00.00 
                   419         0.0 S     4T   0:00.00   0:00.00 
                   419         0.0 S     4T   0:00.00   0:00.00 
                   419         0.0 S     4T   0:00.00   0:00.01 
                   419         0.0 S    31T   0:00.00   0:00.00 
_driverkit         422   ??    0.0 S    31T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                   422         0.0 S    63R   0:00.09   0:00.03 
_driverkit         423   ??    0.0 S    31T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                   423         0.0 S    63R   0:00.00   0:00.00 
_driverkit         425   ??    0.0 S    63R   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                   425         0.0 S    31T   0:00.00   0:00.00 
_driverkit         427   ??    0.0 S    31T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                   427         0.0 S    63R   0:03.41   0:01.46 
_driverkit         428   ??    0.0 S    63R   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                   428         0.0 S    31T   0:00.00   0:00.00 
_driverkit         430   ??    0.0 S    31T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                   430         0.0 S    63R   0:00.00   0:00.00 
_driverkit         432   ??    0.0 S    63R   0:00.94   0:00.30 /usr/bin/some_command with some parameters
                   432         0.0 S    31T   0:00.00   0:00.00 
_driverkit         434   ??    0.0 S    63R   0:00.04   0:00.02 /usr/bin/some_command with some parameters
                   434         0.0 S    31T   0:00.00   0:00.00 
_driverkit         435   ??    0.0 S    63R   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                   435         0.0 S    31T   0:00.00   0:00.00 
_spotlight         437   ??    0.0 S    31T   0:00.00   0:00.02 /usr/bin/some_command with some parameters
                   437         0.0 S    31T   0:00.13   0:00.08 
root               460   ??    0.0 S    63R   0:00.88   0:00.12 /usr/bin/some_command with some parameters
                   460         0.0 S    31T   0:00.00   0:00.00 
_windowserver      474   ??    0.0 S    31T   0:00.00   0:00.02 /usr/bin/some_command with some parameters
                   474         0.0 S    31T   0:00.52   0:00.20 
_appinstalld       481   ??    0.0 S    31T   0:00.01   0:00.03 /usr/bin/some_command with some parameters
                   481         0.0 S    31T   0:00.50   0:00.19 
root               492   ??    0.0 S    51R   0:17.61   0:22.47 /usr/bin/some_command with some parameters
                   492         0.1 S    55R   4:03.41   2:28.94 
                   492         0.0 S    37T   0:03.98   0:03.88 
                   492         0.0 S    51T   0:00.00   0:00.00 
                   492         0.0 S    37T   0:00.00   0:00.00 
                   492         0.0 S    31T   0:00.00   0:00.00 
                   492         0.0 S    51R   0:00.00   0:00.00 
_appleevents       501   ??    0.0 S    31T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                   501         0.0 S    31T   0:00.00   0:00.00 
root               503   ??    0.0 S    31T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                   503         0.0 S     4T   0:00.00   0:00.00 
root               508   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                   508        23.4 S     4T   0:06.35   0:01.50 
                   508         0.0 S     4T   0:00.60   0:00.14 
root               515   ??    0.0 S     4T   0:00.12   0:00.03 /usr/bin/some_command with some parameters
                   515         0.0 S     4T   0:00.00   0:00.00 
                   515         0.0 S     4T   0:00.00   0:00.00 
root               528   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                   528         0.0 S     4T   0:00.00   0:00.00 
_appleevents       541   ??    0.0 S    31T   0:00.01   0:00.02 /usr/bin/some_command with some parameters
                   541         0.0 S    31T   0:00.50   0:00.19 
root               555   ??    0.0 S     4T   0:00.04   0:00.01 /usr/bin/some_command with some parameters
                   555         0.0 S     4T   0:00.00   0:00.00 
someuser       558   ??    0.0 S    31T   0:00.01   0:00.03 /usr/bin/some_command with some parameters
                   558         0.0 S    20T   0:00.86   0:01.75 
root               583   ??    0.0 S     4T   0:00.06   0:00.01 /usr/bin/some_command with some parameters
                   583         0.0 S     4T   0:00.00   0:00.00 
root               631   ??    0.0 S    20T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                   631         0.0 S    20T   0:00.01   0:00.00 
someuser       638   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                   638         0.0 S     4T   0:00.01   0:00.00 
                   638         0.0 S     4T   0:00.00   0:00.00 
someuser       673   ??    0.0 S    47T   0:10.83   0:08.96 /usr/bin/some_command with some parameters
                   673         0.0 S    19T   0:00.00   0:00.00 
                   673         0.0 S    31T   0:00.00   0:00.00 
                   673         0.0 S    37T   0:00.00   0:00.00 
_windowserver      677   ??   26.8 S    79R 100:32.78 206:51.42 /usr/bin/some_command with some parameters
                   677         2.8 S    79R  42:18.54  27:27.26 
                   677         0.0 S    37T   0:00.00   0:00.00 
                   677         0.0 S    79R   0:00.00   0:00.00 
                   677         0.0 S    31T   0:00.01   0:00.00 
                   677         0.0 S    31T   0:00.16   0:00.20 
                   677         0.0 S    31T   0:28.55   0:11.03 
                   677         1.7 U    31T   0:23.73   0:19.24 
                   677         1.9 S    31T   0:14.59   0:11.88 
                   677         0.0 S    79R   0:13.48   0:11.02 
                   677         0.6 S    79R   0:01.43   0:00.84 
                   677         0.2 S    79T   0:04.30   0:03.51 
                   677        21.0 S    79T   0:04.35   0:03.53 
                   677         1.2 S    79R   0:00.53   0:00.29 
                   677         0.0 S    31T   0:00.00   0:00.00 
                   677         1.2 S    79R   0:00.09   0:00.05 
_securityagent     735   ??    0.0 S    31T   0:00.00   0:00.02 /usr/bin/some_command with some parameters
                   735         0.0 S    31T   0:00.47   0:00.18 
root               762   ??    0.0 S     4T   0:00.01   0:00.03 /usr/bin/some_command with some parameters
                   762         0.0 S     4T   0:00.01   0:00.00 
root               860   ??    0.0 S    31T   0:01.12   0:01.52 /usr/bin/some_command with some parameters
                   860         0.0 S    31T   0:00.58   0:00.39 
                   860         0.0 S    31T   0:00.00   0:00.01 
someuser       978   ??    0.0 S    31T   0:03.65   0:02.88 /usr/bin/some_command with some parameters
                   978         0.0 S    31T   0:00.00   0:00.00 
                   978         0.0 S     0T   0:00.02   0:00.02 
                   978         0.0 S    31T   0:00.13   0:00.06 
                   978         0.0 S    31T   0:00.00   0:00.00 
                   978         0.0 S    31T   0:00.00   0:00.00 
                   978         0.0 S    31T   0:00.00   0:00.00 
                   978         0.0 S    31T   0:00.00   0:00.00 
                   978         0.0 S    31T   0:00.00   0:00.00 
                   978         0.0 S    31T   0:00.00   0:00.00 
                   978         0.0 S    31T   0:00.00   0:00.00 
                   978         0.0 S    31T   0:00.00   0:00.00 
                   978         0.0 S    31T   0:00.10   0:00.02 
                   978         0.0 S    31T   0:00.02   0:00.00 
                   978         0.0 S    31T   0:00.01   0:00.00 
someuser      2054   ??    0.0 S     4T   0:01.04   0:01.49 /usr/bin/some_command with some parameters
                  2054         0.0 S     4T   0:00.01   0:00.00 
                  2054         0.0 S     4T   0:00.00   0:00.00 
someuser      2059   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                  2059         0.0 S     4T   0:00.01   0:00.01 
                  2059         0.0 S     4T   0:00.00   0:00.00 
_appstore         2142   ??    0.0 S    31T   0:00.01   0:00.02 /usr/bin/some_command with some parameters
                  2142         0.0 S    31T   0:00.46   0:00.18 
_assetcache       2155   ??    0.0 S    31T   0:00.00   0:00.03 /usr/bin/some_command with some parameters
                  2155         0.0 S    31T   0:00.45   0:00.18 
someuser      2156   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                  2156         0.0 S     4T   0:00.00   0:00.00 
_spotlight        2157   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                  2157         0.0 S     4T   0:00.00   0:00.00 
_spotlight        2165   ??    0.0 S     4T   0:00.01   0:00.03 /usr/bin/some_command with some parameters
                  2165         0.0 S     4T   0:00.00   0:00.00 
someuser      2316   ??    0.0 S    31T   0:04.73   0:05.82 /usr/bin/some_command with some parameters
                  2316         0.0 S    20T   0:00.00   0:00.00 
someuser      2324   ??    0.0 S    31T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                  2324         0.0 S    37T   0:00.00   0:00.00 
                  2324         0.0 S    37T   0:00.00   0:00.00 
someuser      2325   ??    0.0 S    31T   0:00.52   0:00.11 /usr/bin/some_command with some parameters
                  2325         0.0 S    31T   0:00.00   0:00.00 
                  2325         0.0 S    31T   0:00.00   0:00.00 
                  2325         0.0 S    31T   0:00.05   0:00.00 
                  2325         0.0 S    20T   0:00.00   0:00.00 
                  2325         0.0 S    20T   0:00.00   0:00.00 
someuser      2328   ??    0.0 S     4T   0:01.96   0:01.06 /usr/bin/some_command with some parameters
                  2328         0.0 S     4T   0:00.04   0:00.01 
                  2328         0.0 S     4T   0:00.00   0:00.00 
                  2328         0.0 S     4T   0:00.00   0:00.00 
                  2328         0.0 S     4T   0:00.00   0:00.00 
someuser      2329   ??    0.0 S    31T   0:01.99   0:00.36 /usr/bin/some_command with some parameters
                  2329         0.0 S    31T   0:00.00   0:00.00 
someuser      2330   ??    0.0 S    31T   0:22.30   1:25.11 /usr/bin/some_command with some parameters
                  2330         0.0 S    19T   0:00.00   0:00.00 
                  2330         0.0 S    31T   0:00.31   0:00.10 
                  2330         0.0 S    31T   0:00.00   0:00.00 
                  2330         0.0 S    31T   0:00.00   0:00.00 
                  2330         0.0 S    31T   0:00.00   0:00.00 
                  2330         0.0 S    31T   0:00.00   0:00.00 
someuser      2331   ??    0.0 S    31T   0:00.06   0:00.04 /usr/bin/some_command with some parameters
                  2331         0.0 S    37T   0:00.00   0:00.00 
someuser      2332   ??    0.0 S    31T   0:00.71   0:00.34 /usr/bin/some_command with some parameters
                  2332         0.0 S    31T   0:00.02   0:00.00 
                  2332         0.0 S    31T   0:00.00   0:00.00 
someuser      2334   ??    0.0 S    31T   0:02.77   0:01.40 /usr/bin/some_command with some parameters
                  2334         0.0 S    31T   0:00.01   0:00.00 
                  2334         0.0 S    37T   0:00.31   0:00.09 
                  2334         0.0 S    31T   0:00.00   0:00.00 
                  2334         0.0 S    37T   0:00.00   0:00.00 
someuser      2348   ??    0.0 S    31T   0:02.24   0:00.66 /usr/bin/some_command with some parameters
                  2348         0.0 S    31T   0:00.07   0:00.01 
                  2348         0.0 S    31T   0:00.00   0:00.00 
                  2348         0.0 S    31T   0:00.00   0:00.00 
                  2348         0.0 S    31T   0:00.00   0:00.00 
                  2348         0.0 S    31T   0:00.00   0:00.00 
someuser      2349   ??    0.0 S    31T   0:01.18   0:00.45 /usr/bin/some_command with some parameters
                  2349         0.0 S    37T   0:00.00   0:00.00 
someuser      2350   ??    0.0 S    46T   0:14.08   0:12.57 /usr/bin/some_command with some parameters
                  2350         0.0 S    46T   0:00.00   0:00.00 
                  2350         0.0 S    46T   0:00.59   0:00.20 
                  2350         0.0 S    46T   0:00.00   0:00.00 
someuser      2361   ??    0.0 S    31T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                  2361         0.0 S    37T   0:00.02   0:00.00 
someuser      2363   ??    0.0 S    31T   0:00.11   0:00.11 /usr/bin/some_command with some parameters
                  2363         0.0 S    31T   0:00.00   0:00.00 
                  2363         0.0 S    31T   0:00.00   0:00.00 
someuser      2364   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                  2364         0.0 S     4T   0:00.05   0:00.07 
someuser      2367   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                  2367         0.0 S     4T   0:00.00   0:00.00 
someuser      2369   ??    0.0 S     4T   0:05.78   0:05.65 /usr/bin/some_command with some parameters
                  2369         0.0 S     4T   0:00.98   0:00.44 
                  2369         0.0 S     4T   0:00.00   0:00.00 
                  2369         0.0 S     4T   0:00.00   0:00.00 
someuser      2371   ??    0.0 S     4T   0:12.60   0:13.23 /usr/bin/some_command with some parameters
                  2371         0.0 S     4T   0:00.00   0:00.00 
                  2371         0.0 S     4T   0:00.00   0:00.00 
                  2371         0.0 S     4T   0:00.00   0:00.00 
                  2371         0.0 S     4T   0:00.00   0:00.00 
                  2371         0.0 S     4T   0:00.00   0:00.00 
someuser      2383   ??    0.0 S    31T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                  2383         0.0 S    31T   0:00.00   0:00.00 
someuser      2389   ??    0.0 S    31T   0:00.23   0:00.08 /usr/bin/some_command with some parameters
                  2389         0.0 S    31T   0:00.00   0:00.00 
                  2389         0.0 S    31T   0:00.13   0:00.05 
someuser      2391   ??    0.0 S    31T   0:00.99   0:00.22 /usr/bin/some_command with some parameters
                  2391         0.0 S     4T   0:00.00   0:00.00 
someuser      2397   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                  2397         0.0 S     4T   0:00.00   0:00.00 
someuser      2399   ??    0.0 S    46T   0:14.24   0:30.95 /usr/bin/some_command with some parameters
                  2399         0.0 S    46T   0:01.32   0:00.87 
                  2399         0.0 S    37T   0:00.00   0:00.00 
                  2399         0.0 S    46T   0:00.00   0:00.00 
root              2402   ??    0.0 S    31T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                  2402         0.0 S    31T   0:00.00   0:00.00 
someuser      2411   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                  2411         0.0 S     4T   0:00.02   0:00.01 
                  2411         0.0 S     4T   0:00.00   0:00.00 
someuser      2412   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                  2412         0.0 S     4T   0:00.00   0:00.00 
                  2412         0.0 S     4T   0:00.00   0:00.00 
someuser      2414   ??    0.0 S     4T   0:04.02   0:01.69 /usr/bin/some_command with some parameters
                  2414         0.0 S     4T   0:00.56   0:00.10 
                  2414         0.0 S     4T   0:00.00   0:00.00 
                  2414         0.0 S     4T   0:00.00   0:00.00 
someuser      2417   ??    0.0 S    31T   0:00.80   0:00.29 /usr/bin/some_command with some parameters
                  2417         0.0 S    31T   0:00.00   0:00.00 
                  2417         0.0 S    31T   0:00.00   0:00.00 
someuser      2420   ??    0.0 S     4T   0:05.78   0:05.41 /usr/bin/some_command with some parameters
                  2420         0.0 S     4T   0:00.00   0:00.00 
                  2420         0.0 S     4T   0:00.00   0:00.00 
someuser      2421   ??    0.0 S    31T   0:00.03   0:00.01 /usr/bin/some_command with some parameters
                  2421         0.0 S    31T   0:00.00   0:00.00 
someuser      2425   ??    0.0 S    31T   0:18.03   0:12.80 /usr/bin/some_command with some parameters
                  2425         0.0 S    31T   0:13.33   0:05.22 
                  2425         0.0 S    31T   0:00.02   0:00.00 
someuser      2430   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                  2430         0.0 S     4T   0:00.03   0:00.01 
                  2430         0.0 S     4T   0:00.00   0:00.00 
someuser      2441   ??    0.0 S     4T   0:00.11   0:00.04 /usr/bin/some_command with some parameters
                  2441         0.0 S     4T   0:00.00   0:00.00 
                  2441         0.0 S     4T   0:00.00   0:00.00 
someuser      2448   ??    0.0 S     4T   0:00.02   0:00.04 /usr/bin/some_command with some parameters
                  2448         0.0 S     4T   0:00.01   0:00.00 
_reportmemoryexception  2456   ??    0.0 S    31T   0:00.01   0:00.03 /usr/bin/some_command with some parameters
                  2456         0.0 S    31T   0:00.44   0:00.17 
root              2458   ??    0.0 S     4T   0:00.01   0:00.00 /usr/bin/some_command with some parameters
                  2458         0.0 S     4T   0:00.00   0:00.00 
_applepay         2478   ??    0.0 S    31T   0:00.00   0:00.02 /usr/bin/some_command with some parameters
                  2478         0.0 S    31T   0:00.44   0:00.17 
_fpsd             2532   ??    0.0 S    31T   0:00.01   0:00.02 /usr/bin/some_command with some parameters
                  2532         0.0 S    31T   0:01.16   0:00.47 
666               2555   ??    0.0 S    31T   0:00.00   0:00.02 /usr/bin/some_command with some parameters
                  2555         0.0 S    31T   0:00.11   0:00.08 
newrelic          2556   ??    0.0 S    31T   0:00.00   0:00.02 /usr/bin/some_command with some parameters
                  2556         0.0 S    31T   0:00.10   0:00.08 
newrelic          2730   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                  2730         0.0 S     4T   0:00.00   0:00.00 
666               2731   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                  2731         0.0 S     4T   0:00.00   0:00.00 
666               2736   ??    0.0 S     4T   0:01.24   0:01.51 /usr/bin/some_command with some parameters
                  2736         0.0 S     4T   0:00.03   0:00.00 
newrelic          2737   ??    0.0 S     4T   0:01.24   0:01.51 /usr/bin/some_command with some parameters
                  2737         0.0 S     4T   0:00.03   0:00.00 
someuser      2827   ??    3.6 S    47T   3:24.32  12:09.34 /usr/bin/some_command with some parameters
                  2827         0.0 S    47T   0:36.63   0:21.76 
                  2827         0.0 S    31T   0:04.50   0:05.66 
                  2827         0.6 S    47T   0:00.03   0:00.08 
                  2827         0.1 S    47T   0:00.15   0:00.10 
                  2827         0.0 S    37T   0:00.02   0:00.07 
                  2827         0.0 S    47T   0:00.03   0:00.08 
                  2827         0.2 S    47T   0:00.02   0:00.06 
                  2827         0.2 S    37T   0:00.03   0:00.08 
                  2827         0.3 S    37T   0:00.08   0:00.26 
                  2827         0.0 S    31T   0:00.00   0:00.00 
                  2827         0.0 S    31T   0:00.00   0:00.00 
someuser      2828   ??    0.0 S    46T  16:03.60  66:28.44 /usr/bin/some_command with some parameters
                  2828         0.0 S    31T   0:00.00   0:00.00 
                  2828         0.0 S    31T   0:00.46   0:00.34 
                  2828         0.0 S    31T   0:00.92   0:01.03 
                  2828         0.0 S    31T  10:41.96  10:41.22 
                  2828         0.0 S    31T   0:07.12   0:19.95 
                  2828         0.0 S    31T   0:00.08   0:00.02 
                  2828         0.0 S    31T   0:00.00   0:00.00 
                  2828         0.0 S    31T   0:00.01   0:00.00 
                  2828         0.0 S    31T   0:10.27   0:00.81 
                  2828         0.0 S    31T   0:25.33   2:56.06 
                  2828         0.0 S    31T   0:00.00   0:00.00 
                  2828         0.0 S     0T   0:00.00   0:00.00 
                  2828         0.0 S    31T   0:00.01   0:00.00 
                  2828         0.0 S    31T   0:00.28   0:00.22 
                  2828         0.0 S    31T   0:00.24   0:00.14 
                  2828         0.0 S    46T   0:00.06   0:00.02 
                  2828         0.0 S    46T   3:19.50   2:30.69 
                  2828         0.0 S    31T   0:01.52   0:01.64 
                  2828         0.0 S    31T   0:00.01   0:00.00 
                  2828         0.0 S    31T   0:00.31   0:00.05 
                  2828         0.0 S    31T   0:00.22   0:00.05 
                  2828         0.0 S    19T   0:00.00   0:00.00 
                  2828         0.0 S    31T   0:00.03   0:00.01 
                  2828         0.0 S    31T   0:01.38   0:00.91 
                  2828         0.0 S    31T   0:00.01   0:00.00 
                  2828         0.0 S    31T   0:00.01   0:00.00 
                  2828         0.0 S    31T   0:00.01   0:00.00 
                  2828         0.0 S    31T   0:00.01   0:00.00 
                  2828         0.0 S    31T   0:00.01   0:00.00 
                  2828         0.0 S    31T   0:00.02   0:00.00 
                  2828         0.0 S    31T   0:00.01   0:00.00 
                  2828         0.0 S    31T   0:00.13   0:00.15 
                  2828         0.0 S    31T   0:00.01   0:00.00 
                  2828         0.0 S     0T   0:00.00   0:00.00 
                  2828         0.0 S    31T   0:00.00   0:00.00 
                  2828         0.0 S    31T   0:00.00   0:00.00 
someuser      2832   ??    0.2 S    46T   2:47.01   8:47.93 /usr/bin/some_command with some parameters
                  2832         0.0 S    31T   0:02.83   0:02.86 
                  2832         0.0 S     0T   0:00.16   0:00.11 
                  2832         0.2 S    31T   1:48.95   1:18.65 
                  2832         0.0 S    31T   0:00.00   0:00.00 
                  2832         0.0 S    31T   0:00.00   0:00.00 
                  2832         0.0 S    31T   0:04.27   0:09.82 
                  2832         0.0 S    31T   0:03.52   0:09.53 
                  2832         0.0 S    31T   0:06.21   0:11.86 
                  2832         0.0 S    31T   0:00.00   0:00.00 
                  2832         0.0 S    31T   0:01.21   0:00.11 
                  2832         0.0 S    31T   0:01.20   0:00.11 
                  2832         0.0 S    31T   0:01.21   0:00.11 
                  2832         0.0 S    31T   0:01.21   0:00.11 
                  2832         0.0 S    31T   0:00.00   0:00.00 
                  2832         0.0 S    31T   0:00.09   0:00.02 
                  2832         0.0 S    31T   0:00.00   0:00.00 
                  2832         0.0 S    31T   0:00.01   0:00.00 
                  2832         0.0 S    31T   0:00.01   0:00.00 
                  2832         0.0 S    31T   0:00.03   0:00.02 
                  2832         0.0 S    31T   0:09.04   0:02.71 
                  2832         0.0 S    31T   0:00.02   0:00.00 
                  2832         0.0 S    46T   0:53.22   0:30.59 
                  2832         0.0 S    31T   0:00.00   0:00.00 
                  2832         0.0 S    31T   0:00.37   0:00.41 
                  2832         0.0 S     0T   0:00.00   0:00.00 
                  2832         0.0 S    31T   0:00.00   0:00.00 
                  2832         0.0 S    31T   0:00.05   0:00.02 
                  2832         0.0 S    31T   0:00.03   0:00.01 
                  2832         0.0 S    31T   0:00.00   0:00.00 
                  2832         0.0 S    31T   0:00.00   0:00.00 
someuser      2834   ??    0.0 S    46T   1:31.25   3:58.95 /usr/bin/some_command with some parameters
                  2834         0.0 S    31T   0:07.01   0:12.77 
                  2834         0.0 S     0T   0:00.12   0:00.11 
                  2834         0.0 S    31T   1:24.23   1:37.63 
                  2834         0.0 S    31T   0:00.02   0:00.01 
                  2834         0.0 S    31T   0:00.00   0:00.00 
                  2834         0.0 S    31T   0:00.98   0:00.66 
                  2834         0.0 S    31T   0:00.87   0:00.73 
                  2834         0.0 S    31T   0:00.98   0:00.75 
                  2834         0.0 S    31T   0:00.00   0:00.00 
                  2834         0.0 S    31T   0:00.00   0:00.00 
                  2834         0.0 S    31T   0:00.11   0:00.04 
                  2834         0.0 S    31T   0:00.00   0:00.00 
                  2834         0.0 S    31T   0:00.03   0:00.02 
                  2834         0.0 S    31T   0:00.01   0:00.00 
                  2834         0.0 S    31T   0:00.02   0:00.00 
                  2834         0.0 S    31T   0:05.78   0:01.83 
                  2834         0.0 S    31T   0:00.04   0:00.02 
                  2834         0.0 S    31T   0:01.42   0:00.09 
                  2834         0.0 S    31T   0:01.47   0:00.09 
                  2834         0.0 S    31T   0:01.44   0:00.09 
                  2834         0.0 S    31T   0:01.45   0:00.09 
                  2834         0.0 S    46T   0:34.34   0:22.84 
                  2834         0.0 S    31T   0:00.03   0:00.02 
                  2834         0.0 S     0T   0:00.00   0:00.00 
                  2834         0.0 S    31T   0:00.26   0:00.42 
                  2834         0.0 S    31T   0:17.54   0:11.36 
                  2834         0.0 S    31T   0:10.92   0:07.12 
                  2834         0.0 S    37T   0:00.00   0:00.00 
someuser      2836   ??    0.0 S    28T   1:13.22   2:38.49 /usr/bin/some_command with some parameters
                  2836         0.0 S    28T   0:00.00   0:00.00 
                  2836         0.0 S    28T   0:00.23   0:00.26 
                  2836         0.0 S     0T   0:00.97   0:00.65 
                  2836         0.0 S    28T   0:41.17   0:53.42 
                  2836         0.0 S    28T   0:00.04   0:00.03 
                  2836         0.0 S    28T   0:00.10   0:00.04 
                  2836         0.0 S    28T   0:00.03   0:00.02 
                  2836         0.0 S    28T   0:00.00   0:00.00 
                  2836         0.0 S    28T   0:00.27   0:00.03 
                  2836         0.0 S     0T   0:00.73   0:02.01 
                  2836         0.0 S    28T   0:00.03   0:00.10 
                  2836         0.0 S    28T   2:59.40   5:19.92 
                  2836         0.0 S    28T   0:05.51   0:16.63 
                  2836         0.0 S    28T   0:00.00   0:00.00 
                  2836         0.0 S    28T   0:01.00   0:01.60 
                  2836         0.0 S    28T   0:00.01   0:00.01 
                  2836         0.0 S    28T   1:31.26   4:01.24 
                  2836         0.0 S    28T   0:00.03   0:00.01 
                  2836         0.0 S    28T   0:00.00   0:00.00 
                  2836         0.0 S    28T   0:01.24   0:00.39 
                  2836         0.0 S    28T   2:58.51   0:48.56 
                  2836         0.0 S    28T   0:00.63   0:00.03 
                  2836         0.0 S    28T   0:50.04   1:15.25 
                  2836         0.0 S    28T   0:00.35   0:00.08 
                  2836         0.0 S    28T   0:03.12   0:00.91 
                  2836         0.0 S    28T   0:01.97   0:00.30 
                  2836         0.0 S    28T   0:00.06   0:00.01 
                  2836         0.0 S    28T   0:00.04   0:00.01 
                  2836         0.0 S    28T   0:02.95   0:00.93 
                  2836         0.0 S    28T   0:04.52   0:01.20 
                  2836         0.0 S    28T   0:01.26   0:00.90 
                  2836         0.0 S    28T   0:35.10   0:24.68 
                  2836         0.0 S    28T   0:00.04   0:00.02 
                  2836         0.0 S    28T   0:28.24   0:16.75 
                  2836         0.0 S    28T   0:05.82   0:01.66 
                  2836         0.0 S    28T   0:00.31   0:00.46 
                  2836         0.0 S    28T   0:00.05   0:00.01 
                  2836         0.0 S    28T   0:00.04   0:00.02 
                  2836         0.0 S    19T   0:00.00   0:00.00 
                  2836         0.0 S    28T   0:18.64   2:15.96 
                  2836         0.0 S    28T   0:00.02   0:00.01 
                  2836         0.0 S    28T   0:00.00   0:00.00 
                  2836         0.0 S    28T   0:00.00   0:00.00 
someuser      2838   ??    1.6 S    46T  17:08.54  22:01.14 /usr/bin/some_command with some parameters
                  2838         0.0 S    31T   0:01.57   0:00.80 
                  2838         0.0 S    31T   0:00.00   0:00.00 
                  2838         0.0 S    31T   0:03.78   0:01.50 
                  2838         0.0 S    31T   0:10.84   0:06.58 
                  2838         0.1 S    31T   1:18.21   0:15.73 
                  2838         0.1 S    31T   1:17.68   0:15.27 
                  2838         0.1 S    31T   1:17.53   0:14.74 
                  2838         0.0 S    31T   0:01.98   0:00.98 
                  2838         0.0 S    31T   0:09.71   0:06.75 
                  2838         0.1 S    31T   1:19.00   0:17.83 
                  2838         0.0 S    46T   2:51.36   1:51.45 
                  2838         0.0 S    31T   0:48.84   1:23.12 
                  2838         0.0 S    31T   0:08.61   0:03.85 
                  2838         1.2 S    31T   6:48.39   2:04.46 
                  2838         0.0 S    19T   0:00.00   0:00.00 
                  2838         0.0 S    31T   0:00.00   0:00.00 
                  2838         0.1 S    31T   0:58.76   0:08.79 
                  2838         0.1 S    31T   0:58.62   0:08.80 
                  2838         0.1 S    31T   0:56.48   0:09.06 
                  2838         0.1 S    31T   0:09.79   0:01.50 
                  2838         0.1 S    31T   0:03.29   0:00.54 
                  2838         0.1 S    31T   0:03.26   0:00.56 
                  2838         0.1 S    31T   0:03.28   0:00.56 
                  2838         0.0 S    31T   0:00.03   0:00.02 
                  2838         0.7 S    31T   0:07.26   0:09.31 
                  2838         0.1 S    31T   0:03.25   0:00.47 
                  2838         0.0 S    31R   0:00.16   0:00.13 
                  2838         7.0 S    46R   0:03.09   2:03.34 
                  2838         8.4 S    31T   0:03.83   1:56.14 
                  2838         2.2 S    31T   0:07.17   0:37.92 
                  2838         0.4 S    57T   0:01.45   0:06.86 
                  2838         1.8 S    31T   0:34.69   0:11.36 
                  2838         0.0 S    31T   0:00.58   0:00.89 
                  2838         0.5 S    31T   0:01.81   0:19.41 
                  2838         6.7 S    46R   0:09.32   1:57.44 
                  2838         0.0 S    97R   0:00.96   0:00.84 
                  2838         0.7 S    46R   0:00.63   0:13.44 
                  2838         0.1 S    97R   0:00.94   0:02.07 
                  2838         0.1 S    31T   0:00.33   0:05.60 
                  2838         4.1 S    31T   0:02.02   0:51.42 
                  2838         4.0 S    31T   0:02.02   0:51.34 
                  2838         4.0 S    31T   0:02.02   0:51.43 
                  2838         4.0 S    31T   0:02.01   0:51.39 
                  2838         4.0 S    31T   0:02.02   0:51.36 
                  2838         0.0 S    31T   0:00.04   0:00.03 
                  2838         0.0 S    31T   0:00.63   0:16.54 
                  2838         0.0 S    31T   0:00.63   0:16.53 
                  2838         0.4 S    31T   0:02.25   0:22.82 
                  2838         0.0 S    31T   0:00.63   0:16.52 
                  2838         4.0 S    31T   0:02.03   0:51.44 
                  2838         0.0 S    31T   0:00.11   0:00.05 
                  2838         0.0 S    31T   0:00.11   0:00.05 
                  2838         0.0 S    31T   0:00.11   0:00.05 
                  2838         0.0 S    31T   0:00.11   0:00.05 
                  2838         0.0 S    31T   0:00.11   0:00.05 
                  2838         0.0 S    31T   0:00.11   0:00.05 
                  2838         2.8 S    31T   0:01.00   0:42.64 
                  2838         2.9 S    31T   0:01.00   0:42.74 
                  2838         2.9 S    31T   0:01.00   0:42.65 
                  2838         2.9 S    31T   0:00.98   0:42.73 
                  2838         2.9 S    31T   0:01.00   0:42.64 
                  2838         2.8 S    31T   0:01.01   0:42.55 
                  2838         2.8 S    46T   0:02.01   0:03.06 
                  2838         2.4 S    20T   0:00.91   0:01.40 
                  2838         0.0 S    37T   0:00.76   0:01.30 
                  2838         3.0 S    46T   0:00.52   0:00.80 
                  2838         1.0 S    46T   0:00.38   0:00.67 
                  2838         0.0 S    31T   0:00.46   0:00.80 
                  2838         0.0 S    31T   0:00.00   0:00.00 
someuser      2839   ??    0.0 S    46T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
someuser      2840   ??    0.0 S     4T   0:07.76   0:04.96 /usr/bin/some_command with some parameters
                  2840         0.0 S     4T   0:01.14   0:00.37 
                  2840         0.0 S     4T   0:00.00   0:00.00 
                  2840         0.0 S     4T   0:00.00   0:00.00 
someuser      2842   ??    0.0 S    46T   0:41.47   1:23.77 /usr/bin/some_command with some parameters
                  2842         0.0 S    19T   0:00.00   0:00.00 
                  2842         0.0 S    46T   0:01.57   0:00.92 
                  2842         0.0 S    37T   0:00.00   0:00.00 
someuser      2843   ??    0.0 S    47T   0:22.58   0:33.09 /usr/bin/some_command with some parameters
                  2843         0.0 S    47T   0:01.30   0:00.59 
                  2843         0.0 S    37T   0:00.00   0:00.00 
someuser      2844   ??    0.0 S    46T   0:29.59   0:51.01 /usr/bin/some_command with some parameters
                  2844         0.0 S    46T   0:03.21   0:01.96 
                  2844         0.0 S    31T   0:00.04   0:00.00 
                  2844         0.0 S    20T   0:00.00   0:00.00 
                  2844         0.0 S    20T   0:00.00   0:00.00 
someuser      2848   ??    0.0 S     4T   0:10.12   0:13.79 /usr/bin/some_command with some parameters
                  2848         0.0 S     4T   0:00.88   0:00.35 
                  2848         0.0 S     4T   0:01.33   0:00.58 
                  2848         0.0 S     4T   0:00.00   0:00.00 
                  2848         0.0 S     4T   0:00.00   0:00.00 
someuser      2861   ??    0.0 S    31T   0:00.01   0:00.01 /usr/bin/some_command with some parameters
                  2861         0.0 S    31T   0:00.33   0:00.04 
                  2861         0.0 S    31T   0:00.03   0:00.00 
                  2861         0.0 S    31T   0:00.00   0:00.00 
someuser      2872   ??    0.0 S     4T   0:00.27   0:00.11 /usr/bin/some_command with some parameters
                  2872         0.0 S     4T   0:00.04   0:00.01 
                  2872         0.0 S     4T   0:00.00   0:00.00 
root              2882   ??    0.0 S    31T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                  2882         0.0 S     4T   0:00.02   0:00.00 
someuser      2885   ??    0.0 S    31T   0:00.01   0:00.01 /usr/bin/some_command with some parameters
                  2885         0.0 S    31T   0:00.32   0:00.05 
                  2885         0.0 S    31T   0:00.02   0:00.00 
                  2885         0.0 S    31T   0:00.00   0:00.00 
someuser      2889   ??    0.0 S    31T   0:02.32   0:01.03 /usr/bin/some_command with some parameters
                  2889         0.0 S    31T   0:00.00   0:00.00 
someuser      2892   ??    5.5 S    31T  11:25.69  27:31.32 /usr/bin/some_command with some parameters
                  2892         0.0 S    31T   0:00.34   0:00.41 
                  2892         0.0 S    31T   0:15.36   0:16.26 
                  2892         0.0 S    31T   0:04.59   0:06.11 
                  2892         0.0 S     0T   0:00.14   0:00.10 
                  2892         0.6 S    31T   2:39.79   3:07.42 
                  2892         2.0 S    31T   2:16.48  12:19.61 
                  2892         0.0 S    31T   0:00.00   0:00.00 
                  2892         0.0 S    31T   0:00.00   0:00.00 
                  2892         0.0 S    31T   0:00.00   0:00.00 
someuser      2899   ??    0.0 S    31T   0:00.02   0:00.05 /usr/bin/some_command with some parameters
                  2899         0.0 S    31T   0:00.17   0:00.16 
                  2899         0.0 S    31T   0:32.75   1:16.03 
                  2899         0.0 S    31T   0:00.09   0:00.02 
                  2899         0.0 S     0T   0:02.16   0:00.21 
                  2899         0.0 S    31T   0:00.01   0:00.00 
                  2899         0.0 S    31T   0:00.01   0:00.00 
                  2899         0.0 S    31T   0:00.00   0:00.00 
someuser      2913   ??    0.0 S    31T   0:00.01   0:00.01 /usr/bin/some_command with some parameters
                  2913         0.0 S    31T   0:00.31   0:00.04 
                  2913         0.0 S    31T   0:00.01   0:00.00 
                  2913         0.0 S    31T   0:00.00   0:00.00 
someuser      2915   ??    0.3 S    31T   3:51.63  59:54.10 /usr/bin/some_command with some parameters
                  2915         0.0 S    31T   0:19.84   0:22.22 
                  2915         0.0 S     0T   0:00.11   0:00.10 
                  2915         0.6 S    31T   2:43.61   3:46.09 
                  2915         0.0 S    31T   0:00.01   0:00.00 
                  2915         2.8 S    31T   3:57.14  19:14.88 
                  2915         0.0 S    31T   0:00.94   0:01.53 
                  2915         0.0 S    31T   0:07.65   0:39.99 
                  2915         0.0 S    31T   0:07.57   0:39.59 
                  2915         0.0 S    31T   0:07.61   0:39.10 
                  2915         0.0 S    31T   0:07.67   0:40.79 
                  2915         0.0 S    31T   0:00.11   0:00.48 
                  2915         0.0 S    31T   0:00.24   0:00.46 
                  2915         0.0 S    31T   0:00.06   0:00.02 
                  2915         0.0 S    31T   0:00.03   0:00.55 
                  2915         0.0 S    31T   0:00.03   0:00.48 
                  2915         0.0 S    31T   0:00.01   0:00.22 
                  2915         0.0 S    31T   0:00.01   0:00.10 
                  2915         0.0 S    31T   0:00.00   0:00.06 
someuser      2924   ??    0.0 S    31T   0:23.34   0:27.91 /usr/bin/some_command with some parameters
                  2924         0.0 S    31T   0:00.19   0:00.41 
                  2924         0.0 S    31T   0:00.06   0:00.01 
                  2924         0.0 S    31T   0:00.14   0:00.11 
                  2924         0.0 S     0T   0:00.14   0:00.10 
                  2924         0.0 S    31T   0:20.16   0:24.92 
                  2924         0.3 S    31T   1:00.63   3:05.41 
                  2924         0.0 S    31T   0:00.00   0:00.00 
someuser      2925   ??    0.0 S    31T   0:00.02   0:00.06 /usr/bin/some_command with some parameters
                  2925         0.0 S    31T   0:00.10   0:00.08 
                  2925         0.0 S    31T   0:20.11   0:31.57 
                  2925         0.0 S    31T   0:00.09   0:00.02 
                  2925         0.0 S     0T   0:00.83   0:00.11 
                  2925         0.0 S    31T   0:00.15   0:00.05 
                  2925         0.0 S    31T   0:00.00   0:00.00 
someuser      2928   ??    0.0 S    31T   0:00.01   0:00.03 /usr/bin/some_command with some parameters
                  2928         0.0 S    31T   0:00.54   0:00.06 
                  2928         0.0 S    31T   0:00.01   0:00.00 
                  2928         0.0 S    31T   0:00.00   0:00.00 
someuser      2930   ??    0.0 S    31T   0:00.54   0:00.82 /usr/bin/some_command with some parameters
                  2930         0.0 S    31T   0:00.00   0:00.00 
root              2948   ??    0.0 S    31T   0:03.08   0:01.19 /usr/bin/some_command with some parameters
                  2948         0.0 S    31T   0:00.00   0:00.00 
someuser      2949   ??    0.0 S    31T   0:00.02   0:00.01 /usr/bin/some_command with some parameters
someuser      2984   ??    0.0 S    31T  18:41.03  38:08.48 /usr/bin/some_command with some parameters
                  2984         0.0 S    31T   0:00.32   0:00.40 
                  2984         0.0 S    31T   0:00.01   0:00.00 
                  2984         0.0 S    31T   2:54.77   3:38.20 
                  2984         0.0 S    31T   3:30.37  14:49.00 
                  2984         0.0 S    31T   0:07.78   0:16.90 
                  2984         0.0 S    31T   0:00.82   0:00.48 
                  2984         0.0 S    31T   0:05.01   0:10.98 
                  2984         0.0 S    54T   0:06.15   0:14.80 
                  2984         0.0 S     0T   0:00.36   0:00.38 
                  2984         0.0 S    31T   0:00.00   0:00.00 
someuser      2986   ??    0.0 S    31T   0:00.07   0:00.13 /usr/bin/some_command with some parameters
                  2986         0.0 S    31T   0:00.68   0:00.88 
                  2986         0.1 S    31T   8:41.43  28:57.47 
                  2986         0.0 S    31T   0:00.08   0:00.03 
                  2986         0.0 S    31T   0:00.12   0:00.08 
                  2986         0.0 S     0T   0:04.88   0:00.32 
                  2986         0.0 S     0T   0:03.61   0:00.24 
                  2986         0.0 S    31T   0:00.01   0:00.01 
                  2986         0.0 S    31T   0:00.06   0:00.01 
                  2986         0.0 S    31T   0:00.07   0:00.01 
                  2986         0.0 S    31T   0:00.01   0:00.00 
                  2986         0.0 S    31T   0:00.00   0:00.00 
                  2986         0.0 S    31T   0:00.00   0:00.00 
someuser      2991   ??    0.0 S    31T   0:18.98   0:40.44 /usr/bin/some_command with some parameters
                  2991         0.0 S    31T   0:00.00   0:00.00 
                  2991         0.0 S     0T   0:00.13   0:00.10 
                  2991         0.0 S    31T   0:09.96   0:11.54 
                  2991         0.0 S    31T   0:00.09   0:00.02 
                  2991         0.0 S    31T   0:00.00   0:00.00 
                  2991         0.0 S    31T   0:00.01   0:00.00 
                  2991         0.0 S    31T   0:00.00   0:00.00 
someuser      2997   ??    0.0 S    31T   0:20.21   1:53.46 /usr/bin/some_command with some parameters
                  2997         0.0 S    31T   0:00.00   0:00.00 
                  2997         0.0 S     0T   0:00.13   0:00.10 
                  2997         0.0 S    31T   0:15.84   0:25.18 
                  2997         0.0 S    31T   0:00.01   0:00.00 
                  2997         0.0 S    31T   0:00.10   0:00.26 
                  2997         0.0 S    31T   0:00.00   0:00.00 
                  2997         0.0 S    31T   0:00.02   0:00.01 
                  2997         0.0 S    31T   0:00.01   0:00.01 
                  2997         0.0 S    31T   0:00.00   0:00.01 
                  2997         0.0 S    31T   0:00.01   0:00.02 
                  2997         0.0 S    31T   0:00.00   0:00.00 
                  2997         0.0 S    31T   0:00.23   0:00.13 
                  2997         0.0 S    31T   0:00.00   0:00.00 
                  2997         0.0 S    31T   0:00.01   0:00.00 
someuser      2998   ??    0.0 S    31T   0:02.59   0:03.34 /usr/bin/some_command with some parameters
                  2998         0.0 S    31T   0:00.01   0:00.00 
                  2998         0.0 S     0T   0:00.15   0:00.10 
                  2998         0.0 S    31T   0:01.21   0:01.23 
                  2998         0.0 S    31T   0:00.01   0:00.00 
                  2998         0.0 S    31T   0:00.01   0:00.00 
                  2998         0.0 S    31T   0:00.00   0:00.00 
                  2998         0.0 S    31T   0:00.00   0:00.00 
                  2998         0.0 S    31T   0:00.00   0:00.00 
                  2998         0.0 S    31T   0:00.00   0:00.00 
                  2998         0.0 S    31T   0:00.00   0:00.00 
                  2998         0.0 S    31T   0:00.00   0:00.00 
                  2998         0.0 S    31T   0:00.27   0:00.12 
                  2998         0.0 S    31T   0:00.11   0:00.03 
                  2998         0.0 S    31T   0:00.00   0:00.00 
someuser      2999   ??    0.0 S    31T   0:46.82   1:58.19 /usr/bin/some_command with some parameters
                  2999         0.0 S    31T   0:00.00   0:00.00 
                  2999         0.0 S     0T   0:00.14   0:00.09 
                  2999         0.0 S    31T   0:15.19   0:20.96 
                  2999         0.0 S    31T   0:00.01   0:00.02 
                  2999         0.0 S    31T   0:00.37   0:01.38 
                  2999         0.0 S    31T   0:00.00   0:00.00 
                  2999         0.0 S    31T   0:00.03   0:00.04 
                  2999         0.0 S    31T   0:00.03   0:00.04 
                  2999         0.0 S    31T   0:00.02   0:00.04 
                  2999         0.0 S    31T   0:00.03   0:00.05 
                  2999         0.0 S    31T   0:00.00   0:00.00 
                  2999         0.0 S    31T   0:00.01   0:00.04 
                  2999         0.0 S    31T   0:00.48   0:00.15 
                  2999         0.0 S    31T   0:00.00   0:00.00 
                  2999         0.0 S    31T   0:00.00   0:00.00 
someuser      3016   ??    0.0 S    20T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                  3016         0.0 S    20T   0:00.00   0:00.00 
someuser      3033   ??    0.0 S    31T   1:29.64   4:29.00 /usr/bin/some_command with some parameters
                  3033         0.0 S    31T   0:00.72   0:00.47 
                  3033         0.0 S    31T   0:00.01   0:00.00 
                  3033         0.0 S    31T   0:00.15   0:00.11 
                  3033         0.0 S     0T   0:00.12   0:00.09 
                  3033         0.0 S    31T   0:40.64   0:51.82 
                  3033         0.0 S    31T   0:33.94   2:49.91 
                  3033         0.0 S    31T   0:00.00   0:00.00 
someuser      3059   ??    0.0 S    31T   0:04.49   0:00.80 gpg-agent --homedir /usr/bin/some_command with some parameters
someuser      3062   ??    0.0 S    31T   0:00.62   0:00.24 /usr/bin/some_command with some parameters
                  3062         0.0 S    19T   0:00.00   0:00.00 
                  3062         0.0 S    31T   0:00.01   0:00.00 
someuser      3063   ??    0.0 S     4T   0:00.14   0:00.12 /usr/bin/some_command with some parameters
                  3063         0.0 S     4T   0:00.01   0:00.01 
                  3063         0.0 S     4T   0:00.01   0:00.02 
                  3063         0.0 S     4T   0:00.00   0:00.00 
                  3063         0.0 S     4T   0:00.00   0:00.00 
someuser      3071   ??    0.0 S    20T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                  3071         0.0 S    20T   0:00.00   0:00.00 
someuser      3073   ??    0.2 S    20T   5:16.24  10:35.13 /usr/bin/some_command with some parameters
                  3073         0.0 S    20T   0:00.08   0:00.02 
                  3073         0.0 S    20T   0:00.16   0:00.12 
                  3073         0.2 S    20T   4:03.29   3:27.79 
                  3073         0.0 S    20T   0:00.00   0:00.00 
                  3073         0.0 S    20T   0:01.45   0:21.67 
                  3073         0.0 S    20T   0:01.43   0:21.43 
                  3073         0.0 S    20T   0:01.41   0:21.23 
                  3073         0.0 S    20T   0:00.00   0:00.00 
                  3073         0.0 S    20T   0:00.00   0:00.00 
                  3073         0.0 S    20T   0:00.00   0:00.00 
                  3073         0.0 S    20T   0:00.00   0:00.00 
                  3073         0.0 S    20T   0:00.00   0:00.00 
                  3073         0.0 S    20T   0:00.09   0:00.02 
                  3073         0.0 S    20T   0:00.00   0:00.00 
                  3073         0.0 S    20T   0:00.01   0:00.00 
                  3073         0.0 S    20T   0:00.00   0:00.00 
                  3073         0.0 S    20T   0:00.01   0:00.00 
                  3073         0.0 S    20T   0:00.27   0:00.11 
                  3073         0.0 S    20T   0:01.36   0:00.77 
                  3073         0.0 S    20T   0:00.01   0:00.00 
                  3073         0.0 S    20T   0:00.31   0:00.44 
                  3073         0.0 S    20T   0:00.00   0:00.00 
                  3073         0.1 S    20T   0:00.25   0:00.32 
                  3073         0.0 S    20T   0:00.22   0:00.28 
                  3073         0.1 S    20T   0:00.26   0:00.34 
                  3073         0.0 S    20T   0:00.00   0:00.00 
                  3073         0.0 S    20T   0:00.00   0:00.00 
                  3073         0.0 S    20T   0:00.00   0:00.00 
someuser      3080   ??    0.0 S    46T   0:03.17   0:01.25 /usr/bin/some_command with some parameters
                  3080         0.0 S    46T   0:00.45   0:00.09 
                  3080         0.0 S    37T   0:00.00   0:00.00 
someuser      3083   ??    0.0 S     4T   0:06.89   0:05.98 /usr/bin/some_command with some parameters
                  3083         0.0 S     4T   0:00.00   0:00.00 
someuser      3088   ??    0.0 S    20T   0:16.14   0:15.99 /usr/bin/some_command with some parameters
                  3088         0.0 S    20T   0:00.00   0:00.00 
                  3088         0.0 S    20T   0:29.70   0:28.62 
                  3088         0.0 S    20T   0:00.01   0:00.01 
                  3088         0.0 S    20T   0:00.01   0:00.01 
                  3088         0.0 S    20T   0:00.00   0:00.00 
                  3088         0.0 S    20T   0:00.00   0:00.00 
                  3088         0.0 S    20T   0:08.88   0:44.56 
                  3088         0.0 S    20T   0:05.83   0:08.89 
                  3088         0.0 S    20T   0:00.38   0:00.11 
                  3088         0.0 S    20T   0:41.72   0:28.30 
                  3088         0.0 S    20T   0:00.13   0:00.10 
                  3088         0.0 S    20T   0:03.64   0:01.80 
                  3088         0.0 S    20T   0:01.36   0:00.56 
                  3088         0.0 S    20T   0:00.00   0:00.00 
                  3088         0.0 S    20T   0:01.67   0:00.69 
                  3088         0.0 S    20T   0:00.00   0:00.00 
                  3088         0.0 S    20T   0:02.85   0:05.42 
                  3088         0.0 S    20T   0:30.76   0:26.13 
                  3088         0.0 S    20T   0:00.03   0:00.01 
                  3088         0.0 S    20T   0:00.00   0:00.01 
                  3088         0.0 S    20T   0:00.16   0:00.11 
                  3088         0.0 S    20T   0:00.04   0:00.05 
                  3088         0.0 S    20T   0:02.61   0:01.24 
                  3088         0.0 S    20T   0:01.54   0:00.83 
                  3088         0.0 S    20T   0:00.74   0:00.29 
                  3088         0.0 S    20T   0:01.15   0:00.46 
                  3088         0.0 S    20T   0:02.32   0:01.10 
                  3088         0.0 S    20T   0:03.38   0:01.60 
                  3088         0.0 S    20T   0:01.86   0:00.84 
                  3088         0.0 S    20T   0:01.69   0:00.88 
                  3088         0.0 S    20T   0:02.14   0:01.09 
                  3088         0.0 S    20T   0:00.45   0:00.19 
                  3088         0.0 S    20T   0:01.06   0:00.48 
                  3088         0.0 S    20T   0:00.01   0:00.00 
                  3088         0.0 S    20T   0:00.00   0:00.01 
                  3088         0.0 S    20T   0:00.02   0:00.01 
                  3088         0.0 S    20T   0:00.01   0:00.00 
                  3088         0.0 S    20T   0:00.00   0:00.00 
someuser      3091   ??    0.0 S     4T   0:00.01   0:00.04 /usr/bin/some_command with some parameters
                  3091         0.0 S     4T   0:00.02   0:00.00 
someuser      3093   ??    0.0 S    31T   0:00.28   0:00.17 /usr/bin/some_command with some parameters
                  3093         0.0 S    31T   0:00.01   0:00.00 
                  3093         0.0 S     0T   0:00.13   0:00.10 
                  3093         0.0 S    31T   0:00.27   0:00.10 
                  3093         0.0 S    31T   0:00.03   0:00.02 
                  3093         0.0 S    31T   0:00.00   0:00.00 
someuser      3094   ??    0.0 S    31T   0:00.03   0:00.07 /usr/bin/some_command with some parameters
                  3094         0.0 S    31T   0:00.09   0:00.07 
                  3094         0.0 S    31T   0:31.44   0:58.88 
                  3094         0.0 S    31T   0:00.08   0:00.03 
                  3094         0.0 S    31T   0:00.00   0:00.00 
                  3094         0.0 S     0T   0:00.12   0:00.01 
                  3094         0.0 S    31T   0:00.27   0:00.04 
someuser      3095   ??    0.0 S    31T   1:29.01  11:00.31 /usr/bin/some_command with some parameters
                  3095         0.0 S    31T   0:00.06   0:00.05 
                  3095         0.0 S     0T   0:00.12   0:00.10 
                  3095         0.0 S    31T   0:43.62   1:04.66 
                  3095         0.0 S    31T   0:00.01   0:00.00 
                  3095         0.0 S    31T   1:00.96   4:59.78 
                  3095         0.0 S    31T   0:00.81   0:00.80 
                  3095         0.0 S    31T   0:02.30   0:07.20 
                  3095         0.0 S    31T   0:02.30   0:07.27 
                  3095         0.0 S    31T   0:02.39   0:07.26 
                  3095         0.0 S    31T   0:02.31   0:07.21 
                  3095         0.0 S    31T   0:00.01   0:00.02 
                  3095         0.0 S    31T   0:00.11   0:00.04 
                  3095         0.0 S    31T   0:00.01   0:00.00 
                  3095         0.0 S    31T   0:00.36   0:00.14 
                  3095         0.0 S    31T   0:00.05   0:00.01 
someuser      3146   ??    0.0 S    46T   0:20.20   0:26.52 /usr/bin/some_command with some parameters
                  3146         0.0 S    46T   0:01.17   0:00.58 
                  3146         0.0 S    31T   0:00.00   0:00.00 
                  3146         0.0 S    31T   0:00.00   0:00.00 
someuser      3181   ??    0.3 S    46T   9:32.32  10:30.99 /usr/bin/some_command with some parameters
                  3181         0.0 S    46T   0:01.30   0:00.81 
                  3181         0.0 S    46T   0:00.00   0:00.00 
                  3181         0.0 S    46T   0:00.00   0:00.00 
                  3181         0.0 S    46T   0:00.00   0:00.00 
                  3181         0.0 S    46T   0:00.00   0:00.00 
                  3181         0.0 S    46T   0:00.00   0:00.00 
                  3181         0.0 S    46T   0:00.00   0:00.00 
                  3181         0.0 S    46T   0:00.00   0:00.00 
                  3181         0.0 S    46T   0:00.00   0:00.00 
                  3181         0.0 S    37T   0:00.00   0:00.00 
                  3181         0.0 S    31T   0:00.00   0:00.00 
someuser      3211   ??    0.0 S    20T   0:00.13   0:00.17 /usr/bin/some_command with some parameters
                  3211         0.0 S    20T   0:00.10   0:00.01 
                  3211         0.0 S    20T   0:00.18   0:00.12 
                  3211         0.0 S    20T   0:00.15   0:00.12 
                  3211         0.0 S    20T   2:46.82   1:29.37 
                  3211         0.0 S    20T   3:44.57  16:11.83 
                  3211         0.0 S    20T   0:00.00   0:00.00 
someuser      3288   ??    0.0 S    20T   0:00.05   0:00.04 /usr/bin/some_command with some parameters
                  3288         0.0 S    20T   0:00.07   0:00.02 
                  3288         0.0 S    20T   0:00.15   0:00.12 
                  3288         0.1 S    20T   1:07.39   2:51.00 
                  3288         0.0 S    20T   0:00.09   0:00.02 
                  3288         0.0 S    20T   0:00.02   0:00.01 
                  3288         0.0 S    20T   0:00.00   0:00.00 
someuser      3312   ??    0.0 S    31T   0:33.92   2:38.45 /usr/bin/some_command with some parameters
                  3312         0.0 S    31T   0:00.01   0:00.00 
                  3312         0.0 S     0T   0:00.12   0:00.09 
                  3312         0.0 S    31T   0:05.15   0:04.22 
                  3312         0.0 S    31T   0:00.01   0:00.00 
                  3312         0.0 S    31T   0:04.08   0:15.29 
                  3312         0.0 S    31T   0:00.00   0:00.00 
                  3312         0.0 S    31T   0:00.16   0:00.52 
                  3312         0.0 S    31T   0:00.28   0:00.54 
                  3312         0.0 S    31T   0:00.21   0:00.71 
                  3312         0.0 S    31T   0:00.44   0:00.74 
                  3312         0.0 S    31T   0:00.01   0:00.03 
                  3312         0.0 S    31T   0:00.85   0:00.21 
                  3312         0.0 S    31T   0:00.00   0:00.00 
                  3312         0.0 S    31T   0:01.40   0:00.32 
                  3312         0.0 S    31T   0:00.03   0:00.02 
                  3312         0.0 S    31T   0:00.02   0:00.01 
someuser      3337   ??    0.0 S    31T   0:51.88   2:16.56 /usr/bin/some_command with some parameters
                  3337         0.0 S    31T   0:00.01   0:00.00 
                  3337         0.0 S     0T   0:00.13   0:00.09 
                  3337         0.0 S    31T   0:16.44   0:19.64 
                  3337         0.0 S    31T   0:00.01   0:00.00 
                  3337         0.0 S    31T   0:00.65   0:01.07 
                  3337         0.0 S    31T   0:00.00   0:00.00 
                  3337         0.0 S    31T   0:00.07   0:00.05 
                  3337         0.0 S    31T   0:00.06   0:00.04 
                  3337         0.0 S    31T   0:00.07   0:00.05 
                  3337         0.0 S    31T   0:00.05   0:00.04 
                  3337         0.0 S    31T   0:00.00   0:00.00 
                  3337         0.0 S    31T   0:00.50   0:00.20 
                  3337         0.0 S    31T   0:00.42   0:00.16 
                  3337         0.0 S    31T   0:00.13   0:00.15 
                  3337         0.0 S    31T   0:00.04   0:00.03 
someuser      3543   ??    0.0 S    31T   0:31.51   1:34.86 /usr/bin/some_command with some parameters
                  3543         0.0 S    31T   0:00.13   0:00.01 
                  3543         0.0 S    31T   0:00.15   0:00.11 
                  3543         0.0 S     0T   0:00.15   0:00.11 
                  3543         0.0 S    31T   0:00.00   0:00.00 
                  3543         0.0 S    31T   0:00.05   0:00.03 
                  3543         0.0 S    31T   0:00.05   0:00.02 
                  3543         0.0 S    31T   0:00.02   0:00.01 
                  3543         0.0 S    31T   0:00.00   0:00.00 
                  3543         0.0 S    31T   0:00.00   0:00.00 
someuser      3544   ??    0.0 S    31T   0:16.69   0:54.27 /usr/bin/some_command with some parameters
                  3544         0.0 S    31T   0:00.03   0:00.00 
                  3544         0.0 S     0T   0:00.12   0:00.11 
                  3544         0.0 S    31T   0:10.40   0:09.03 
                  3544         0.0 S    31T   0:00.01   0:00.00 
                  3544         0.0 S    31T   0:00.15   0:00.09 
                  3544         0.0 S    31T   0:00.00   0:00.00 
                  3544         0.0 S    31T   0:00.00   0:00.00 
                  3544         0.0 S    31T   0:00.01   0:00.00 
                  3544         0.0 S    31T   0:00.01   0:00.00 
                  3544         0.0 S    31T   0:00.00   0:00.00 
                  3544         0.0 S    31T   0:00.00   0:00.00 
                  3544         0.0 S    31T   0:00.00   0:00.00 
                  3544         0.0 S    31T   0:00.01   0:00.01 
                  3544         0.0 S    31T   0:00.00   0:00.00 
                  3544         0.0 S    31T   0:00.00   0:00.00 
someuser      3545   ??    0.0 S    31T   0:08.99   0:27.17 /usr/bin/some_command with some parameters
                  3545         0.0 S    31T   0:00.03   0:00.00 
                  3545         0.0 S     0T   0:00.13   0:00.10 
                  3545         0.0 S    31T   0:06.04   0:05.41 
                  3545         0.0 S    31T   0:00.01   0:00.00 
                  3545         0.0 S    31T   0:00.09   0:00.05 
                  3545         0.0 S    31T   0:00.00   0:00.00 
                  3545         0.0 S    31T   0:00.00   0:00.00 
                  3545         0.0 S    31T   0:00.00   0:00.00 
                  3545         0.0 S    31T   0:00.00   0:00.00 
                  3545         0.0 S    31T   0:00.00   0:00.00 
                  3545         0.0 S    31T   0:00.00   0:00.00 
                  3545         0.0 S    31T   0:00.00   0:00.00 
                  3545         0.0 S    31T   0:00.00   0:00.00 
                  3545         0.0 S    31T   0:00.00   0:00.00 
someuser      3564   ??    0.2 S    31T   1:56.38  11:04.14 /usr/bin/some_command with some parameters
                  3564         0.0 S    31T   0:00.02   0:00.00 
                  3564         0.0 S     0T   0:00.12   0:00.10 
                  3564         0.0 S    31T   0:30.11   0:36.49 
                  3564         0.0 S    31T   0:00.00   0:00.00 
                  3564         0.0 S    31T   0:18.17   0:51.64 
                  3564         0.0 S    31T   0:00.00   0:00.00 
                  3564         0.0 S    31T   0:00.01   0:00.01 
                  3564         0.0 S    31T   0:00.02   0:00.01 
                  3564         0.0 S    31T   0:00.02   0:00.02 
                  3564         0.0 S    31T   0:00.02   0:00.02 
                  3564         0.0 S    31T   0:00.00   0:00.00 
                  3564         0.0 S    31T   0:00.00   0:00.00 
                  3564         0.0 S    31T   0:00.00   0:00.00 
                  3564         0.0 S    31T   0:00.00   0:00.00 
                  3564         0.0 S    31T   0:00.00   0:00.00 
                  3564         0.0 S    31T   0:00.02   0:00.02 
                  3564         0.0 S    31T   0:00.00   0:00.00 
someuser      3566   ??    0.0 S    31T   0:00.89   0:00.49 /usr/bin/some_command with some parameters
                  3566         0.0 S    31T   0:00.07   0:00.01 
                  3566         0.0 S     0T   0:00.14   0:00.11 
                  3566         0.0 S    31T   0:00.22   0:00.04 
                  3566         0.0 S    31T   0:00.01   0:00.00 
                  3566         0.0 S    31T   0:00.01   0:00.00 
                  3566         0.0 S    31T   0:00.00   0:00.00 
                  3566         0.0 S    31T   0:00.00   0:00.00 
                  3566         0.0 S    31T   0:00.00   0:00.00 
                  3566         0.0 S    31T   0:00.00   0:00.00 
                  3566         0.0 S    31T   0:00.00   0:00.00 
                  3566         0.0 S    31T   0:00.00   0:00.00 
                  3566         0.0 S    31T   0:00.00   0:00.00 
                  3566         0.0 S    31T   0:00.16   0:00.12 
                  3566         0.0 S    31T   0:00.00   0:00.00 
someuser      3569   ??    0.1 S    31T   2:18.42  13:40.07 /usr/bin/some_command with some parameters
                  3569         0.0 S    31T   0:00.02   0:00.00 
                  3569         0.0 S     0T   0:00.12   0:00.10 
                  3569         0.0 S    31T   0:30.67   0:38.85 
                  3569         0.0 S    31T   0:00.01   0:00.00 
                  3569         0.0 S    31T   0:21.88   1:15.72 
                  3569         0.0 S    31T   0:00.00   0:00.00 
                  3569         0.0 S    31T   0:00.15   0:00.27 
                  3569         0.0 S    31T   0:00.14   0:00.26 
                  3569         0.0 S    31T   0:00.13   0:00.29 
                  3569         0.0 S    31T   0:00.13   0:00.32 
                  3569         0.0 S    31T   0:00.00   0:00.00 
                  3569         0.0 S    31T   0:00.00   0:00.00 
                  3569         0.0 S    31T   0:00.00   0:00.00 
                  3569         0.0 S    31T   0:00.00   0:00.00 
                  3569         0.0 S    31T   0:00.00   0:00.00 
                  3569         0.0 S    31T   0:00.00   0:00.00 
                  3569         0.0 S    31T   0:00.00   0:00.00 
                  3569         0.0 S    31T   0:00.00   0:00.00 
                  3569         0.0 S    31T   0:00.00   0:00.00 
                  3569         0.0 S    31T   0:00.03   0:00.02 
                  3569         0.0 S    31T   0:00.00   0:00.00 
someuser      3571   ??    0.0 S    31T   0:00.97   0:00.52 /usr/bin/some_command with some parameters
                  3571         0.0 S    31T   0:00.07   0:00.01 
                  3571         0.0 S     0T   0:00.14   0:00.11 
                  3571         0.0 S    31T   0:00.23   0:00.05 
                  3571         0.0 S    31T   0:00.01   0:00.00 
                  3571         0.0 S    31T   0:00.01   0:00.00 
                  3571         0.0 S    31T   0:00.00   0:00.00 
                  3571         0.0 S    31T   0:00.00   0:00.00 
                  3571         0.0 S    31T   0:00.00   0:00.00 
                  3571         0.0 S    31T   0:00.00   0:00.00 
                  3571         0.0 S    31T   0:00.00   0:00.00 
                  3571         0.0 S    31T   0:00.00   0:00.00 
                  3571         0.0 S    31T   0:00.00   0:00.00 
                  3571         0.0 S    31T   0:00.15   0:00.12 
                  3571         0.0 S    31T   0:00.00   0:00.00 
someuser      3623   ??    1.6 S    20T   3:07.53  26:05.10 /usr/bin/some_command with some parameters
                  3623         0.0 S    20T   0:00.02   0:00.00 
                  3623         0.0 S    20T   0:00.14   0:00.12 
                  3623         0.1 S    20T   2:59.93   3:58.42 
                  3623         0.0 S    20T   0:00.00   0:00.00 
                  3623         0.0 S    20T   3:50.67  16:36.39 
                  3623         0.0 S    20T   0:00.00   0:00.00 
                  3623         0.0 S    20T   0:07.04   0:08.13 
                  3623         0.0 S    20T   0:07.15   0:08.16 
                  3623         0.0 S    20T   0:07.15   0:08.21 
                  3623         0.0 S    20T   0:07.13   0:08.20 
                  3623         0.0 S    20T   0:00.00   0:00.00 
                  3623         0.0 S    20T   0:00.02   0:00.01 
                  3623         0.0 S    20T   0:00.01   0:00.00 
                  3623         0.0 S    20T   0:00.01   0:00.00 
                  3623         0.0 S    20T   0:00.01   0:00.00 
                  3623         0.0 S    20T   0:00.01   0:00.00 
                  3623         0.0 S    20T   0:00.77   0:00.26 
                  3623         0.0 S    20T   0:00.00   0:00.00 
                  3623         0.0 S    20T   0:00.10   0:00.56 
                  3623         0.0 S    20T   0:00.11   0:00.62 
                  3623         0.0 S    20T   0:00.09   0:00.60 
                  3623         0.0 S    20T   0:00.11   0:00.66 
                  3623         0.0 S    20T   0:00.11   0:00.62 
                  3623         0.0 S    20T   0:00.14   0:00.70 
                  3623         0.0 S    20T   0:00.06   0:00.35 
                  3623         0.0 S    20T   0:00.05   0:00.30 
                  3623         0.0 S    20T   0:00.00   0:00.00 
someuser      3656   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                  3656         0.0 S     4T   0:00.00   0:00.00 
root              3732   ??    0.0 S    20T   0:00.01   0:00.01 /usr/bin/some_command with some parameters
                  3732         0.4 S    20T   0:57.98   7:08.01 
                  3732         0.0 S    20T   0:00.00   0:00.00 
                  3732         0.0 S    20T   0:00.46   0:00.25 
                  3732         0.0 S    20T   0:00.00   0:00.00 
                  3732         0.0 S    20T   0:00.00   0:00.00 
                  3732         0.0 S    20T   0:11.95   0:05.79 
someuser      3736   ??    0.0 S    20T   0:00.33   0:00.26 /usr/bin/some_command with some parameters
                  3736         0.0 S    20T   1:11.05   4:16.13 
                  3736         0.0 S    20T   0:00.00   0:00.00 
                  3736         0.0 S    20T   0:00.46   0:00.25 
                  3736         0.0 S    20T   0:00.00   0:00.00 
                  3736         0.0 S    20T   0:11.65   0:06.09 
                  3736         0.0 S    20T   0:00.00   0:00.00 
                  3736         0.0 S    20T   0:00.00   0:00.00 
                  3736         0.0 S    20T   0:00.00   0:00.00 
root              3742   ??    0.0 S    31T   0:00.01   0:00.01 /usr/bin/some_command with some parameters
                  3742         0.0 S    31T   1:32.58   3:35.36 
                  3742         0.0 S    31T   0:05.20   0:00.21 
                  3742         0.0 S    31T   0:00.50   0:00.28 
                  3742         0.0 S    31T   0:00.00   0:00.00 
                  3742         0.0 S    31T   0:00.03   0:00.02 
                  3742         0.0 S    31T   0:17.45   0:06.37 
                  3742         0.0 S    31T   0:04.79   0:02.33 
                  3742         0.0 S    31T   0:28.30   0:10.24 
                  3742         0.0 S    31T   0:05.11   0:02.47 
                  3742         0.0 S    31T   1:33.15   2:44.53 
                  3742         0.0 S    31T   0:00.00   0:00.00 
                  3742         0.0 S    31T   1:13.45   0:32.12 
                  3742         0.0 S    31T   0:00.06   0:00.03 
                  3742         0.0 S    31T   0:00.05   0:00.01 
                  3742         0.0 S    31T   0:00.05   0:00.01 
                  3742         0.0 S    31T   0:00.65   0:01.64 
                  3742         0.0 S    31T   0:00.11   0:00.11 
                  3742         0.0 S    31T   0:00.00   0:00.00 
                  3742         0.0 S    31T   0:00.00   0:00.00 
                  3742         0.0 S    31T   0:00.00   0:00.00 
                  3742         0.0 S    31T   0:00.00   0:00.00 
someuser      3743   ??    0.0 S    46T   0:09.36   0:11.95 /usr/bin/some_command with some parameters
                  3743         0.0 S    31T   0:00.00   0:00.00 
                  3743         0.0 S    31T   0:00.00   0:00.00 
                  3743         0.0 S    31T   0:00.00   0:00.00 
                  3743         0.0 S    31T   0:00.00   0:00.00 
                  3743         0.0 S    46T   0:01.34   0:00.57 
                  3743         0.0 S    31T   0:00.00   0:00.00 
                  3743         0.0 S    37T   0:00.00   0:00.00 
root              3747   ??    0.0 S    20T   0:00.01   0:00.01 /usr/bin/some_command with some parameters
                  3747         0.0 R    20T   1:30.26   5:34.22 
                  3747         0.0 S    20T   0:00.00   0:00.00 
                  3747         0.0 S    20T   0:00.66   0:00.29 
                  3747         0.0 S    20T   0:00.00   0:00.00 
                  3747         0.0 S    20T   0:20.98   0:10.77 
                  3747         0.0 S    20T   0:00.28   0:00.10 
                  3747         0.0 S    20T   0:00.25   0:00.07 
                  3747         0.0 S    20T   0:00.23   0:00.07 
                  3747         0.0 S    20T   0:03.57   0:06.72 
                  3747         0.0 S    20T   0:00.00   0:00.00 
                  3747         0.0 S    20T   0:01.41   0:01.08 
                  3747         0.0 S    20T   0:00.75   0:01.43 
                  3747         0.0 S    20T   0:11.93   0:27.25 
                  3747         0.0 S    20T   0:00.00   0:00.00 
                  3747         0.0 S    20T   0:00.00   0:00.00 
                  3747         0.0 S    20T   0:00.01   0:00.00 
                  3747         0.0 S    20T   0:00.01   0:00.00 
root              3769   ??    0.0 S    31T   0:53.06   0:37.06 /usr/bin/some_command with some parameters
                  3769         0.0 S    31T   0:00.42   0:00.27 
                  3769         0.0 S    31T   0:00.00   0:00.00 
                  3769         0.0 S    31T   1:28.59   0:29.68 
                  3769         0.0 S    31T   0:00.00   0:00.00 
                  3769         0.0 S    31T   0:00.00   0:00.00 
                  3769         0.0 S    31T   0:15.11   0:07.92 
                  3769         0.0 S    31T   0:00.00   0:00.00 
                  3769         0.0 S    31T   0:13.86   0:07.25 
_driverkit        3811   ??    0.0 S    63R   0:11.05   0:12.34 /usr/bin/some_command with some parameters
                  3811         0.0 S    31T   0:00.00   0:00.00 
_driverkit        3813   ??    0.0 S    63R   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                  3813         0.0 S    31T   0:00.00   0:00.00 
someuser      3834   ??    0.0 S    20T   0:10.13   0:04.30 /usr/bin/some_command with some parameters
                  3834         0.0 S    20T   0:00.00   0:00.00 
                  3834         0.0 S    20T   0:00.00   0:00.00 
                  3834         0.0 S    20T   0:00.00   0:00.00 
                  3834         0.0 S    20T   0:04.18   0:00.63 
                  3834         0.0 S    20T   0:00.50   0:00.12 
                  3834         0.0 S    20T   0:00.00   0:00.00 
                  3834         0.0 S    20T   0:00.00   0:00.00 
someuser      3857   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                  3857         0.0 S     4T   0:00.00   0:00.00 
root              4074   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                  4074         0.0 S     4T   0:08.20   0:08.17 
                  4074         0.0 S     4T   0:11.99   0:12.76 
                  4074         0.0 S     4T   0:00.47   0:00.32 
                  4074         0.0 S     4T   0:00.15   0:00.06 
                  4074         0.0 S     4T   0:00.09   0:00.04 
                  4074         0.0 S     4T   0:00.00   0:00.00 
someuser      4168   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                  4168         0.0 S     4T   0:00.00   0:00.00 
someuser      5222   ??    0.0 S    31T   2:04.89   9:15.88 /usr/bin/some_command with some parameters
                  5222         0.0 S    31T   0:00.14   0:00.16 
                  5222         0.0 S     0T   0:00.12   0:00.09 
                  5222         0.0 S    31T   0:16.89   0:21.20 
                  5222         0.0 S    31T   0:00.03   0:00.02 
                  5222         0.0 S    31T   0:07.50   0:29.90 
                  5222         0.0 S    31T   0:01.60   0:02.46 
                  5222         0.0 S    31T   0:00.60   0:01.87 
                  5222         0.0 S    31T   0:00.58   0:01.99 
                  5222         0.0 S    31T   0:00.59   0:01.92 
                  5222         0.0 S    31T   0:00.58   0:01.89 
                  5222         0.0 S    31T   0:00.03   0:00.07 
                  5222         0.0 S    31T   0:00.03   0:00.01 
                  5222         0.0 S    31T   0:00.43   0:00.16 
                  5222         0.0 S    31T   0:00.40   0:00.15 
                  5222         0.0 S    31T   0:00.01   0:00.01 
                  5222         0.0 S    31T   0:00.01   0:00.01 
                  5222         0.0 S    31T   0:00.00   0:00.00 
                  5222         0.0 S    31T   0:00.01   0:00.01 
someuser      5252   ??    0.0 S    47T   0:01.94   0:04.23 /usr/bin/some_command with some parameters
                  5252         0.0 S    31T   0:00.30   0:00.22 
                  5252         0.0 S    31T   0:00.44   0:00.21 
                  5252         0.0 S     0T   0:00.13   0:00.09 
                  5252         0.0 S    31T   0:00.37   0:00.17 
                  5252         0.0 S    19T   0:00.00   0:00.00 
                  5252         0.0 S    31T   0:00.05   0:00.02 
                  5252         0.0 S    31T   0:00.01   0:00.00 
                  5252         0.0 S    31T   0:00.00   0:00.00 
_fpsd             5347   ??    0.0 S    31T   0:00.17   0:00.04 /usr/bin/some_command with some parameters
someuser      5407   ??    0.0 S    31T   0:00.45   0:00.24 /usr/bin/some_command with some parameters
                  5407         0.0 S    37T   0:00.00   0:00.00 
nobody            6280   ??    0.0 S    31T   0:00.00   0:00.02 /usr/bin/some_command with some parameters
                  6280         0.0 S    31T   0:00.40   0:00.16 
someuser      6305   ??    1.3 S    46T  14:38.38  21:54.25 /usr/bin/some_command with some parameters
                  6305         0.0 S    31T   0:00.58   0:03.33 
                  6305         0.0 S    31T   1:56.75   2:30.84 
                  6305         0.0 S    31T   0:00.19   0:05.45 
                  6305         0.0 S    31T   0:55.35   9:47.97 
                  6305         0.0 S    31T   0:02.03   0:12.22 
                  6305         0.2 S    31T   0:08.09   1:37.46 
                  6305         0.0 S    31T   0:19.19   0:24.56 
                  6305         0.0 S    31T   0:00.54   0:03.37 
                  6305         0.0 S    31T   0:00.43   0:00.52 
                  6305         0.0 S    31T   0:00.00   0:00.00 
                  6305         0.0 S    31T   0:00.00   0:00.06 
                  6305         0.0 S    31T   1:14.17  18:13.85 
                  6305         0.0 S    31T   0:19.65   1:18.76 
                  6305         0.0 S    31T   0:03.51   0:09.72 
                  6305         0.0 S    31T   0:00.22   0:00.13 
                  6305         0.0 S    31T   0:32.14   0:20.07 
                  6305         0.0 S    31T   0:00.03   0:00.00 
                  6305         0.0 S    31T   0:00.02   0:00.01 
                  6305         0.0 S    31T   0:00.10   0:00.08 
                  6305         0.0 S    31T   1:56.78   2:30.94 
                  6305         0.0 S    31T   1:56.75   2:31.11 
                  6305         0.0 S    31T   1:56.49   2:31.40 
                  6305         0.0 S    31T   1:56.60   2:30.67 
                  6305         0.0 S    31T   1:56.62   2:30.67 
                  6305         0.0 S    31T   1:56.76   2:31.07 
                  6305         0.0 S    31T   1:56.71   2:30.79 
                  6305         0.0 S    31T   1:56.79   2:30.63 
                  6305         0.0 S    31T   1:56.53   2:30.88 
                  6305         0.0 S    31T   0:00.11   0:04.80 
                  6305         0.0 S    31T   0:00.07   0:03.24 
                  6305         0.0 S    31T   0:00.05   0:02.38 
                  6305         0.0 S    46T   2:56.91   2:01.51 
                  6305         3.3 S    31T  12:58.58  72:36.81 
                  6305         0.0 S    31T   0:55.46   9:47.97 
                  6305         0.0 S    31T   0:55.40   9:47.91 
                  6305         0.0 S    31T   0:01.74   0:02.82 
                  6305         0.3 S    31T   4:43.67  12:23.04 
                  6305         0.0 S    31T   0:01.57   0:03.01 
                  6305         0.2 S    31T   1:10.77   2:20.80 
                  6305         0.0 S    31T   0:02.30   0:02.43 
                  6305         0.0 S    31T   0:03.38   0:02.56 
                  6305         0.0 S    31T   0:03.83   0:02.92 
                  6305         0.0 S    31T   0:00.00   0:00.00 
                  6305         0.0 S    31T   0:14.64   0:17.93 
                  6305         0.0 S    31T   0:00.00   0:00.00 
                  6305         0.4 S    31T   2:45.00   6:39.29 
                  6305         0.0 S    31T   0:00.03   0:01.13 
                  6305         0.0 S    31T   0:00.04   0:01.79 
                  6305         0.0 S    31T   0:00.03   0:01.41 
                  6305         0.0 S    31T   0:00.02   0:01.08 
                  6305         0.0 S    31T   0:00.26   0:02.26 
                  6305         0.0 S    31T   0:00.21   0:00.05 
                  6305         0.0 S     0T   0:02.77   0:01.00 
                  6305         0.0 S    31T   0:00.75   0:00.83 
                  6305         0.0 S    31T   0:00.02   0:00.01 
                  6305         0.0 S    31T   0:00.24   0:00.09 
                  6305         0.0 S    31T   0:00.05   0:00.02 
                  6305         0.0 S    31T   0:00.00   0:00.00 
                  6305         0.0 S    31T   0:00.03   0:00.00 
                  6305         0.0 S     0T   0:00.00   0:00.00 
                  6305         0.0 S    31T   0:00.00   0:00.00 
                  6305         0.0 S    31T   0:00.07   0:00.03 
                  6305         0.0 S    31T   0:01.45   0:01.30 
                  6305         0.0 S    31T   0:00.08   0:00.96 
                  6305         0.0 S    31T   0:00.02   0:00.83 
                  6305         0.0 S    31T   0:00.01   0:00.63 
                  6305         0.0 S    31T   0:00.01   0:00.47 
                  6305         0.0 S    31T   0:00.00   0:00.00 
                  6305         0.0 S    31T   0:01.03   0:00.80 
                  6305         0.0 S    31T   0:00.88   0:00.72 
                  6305         0.0 S    31T   0:01.09   0:00.83 
                  6305         0.0 S    31T   0:00.99   0:00.78 
                  6305         0.0 S    31T   0:00.01   0:00.32 
                  6305         0.0 S    31T   0:00.15   0:00.00 
                  6305         0.0 S    31T   0:00.09   0:00.53 
                  6305         0.0 S    31T   0:00.22   0:00.13 
                  6305         0.0 S    31T   0:00.13   0:00.48 
                  6305         0.0 S    31T   0:01.48   0:31.13 
                  6305         0.0 S    31T   0:00.19   0:00.00 
                  6305         0.0 S    31T   0:00.09   0:00.08 
                  6305         0.0 S    31T   0:07.05   0:09.79 
                  6305         0.0 S    31T   0:00.48   0:00.30 
                  6305         0.0 S    31T   0:00.05   0:00.09 
                  6305         0.0 S    31T   0:00.26   0:00.56 
                  6305         0.0 S    31T   0:00.05   0:00.23 
                  6305         0.0 S    31T   0:00.02   0:00.09 
                  6305         0.0 S    31T   0:00.38   0:01.15 
                  6305         0.0 S    31T   0:00.01   0:00.04 
                  6305         0.0 S    31T   0:00.07   0:00.90 
                  6305         0.0 S    31T   0:00.02   0:00.08 
                  6305         0.0 S    31T   0:00.00   0:00.10 
                  6305         0.0 S    31T   0:00.06   0:00.13 
                  6305         0.0 S    31T   0:00.01   0:00.08 
                  6305         0.0 S    31T   0:00.00   0:00.01 
                  6305         0.0 S    31T   0:00.04   0:00.59 
                  6305         0.0 S    31T   0:00.00   0:00.01 
                  6305         0.0 S    31T   0:00.19   0:00.27 
                  6305         0.0 S    31T   0:00.13   0:05.79 
                  6305         0.0 S    31T   0:02.17   0:17.73 
                  6305         0.0 S    31T   0:02.58   0:19.51 
                  6305         0.0 S    31T   0:01.45   0:15.04 
                  6305         0.0 S    31T   0:02.03   0:13.55 
                  6305         0.0 S    31T   0:01.58   0:12.37 
                  6305         0.0 S    31T   0:01.38   0:15.01 
                  6305         0.0 S    31T   0:01.20   0:10.89 
                  6305         0.0 S    31T   0:00.01   0:00.06 
                  6305         0.0 S    31T   0:01.75   0:15.56 
                  6305         0.0 S    31T   0:01.38   0:14.93 
                  6305         0.0 S    31T   0:01.38   0:13.37 
                  6305         0.0 S    31T   0:01.05   0:12.57 
                  6305         0.0 S    31T   0:01.17   0:13.21 
                  6305         0.0 S    31T   0:01.30   0:14.13 
                  6305         0.0 S    31T   0:00.77   0:10.35 
                  6305         0.0 S    31T   0:01.16   0:11.87 
                  6305         0.0 S    31T   0:01.37   0:14.07 
                  6305         0.0 S    31T   0:00.99   0:11.23 
                  6305         0.0 S    31T   0:00.88   0:09.94 
                  6305         0.0 S    31T   0:00.96   0:11.20 
                  6305         0.0 S    31T   0:01.04   0:13.12 
                  6305         0.0 S    31T   0:01.21   0:11.56 
                  6305         0.0 S    31T   0:01.20   0:11.02 
                  6305         0.0 S    31T   0:01.29   0:15.79 
                  6305         0.0 S    31T   0:00.63   0:08.23 
                  6305         0.0 S    31T   0:01.32   0:11.65 
                  6305         0.0 S    31T   0:01.34   0:11.90 
                  6305         0.0 S    31T   0:00.94   0:11.78 
                  6305         0.0 S    31T   0:00.01   0:00.01 
                  6305         0.0 S    31T   0:00.86   0:09.48 
                  6305         0.0 S    31T   0:00.67   0:10.34 
                  6305         0.0 S    31T   0:00.85   0:09.31 
                  6305         0.0 S    31T   0:00.97   0:11.96 
                  6305         0.0 S    31T   0:00.69   0:07.93 
                  6305         0.0 S    31T   0:00.66   0:09.77 
                  6305         0.0 S    31T   0:00.46   0:07.58 
                  6305         0.0 S    31T   0:00.75   0:08.26 
                  6305         0.0 S    31T   0:00.72   0:09.74 
                  6305         0.0 S    31T   0:00.81   0:11.11 
                  6305         0.0 S    31T   0:00.79   0:07.88 
                  6305         0.0 S    31T   0:00.44   0:06.56 
                  6305         0.0 S    31T   0:00.36   0:05.39 
                  6305         0.0 S    31T   0:00.61   0:07.06 
                  6305         0.0 S    31T   0:00.87   0:08.89 
                  6305         0.0 S    31T   0:00.62   0:08.71 
                  6305         0.0 S    31T   0:00.72   0:07.11 
                  6305         0.0 S    31T   0:00.55   0:09.69 
                  6305         0.0 S    31T   0:00.53   0:08.28 
                  6305         0.0 S    31T   0:00.58   0:06.60 
                  6305         0.0 S    31T   0:00.59   0:08.23 
                  6305         0.0 S    31T   0:00.68   0:07.10 
                  6305         0.0 S    31T   0:00.42   0:08.30 
                  6305         0.0 S    31T   0:00.69   0:08.53 
                  6305         0.0 S    31T   0:00.56   0:06.80 
                  6305         0.0 S    31T   0:00.43   0:08.04 
                  6305         0.0 S    31T   0:00.43   0:06.37 
                  6305         0.0 S    31T   0:00.65   0:08.07 
                  6305         0.0 S    31T   0:00.64   0:06.97 
                  6305         0.0 S    31T   0:00.59   0:06.51 
                  6305         0.0 S    31T   0:00.31   0:05.59 
                  6305         0.0 S    31T   0:00.40   0:04.95 
                  6305         0.0 S    31T   0:00.52   0:06.14 
                  6305         0.0 S    31T   0:00.98   0:06.32 
                  6305         0.0 S    31T   0:00.54   0:07.47 
                  6305         0.0 S    31T   0:00.37   0:05.68 
                  6305         0.0 S    31T   0:00.45   0:08.21 
                  6305         0.0 S    31T   0:00.34   0:04.88 
                  6305         0.0 S    31T   0:00.52   0:04.65 
                  6305         0.0 S    31T   0:00.50   0:05.71 
                  6305         0.0 S    31T   0:00.43   0:05.11 
                  6305         0.0 S    31T   0:00.20   0:03.59 
                  6305         0.0 S    31T   0:00.18   0:01.24 
                  6305         0.0 S    31T   0:00.20   0:01.65 
                  6305         0.0 S    31T   0:00.16   0:01.14 
                  6305         0.0 S    31T   0:00.24   0:02.09 
                  6305         0.0 S    31T   0:00.12   0:01.40 
                  6305         0.0 S    31T   0:00.11   0:01.56 
                  6305         0.0 S    31T   0:00.09   0:01.35 
                  6305         0.0 S    31T   0:00.09   0:01.50 
                  6305         0.0 S    31T   0:00.07   0:01.12 
                  6305         0.0 S    31T   0:00.17   0:02.92 
                  6305         0.0 S    31T   0:00.19   0:01.78 
                  6305         0.0 S    31T   0:00.04   0:01.05 
                  6305         0.0 S    31T   0:00.07   0:01.62 
                  6305         0.0 S    31T   0:00.08   0:01.47 
                  6305         0.0 S    31T   0:00.56   0:02.55 
                  6305         0.0 S    31T   0:00.05   0:00.76 
                  6305         0.0 S    31T   0:00.00   0:00.00 
                  6305         0.0 S    31T   0:00.00   0:00.00 
                  6305         0.0 S    31T   0:00.00   0:00.01 
                  6305         0.0 S    31T   0:00.00   0:00.00 
                  6305         0.0 S    31T   0:00.00   0:00.00 
                  6305         0.0 S    31T   0:00.01   0:00.01 
                  6305         0.0 S    31T   0:00.03   0:00.44 
                  6305         0.0 S    31T   0:00.12   0:01.07 
                  6305         0.0 S    31T   0:00.03   0:00.31 
                  6305         0.0 S    31T   0:01.55   0:07.47 
                  6305         0.0 S    31T   0:00.95   0:05.26 
                  6305         1.2 S    31T   0:00.24   0:01.77 
                  6305         0.0 S    31T   0:00.23   0:01.26 
                  6305         0.0 S    31T   0:00.17   0:01.56 
                  6305         0.0 S    31T   0:00.48   0:03.07 
                  6305         0.0 S    31T   0:00.01   0:00.08 
                  6305         0.0 S    31T   0:00.26   0:01.80 
                  6305         1.5 S    31T   0:00.17   0:01.06 
                  6305         0.0 S    31T   0:00.02   0:00.02 
                  6305         0.0 S    31T   0:00.02   0:00.14 
                  6305         0.0 S    31T   0:00.00   0:00.00 
                  6305         0.0 S    31T   0:00.00   0:00.00 
                  6305         0.0 S    31T   0:00.00   0:00.00 
                  6305         0.0 S    31T   0:00.00   0:00.00 
                  6305         0.0 S    37T   0:00.00   0:00.00 
                  6305         0.0 S     4T   0:00.00   0:00.00 
                  6305         0.0 S    37T   0:00.01   0:00.01 
                  6305         0.0 S    46T   0:00.00   0:00.00 
someuser      6351   ??    0.0 S    31T   0:00.01   0:00.01 /usr/bin/some_command with some parameters
                  6351         0.0 S    31T   0:24.98   0:11.90 
                  6351         0.0 S    31T   0:00.00   0:00.00 
someuser      6365   ??    0.0 S    31T   0:02.68   0:02.63 /usr/bin/some_command with some parameters
                  6365         0.0 S    31T   0:00.61   0:00.45 
                  6365         0.0 S    31T   0:00.01   0:00.00 
                  6365         0.0 S    31T   0:00.14   0:00.11 
                  6365         0.0 S     0T   0:00.12   0:00.10 
                  6365         0.0 S    31T   0:00.32   0:00.16 
                  6365         0.0 S    31T   0:00.53   0:00.98 
                  6365         0.0 S    31T   0:00.00   0:00.00 
someuser      6368   ??    0.0 S    31T   0:00.03   0:00.04 /usr/bin/some_command with some parameters
                  6368         0.0 S    31T   0:00.04   0:00.02 
                  6368         0.0 S     0T   0:00.14   0:00.10 
                  6368         0.0 S    31T   0:00.73   0:00.28 
                  6368         0.0 S    31T   0:00.16   0:00.03 
                  6368         0.0 S    31T   0:00.01   0:00.01 
                  6368         0.0 S    31T   0:00.00   0:00.00 
someuser      6774   ??    0.0 S    46T   0:24.25   0:42.34 /usr/bin/some_command with some parameters
                  6774         0.0 S    31T   0:04.32   0:04.53 
                  6774         0.0 S    46T   0:00.00   0:00.00 
                  6774         0.0 S    46T   0:00.00   0:00.00 
                  6774         0.0 S    31T   0:00.00   0:00.00 
someuser      6796   ??    0.0 S    46T   0:04.38   0:01.51 /usr/bin/some_command with some parameters
                  6796         0.0 S    46T   0:00.47   0:00.09 
                  6796         0.0 S    31T   0:00.00   0:00.00 
                  6796         0.0 S    37T   0:00.00   0:00.00 
someuser      6947   ??    0.0 S    31T   0:27.15   0:24.09 tmux
someuser      7649   ??    0.0 S    46T   0:04.70   0:02.03 /usr/bin/some_command with some parameters
                  7649         0.0 S    46T   0:00.43   0:00.09 
                  7649         0.0 S    19T   0:00.00   0:00.00 
                  7649         0.0 S    31T   0:00.00   0:00.00 
                  7649         0.0 S    37T   0:00.00   0:00.00 
someuser      7651   ??    0.0 S    46T   0:03.32   0:01.25 /usr/bin/some_command with some parameters
                  7651         0.0 S    46T   0:00.49   0:00.09 
                  7651         0.0 S    37T   0:00.00   0:00.00 
                  7651         0.0 S    37T   0:00.00   0:00.00 
someuser      7961   ??    0.0 S    20T   0:00.59   0:02.56 /usr/bin/some_command with some parameters
someuser      9260   ??    0.0 S    42T   0:03.22   0:04.05 /usr/bin/some_command with some parameters
                  9260         0.0 S    31T   0:42.22   0:05.66 
                  9260         0.0 S    31T   0:01.14   0:23.88 
                  9260         0.0 S    31T   0:00.12   0:00.14 
                  9260         0.0 S    31T   0:00.01   0:00.00 
                  9260         0.0 S    31T  12:00.97   1:03.81 
                  9260         0.0 S    31T   0:00.00   0:00.00 
                  9260         0.0 S    31T   0:05.92   0:03.89 
                  9260         0.0 S    31T   0:00.00   0:00.00 
                  9260         0.0 S    31T   0:02.90   0:01.01 
                  9260         0.0 S    31T   0:09.95   0:03.94 
                  9260         0.0 S    31T   0:00.00   0:00.00 
                  9260         0.0 S    31T   0:00.00   0:00.00 
                  9260         0.0 S    31T   0:00.62   0:00.40 
                  9260         0.0 S    31T   0:01.02   0:01.37 
                  9260         0.0 S    31T   0:08.48   0:02.01 
                  9260         0.0 S    31T   0:00.00   0:00.00 
                  9260         0.0 S    31T   0:01.28   0:00.30 
                  9260         0.0 S    31T   0:01.11   0:01.11 
                  9260         0.0 S    31T   0:00.01   0:00.01 
                  9260         0.0 S    31T   0:00.03   0:00.01 
                  9260         0.0 S    31T   0:09.80   0:02.43 
                  9260         0.0 S    31T   0:00.27   0:00.06 
                  9260         0.0 S    31T   0:00.00   0:00.00 
                  9260         0.0 S    19T   0:00.00   0:00.00 
                  9260         0.0 S    31T   0:01.46   0:34.31 
                  9260         0.0 S    31T   0:12.38   0:14.26 
                  9260         0.0 S    31T   0:12.50   0:14.27 
                  9260         0.0 S    31T   0:12.40   0:14.23 
                  9260         0.0 S    20T   0:01.37   0:00.59 
                  9260         0.0 S    20T   0:01.22   0:00.53 
                  9260         0.0 S    20T   0:00.07   0:00.03 
                  9260         0.0 S    61T   0:00.00   0:00.00 
                  9260         0.0 S    31T   0:00.00   0:00.00 
someuser     12403   ??    0.0 S    31T   0:04.96   0:02.66 /usr/bin/some_command with some parameters
                 12403         0.0 S    37T   0:00.65   0:00.15 
                 12403         0.0 S    37T   0:00.00   0:00.00 
someuser     13175   ??    0.0 S    46T   0:10.60   0:14.64 /usr/bin/some_command with some parameters
                 13175         0.0 S     4T   0:00.01   0:00.01 
                 13175         0.0 S    31T   0:00.06   0:00.07 
                 13175         0.0 S    31T   0:00.00   0:00.00 
                 13175         0.0 S    31T   0:00.00   0:00.00 
                 13175         0.0 S    46T   0:01.09   0:00.50 
                 13175         0.0 S    31T   0:00.05   0:00.03 
                 13175         0.0 S     4T   0:00.06   0:00.05 
                 13175         0.0 S    37T   0:00.00   0:00.00 
                 13175         0.0 S    37T   0:00.00   0:00.00 
someuser     13178   ??    0.0 S    31T   0:15.15   0:20.39 /usr/bin/some_command with some parameters
                 13178         0.0 S    31T   0:44.89   0:26.59 
                 13178         0.0 S    31T   0:00.00   0:00.00 
                 13178         0.0 S    31T   0:15.04   0:20.25 
                 13178         0.0 S    31T   0:15.16   0:20.54 
                 13178         0.0 S    31T   0:00.00   0:00.00 
                 13178         0.0 S    31T   0:14.73   0:19.94 
                 13178         0.0 S    31T   0:00.00   0:00.00 
                 13178         0.0 S    31T   0:00.00   0:00.00 
                 13178         0.0 S    31T   0:15.60   0:21.09 
                 13178         0.0 S    31T   0:00.00   0:00.00 
                 13178         0.0 S    31T   0:14.89   0:20.23 
                 13178         0.0 S    31T   0:12.79   0:17.16 
                 13178         0.0 S    31T   0:15.57   0:20.91 
                 13178         0.0 S    31T   0:15.23   0:20.53 
                 13178         0.0 S    31T   0:12.72   0:17.05 
                 13178         0.0 S    31T   0:14.85   0:20.27 
                 13178         0.0 S    31T   0:15.46   0:20.75 
                 13178         0.0 S    31T   0:08.81   0:11.94 
                 13178         0.0 S    20T   0:00.04   0:00.00 
                 13178         0.3 S    31T   0:14.74   0:19.94 
                 13178         0.2 S    31T   0:11.98   0:16.27 
someuser     13179   ??    0.0 S    31T   0:00.02   0:00.01 /usr/bin/some_command with some parameters
                 13179         0.0 S    31T   0:00.25   0:00.12 
                 13179         0.0 S    31T   0:00.00   0:00.00 
                 13179         0.0 S    31T   0:00.29   0:00.27 
                 13179         0.0 S    31T   0:00.00   0:00.00 
                 13179         0.0 S    31T   0:00.33   0:00.29 
                 13179         0.0 S    31T   0:00.00   0:00.00 
                 13179         0.0 S    31T   0:00.30   0:00.29 
                 13179         0.0 S    31T   0:00.24   0:00.21 
                 13179         0.0 S    31T   0:00.32   0:00.26 
                 13179         0.0 S    31T   0:00.29   0:00.27 
                 13179         0.0 S    31T   0:00.31   0:00.27 
                 13179         0.0 S    31T   0:00.29   0:00.28 
                 13179         0.0 S    31T   0:00.22   0:00.24 
                 13179         0.0 S    31T   0:00.29   0:00.27 
                 13179         0.0 S    31T   0:00.29   0:00.26 
                 13179         0.0 S    31T   0:00.25   0:00.24 
                 13179         0.0 S    31T   0:00.27   0:00.24 
                 13179         0.0 S    31T   0:00.21   0:00.16 
someuser     13201   ??    0.0 S    31T   0:00.42   0:00.33 /usr/bin/some_command with some parameters
                 13201         0.0 S    31T   0:00.35   0:00.18 
                 13201         0.0 S    31T   0:00.00   0:00.00 
                 13201         0.0 S    31T   0:00.07   0:00.01 
                 13201         0.0 S    31T   0:00.01   0:00.00 
                 13201         0.0 S    31T   0:00.00   0:00.00 
                 13201         0.0 S    31T   0:00.00   0:00.00 
                 13201         0.0 S    31T   0:00.00   0:00.00 
                 13201         0.0 S    31T   0:00.00   0:00.00 
                 13201         0.0 S    31T   0:00.00   0:00.00 
                 13201         0.0 S    31T   0:00.00   0:00.00 
                 13201         0.0 S    31T   0:00.34   0:00.30 
                 13201         0.0 S    31T   0:00.00   0:00.00 
                 13201         0.0 S    31T   0:00.38   0:00.34 
                 13201         0.0 S    31T   0:00.40   0:00.32 
                 13201         0.0 S    31T   0:00.36   0:00.30 
                 13201         0.0 S    31T   0:00.39   0:00.34 
                 13201         0.0 S    31T   0:00.36   0:00.31 
                 13201         0.0 S    31T   0:00.37   0:00.32 
                 13201         0.0 S    31T   0:00.39   0:00.32 
                 13201         0.0 S    31T   0:00.44   0:00.35 
                 13201         0.0 S    31T   0:00.36   0:00.32 
                 13201         0.0 S    31T   0:00.32   0:00.31 
                 13201         0.0 S    31T   0:00.41   0:00.34 
                 13201         0.0 S    31T   0:00.38   0:00.31 
someuser     13207   ??    0.0 S    31T   0:12.54   0:15.84 com.docker.vpnkit --ethernet fd:3 --diagnostics fd:4 --pcap fd:5 --vsock-path vms/0/connect --host-names host.docker.internal,docker.for.mac.host.internal,docker.for.mac.localhost --listen-backlog 32 --mtu 1500 --allowed-bind-addresses 0.0.0.0 --http /usr/bin/some_command with some parameters
                 13207         0.0 S    31T   0:03.22   0:00.28 
                 13207         0.0 S    31T   0:03.23   0:00.28 
                 13207         0.0 S    31T   0:03.22   0:00.28 
                 13207         0.0 S    31T   0:03.22   0:00.28 
someuser     13208   ??    0.0 S    31T   0:00.05   0:00.02 docker serve --address unix:///Users/someuser/.docker/run/docker-cli-api.sock
                 13208         0.0 S    31T   0:01.57   0:00.98 
                 13208         0.0 S    31T   0:00.81   0:00.91 
                 13208         0.0 S    31T   0:00.86   0:00.97 
                 13208         0.0 S    31T   0:00.76   0:00.85 
                 13208         0.0 S    31T   0:00.79   0:00.92 
                 13208         0.0 S    31T   0:00.76   0:00.86 
                 13208         0.0 S    31T   0:00.81   0:00.94 
                 13208         0.0 S    31T   0:00.75   0:00.87 
                 13208         0.0 S    31T   0:00.80   0:00.92 
                 13208         0.0 S    31T   0:00.75   0:00.89 
                 13208         0.0 S    31T   0:00.00   0:00.00 
                 13208         0.0 S    31T   0:00.72   0:00.90 
                 13208         0.0 S    31T   0:00.00   0:00.00 
                 13208         0.0 S    31T   0:00.84   0:00.91 
                 13208         0.0 S    31T   0:00.73   0:00.79 
                 13208         0.0 S    31T   0:00.87   0:00.96 
                 13208         0.0 S    31T   0:00.59   0:00.63 
someuser     13209   ??    0.0 S    31T   0:21.43   0:12.21 vpnkit-bridge --disable wsl2-cross-distro-service,wsl2-bootstrap-expose-ports,transfused --addr listen://1999 host
                 13209         0.0 S    31T   1:09.44   0:39.38 
                 13209         0.0 S    31T   0:19.72   0:11.04 
                 13209         0.1 S    31T   0:20.30   0:11.48 
                 13209         0.0 S    31T   0:20.49   0:11.54 
                 13209         0.0 S    31T   0:19.68   0:11.18 
                 13209         0.0 S    31T   0:00.00   0:00.00 
                 13209         0.0 S    31T   0:18.70   0:10.39 
                 13209         0.0 S    31T   0:20.89   0:11.77 
                 13209         0.0 S    31T   0:19.80   0:11.19 
                 13209         0.0 S    31T   0:19.19   0:10.81 
                 13209         0.0 S    31T   0:15.30   0:08.80 
                 13209         0.0 S    31T   0:21.64   0:12.16 
                 13209         0.0 S    31T   0:18.95   0:10.76 
                 13209         0.0 S    31T   0:20.61   0:11.57 
                 13209         0.0 S    31T   0:14.18   0:07.93 
someuser     13210   ??    0.0 S    31T   0:02.99   0:02.18 com.docker.driver.amd64-linux -addr fd:3 -debug -native-api
                 13210         0.0 S    31T   0:08.70   0:04.96 
                 13210         0.0 S    31T   0:03.44   0:02.47 
                 13210         0.0 S    31T   0:02.62   0:01.93 
                 13210         0.0 S    31T   0:02.40   0:01.88 
                 13210         0.0 S    31T   0:00.00   0:00.00 
                 13210         0.0 S    31T   0:02.96   0:02.22 
                 13210         0.0 S    31T   0:02.72   0:02.04 
                 13210         0.0 S    31T   0:02.96   0:02.15 
                 13210         0.0 S    31T   0:03.01   0:02.23 
                 13210         0.0 S    31T   0:00.00   0:00.00 
                 13210         0.0 S    31T   0:00.00   0:00.00 
                 13210         0.0 S    31T   0:03.18   0:02.38 
                 13210         0.0 S    31T   0:02.95   0:02.21 
                 13210         0.0 S    31T   0:03.37   0:02.49 
                 13210         0.0 S    31T   0:00.00   0:00.00 
                 13210         0.0 S    31T   0:02.96   0:02.23 
                 13210         0.0 S    31T   0:02.66   0:02.06 
                 13210         0.0 S    31T   0:02.78   0:02.15 
someuser     13219   ??    0.0 S    31T   0:00.03   0:00.01 com.docker.hyperkit -A -u -F vms/0/hyperkit.pid -c 6 -m 2048M -s 0:0,hostbridge -s 31,lpc -s 1:0,virtio-vpnkit,path=vpnkit.eth.sock,uuid=254b47b9-08d1-4825-812d-21a5c072a954 -U e5194447-4cb5-4962-9f8a-6926b08ac2b9 -s 2:0,virtio-blk,/Users/someuser/Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw -s 3,virtio-sock,guest_cid=3,path=vms/0,guest_forwards=2376;1525 -s 4,virtio-rnd -l com1,null,asl,log=vms/0/console-ring -f kexec,/Applications/Docker.app/Contents/Resources/linuxkit/kernel,/Applications/Docker.app/Contents/Resources/linuxkit/initrd.img,earlyprintk=serial page_poison=1 vsyscall=emulate panic=1 nospec_store_bypass_disable noibrs noibpb no_stf_barrier mitigations=off console=ttyS0 console=ttyS1  vpnkit.connect=connect://2/1999
                 13219         0.0 S    31T   0:00.24   0:00.08 
                 13219         0.0 S    31T   0:47.37   0:14.79 
                 13219         0.6 S    31T  18:03.18   5:13.88 
                 13219         0.0 S    31T   0:01.02   0:00.21 
                 13219         0.0 S    31T   0:03.91   0:01.07 
                 13219         0.0 S    31T   0:04.41   0:00.07 
                 13219         0.0 S    31T   1:26.07   0:15.54 
                 13219         0.0 S    31T   1:22.96   0:18.63 
                 13219         1.3 S    31T  40:46.89   8:59.16 
                 13219         0.6 S    31T  42:32.76   9:23.27 
                 13219         0.9 S    31T  41:26.00   9:08.48 
                 13219         3.9 S    31T  40:25.64   9:00.49 
                 13219         1.4 S    31T  37:32.72   8:13.76 
                 13219         1.5 S    31T  49:41.46  11:22.61 
                 13219         0.0 S    31T   0:00.00   0:00.00 
someuser     13565   ??    0.0 S    47T   0:01.95   0:03.59 /usr/bin/some_command with some parameters
                 13565         0.0 S    31T   0:00.29   0:00.20 
                 13565         0.0 S    31T   0:00.44   0:00.19 
                 13565         0.0 S     0T   0:00.12   0:00.10 
                 13565         0.0 S    31T   0:00.14   0:00.06 
                 13565         0.0 S    19T   0:00.00   0:00.00 
                 13565         0.0 S    61T   0:00.00   0:00.00 
someuser     15552   ??    0.0 S    31T   0:06.78   0:11.04 /usr/bin/some_command with some parameters
                 15552         0.0 S    31T   0:00.00   0:00.00 
                 15552         0.0 S     0T   0:00.01   0:00.01 
                 15552         0.0 S    31T   0:00.65   0:00.39 
                 15552         0.0 S    31T   0:00.01   0:00.01 
                 15552         0.0 S    31T   0:00.06   0:00.26 
                 15552         0.0 S    31T   0:00.00   0:00.00 
                 15552         0.0 S    31T   0:00.01   0:00.28 
                 15552         0.0 S    31T   0:00.01   0:00.32 
                 15552         0.0 S    31T   0:00.01   0:00.30 
                 15552         0.0 S    31T   0:00.01   0:00.27 
                 15552         0.0 S    31T   0:00.00   0:00.00 
                 15552         0.0 S    31T   0:00.05   0:00.31 
                 15552         0.0 S    31T   0:00.11   0:00.02 
                 15552         0.0 S    31T   0:00.05   0:00.02 
                 15552         0.0 S    31T   0:00.10   0:00.03 
someuser     20135   ??    0.0 S    31T   0:06.37   0:04.95 /usr/bin/some_command with some parameters
                 20135         0.0 S    31T   0:00.01   0:00.00 
                 20135         0.0 S     0T   0:00.13   0:00.09 
                 20135         0.0 S    31T   0:01.40   0:00.74 
                 20135         0.0 S    31T   0:00.00   0:00.00 
                 20135         0.0 S    31T   0:00.22   0:00.17 
                 20135         0.0 S    31T   0:00.00   0:00.00 
                 20135         0.0 S    31T   0:00.00   0:00.00 
                 20135         0.0 S    31T   0:00.01   0:00.00 
                 20135         0.0 S    31T   0:00.01   0:00.00 
                 20135         0.0 S    31T   0:00.01   0:00.00 
                 20135         0.0 S    31T   0:00.00   0:00.00 
                 20135         0.0 S    31T   0:00.44   0:00.13 
                 20135         0.0 S    31T   0:00.03   0:00.01 
                 20135         0.0 S    31T   0:00.01   0:00.00 
someuser     22878   ??    0.0 S    31T   0:03.45   0:01.37 /usr/bin/some_command with some parameters
                 22878         0.0 S    37T   0:00.47   0:00.09 
                 22878         0.0 S    37T   0:00.00   0:00.00 
root             23677   ??    0.0 S     4T   0:00.03   0:00.03 /usr/bin/some_command with some parameters
                 23677         0.0 S     4T   0:00.00   0:00.00 
someuser     25255   ??    0.1 S    42T   6:20.26   0:41.43 /usr/bin/some_command with some parameters
someuser     25257   ??    0.0 S    42T   0:33.20   0:39.82 /usr/bin/some_command with some parameters
                 25257         0.0 S    31T   3:27.77   0:49.18 
                 25257         0.0 S    31T   0:05.84   0:06.98 
                 25257         0.0 S    31T   0:00.00   0:00.00 
                 25257         0.0 S    31T   0:00.00   0:00.00 
                 25257         0.0 S    31T   0:04.04   0:04.28 
                 25257         0.2 S    31T   5:43.56   4:03.97 
                 25257         0.0 S    31T   0:00.07   0:00.03 
                 25257         0.0 S    31T   0:00.12   0:00.09 
                 25257         0.0 S    31T   0:14.99   0:08.07 
                 25257         0.0 S    31T   0:00.51   0:01.78 
                 25257         0.0 S    31T   0:05.98   0:07.04 
                 25257         0.0 S    31T   0:06.15   0:06.98 
                 25257         0.0 S    31T   0:05.36   0:06.37 
                 25257         0.0 S    31T   0:05.34   0:06.34 
                 25257         0.0 S    19T   0:00.00   0:00.00 
                 25257         0.0 S    31T   0:05.13   0:06.33 
                 25257         0.0 S    31T   0:03.31   0:04.24 
                 25257         0.0 S    31T   0:03.52   0:04.25 
                 25257         0.0 S    61T   0:00.00   0:00.00 
                 25257         0.0 S    20T   0:00.00   0:00.00 
someuser     25320   ??    0.0 S    31T   0:01.42   0:00.23 /usr/bin/some_command with some parameters
                 25320         0.0 S    31T   0:03.79   0:03.03 
root             27923   ??    0.0 S    31T   0:00.01   0:00.00 /usr/bin/some_command with some parameters
                 27923         0.0 S     4T   0:00.00   0:00.00 
someuser     29226   ??    0.0 S     4T   0:00.37   0:00.03 /usr/bin/some_command with some parameters
                 29226         0.0 S     4T   0:00.01   0:00.00 
                 29226         0.0 S     4T   0:00.00   0:00.00 
someuser     29631   ??    0.0 S    31T   0:21.95   0:26.43 /usr/bin/some_command with some parameters
                 29631         0.0 S    31T   0:00.00   0:00.00 
                 29631         0.0 S     0T   0:00.08   0:00.04 
                 29631         0.0 S    31T   0:01.79   0:01.89 
                 29631         0.0 S    31T   0:00.01   0:00.01 
                 29631         0.0 S    31T   0:00.30   0:01.31 
                 29631         0.0 S    31T   0:00.00   0:00.00 
                 29631         0.0 S    31T   0:00.06   0:00.18 
                 29631         0.0 S    31T   0:00.03   0:00.22 
                 29631         0.0 S    31T   0:00.02   0:00.16 
                 29631         0.0 S    31T   0:00.05   0:00.18 
                 29631         0.0 S    31T   0:00.01   0:00.04 
                 29631         0.0 S    31T   0:00.41   0:00.08 
                 29631         0.0 S    31T   0:00.05   0:00.01 
                 29631         0.0 S    31T   0:00.06   0:00.03 
someuser     29686   ??    0.0 S    31T   0:37.11   1:54.63 /usr/bin/some_command with some parameters
                 29686         0.0 S    31T   0:00.00   0:00.00 
                 29686         0.0 S     0T   0:00.06   0:00.04 
                 29686         0.0 S    31T   0:03.42   0:03.91 
                 29686         0.0 S    31T   0:00.01   0:00.02 
                 29686         0.0 S    31T   0:00.59   0:04.69 
                 29686         0.0 S    31T   0:00.00   0:00.00 
                 29686         0.0 S    31T   0:00.02   0:00.08 
                 29686         0.0 S    31T   0:00.02   0:00.08 
                 29686         0.0 S    31T   0:00.02   0:00.08 
                 29686         0.0 S    31T   0:00.03   0:00.08 
                 29686         0.0 S    31T   0:00.00   0:00.00 
                 29686         0.0 S    31T   0:00.22   0:00.07 
                 29686         0.0 S    31T   0:00.18   0:00.07 
                 29686         0.0 S    31T   0:00.00   0:00.00 
someuser     29894   ??    0.0 S    31T   0:03.26   0:07.72 /usr/bin/some_command with some parameters
                 29894         0.0 S    31T   0:00.00   0:00.00 
                 29894         0.0 S     0T   0:00.04   0:00.03 
                 29894         0.0 S    31T   0:00.43   0:00.21 
                 29894         0.0 S    31T   0:00.00   0:00.00 
                 29894         0.0 S    31T   0:00.10   0:00.46 
                 29894         0.0 S    31T   0:00.00   0:00.00 
                 29894         0.0 S    31T   0:00.01   0:00.06 
                 29894         0.0 S    31T   0:00.01   0:00.07 
                 29894         0.0 S    31T   0:00.02   0:00.12 
                 29894         0.0 S    31T   0:00.01   0:00.07 
                 29894         0.0 S    31T   0:00.00   0:00.00 
                 29894         0.0 S    31T   0:00.21   0:00.04 
                 29894         0.0 S    31T   0:00.09   0:00.05 
                 29894         0.0 S    31T   0:00.02   0:00.01 
someuser     31499   ??    0.0 S    31T   0:24.21   0:26.45 /usr/bin/some_command with some parameters
                 31499         0.0 S    31T   0:00.00   0:00.00 
                 31499         0.0 S     0T   0:00.05   0:00.04 
                 31499         0.0 S    31T   0:01.51   0:01.19 
                 31499         0.0 S    31T   0:00.01   0:00.01 
                 31499         0.0 S    31T   0:00.22   0:00.86 
                 31499         0.0 S    31T   0:00.00   0:00.00 
                 31499         0.0 S    31T   0:00.02   0:00.24 
                 31499         0.0 S    31T   0:00.06   0:00.30 
                 31499         0.0 S    31T   0:00.02   0:00.24 
                 31499         0.0 S    31T   0:00.04   0:00.39 
                 31499         0.0 S    31T   0:00.00   0:00.00 
                 31499         0.0 S    31T   0:00.44   0:00.08 
                 31499         0.0 S    31T   0:00.07   0:00.02 
                 31499         0.0 S    31T   0:00.07   0:00.04 
someuser     31632   ??    0.0 S    31T   0:33.04   3:00.11 /usr/bin/some_command with some parameters
                 31632         0.0 S    31T   0:00.00   0:00.00 
                 31632         0.0 S     0T   0:00.07   0:00.04 
                 31632         0.0 S    31T   0:07.05   0:08.22 
                 31632         0.0 S    31T   0:00.01   0:00.01 
                 31632         0.0 S    31T   0:07.97   0:34.81 
                 31632         0.0 S    31T   0:00.00   0:00.00 
                 31632         0.0 S    31T   0:00.38   0:05.44 
                 31632         0.0 S    31T   0:00.40   0:05.95 
                 31632         0.0 S    31T   0:00.39   0:05.04 
                 31632         0.0 S    31T   0:00.42   0:05.37 
                 31632         0.0 S    31T   0:00.00   0:00.00 
                 31632         0.0 S    31T   0:00.44   0:00.07 
                 31632         0.0 S    31T   0:00.12   0:00.04 
                 31632         0.0 S    31T   0:00.07   0:00.06 
                 31632         0.0 S    31T   0:00.00   0:00.00 
someuser     32179   ??    0.0 S     4T   0:11.92   0:31.08 /usr/bin/some_command with some parameters
                 32179         0.0 S     4T   0:01.70   0:00.46 
                 32179         0.0 S     4T   0:00.00   0:00.00 
someuser     32424   ??    0.0 S    31T   0:01.39   0:02.07 /usr/bin/some_command with some parameters
                 32424         0.0 S    31T   0:00.00   0:00.00 
                 32424         0.0 S     0T   0:00.04   0:00.03 
                 32424         0.0 S    31T   0:00.30   0:00.14 
                 32424         0.0 S    31T   0:00.00   0:00.00 
                 32424         0.0 S    31T   0:00.02   0:00.08 
                 32424         0.0 S    31T   0:00.00   0:00.00 
                 32424         0.0 S    31T   0:00.00   0:00.00 
                 32424         0.0 S    31T   0:00.00   0:00.01 
                 32424         0.0 S    31T   0:00.00   0:00.01 
                 32424         0.0 S    31T   0:00.00   0:00.01 
                 32424         0.0 S    31T   0:00.00   0:00.00 
                 32424         0.0 S    31T   0:00.16   0:00.04 
                 32424         0.0 S    31T   0:00.05   0:00.04 
                 32424         0.0 S    31T   0:00.01   0:00.00 
someuser     33878   ??    0.0 S     4T   0:25.60   0:38.00 /usr/bin/some_command with some parameters
                 33878         0.0 S     4T   1:25.59   0:20.82 
                 33878         0.0 S     4T   0:00.97   0:00.64 
                 33878         0.0 S     3T   0:00.22   0:00.19 
                 33878         0.0 S     4T   0:09.85   0:10.18 
                 33878         0.0 S     4T   0:00.69   0:01.10 
                 33878         0.0 S     4T   0:00.65   0:00.32 
                 33878         0.0 S     4T   0:00.58   0:00.42 
                 33878         0.0 S     4T   0:00.00   0:00.00 
                 33878         0.0 S     4T   0:00.00   0:00.00 
someuser     33945   ??    0.0 S    42T   0:02.18   0:02.60 /usr/bin/some_command with some parameters
                 33945         0.0 S    31T   0:21.66   0:03.84 
                 33945         0.0 S    31T   0:00.88   0:12.15 
                 33945         0.0 S    31T   0:00.23   0:00.19 
                 33945         0.0 S    31T   0:00.01   0:00.00 
                 33945         0.0 S    31T  17:48.57   0:24.29 
                 33945         0.0 S    31T  30:13.52   2:32.90 
                 33945         0.0 S    31T   0:00.00   0:00.00 
                 33945         0.0 S    31T   0:08.96   0:05.76 
                 33945         0.0 S    31T   0:00.00   0:00.00 
                 33945         0.0 S    31T   0:04.72   0:01.54 
                 33945         0.0 S    31T   0:16.20   0:06.16 
                 33945         0.0 S    31T   0:01.72   0:00.32 
                 33945         0.0 S    31T   0:00.00   0:00.00 
                 33945         0.0 S    31T   0:01.13   0:00.61 
                 33945         0.0 S    31T   0:01.56   0:02.05 
                 33945         0.0 S    31T   0:19.88   0:15.23 
                 33945         0.0 S    31T   0:09.60   0:09.37 
                 33945         0.0 S    31T   0:00.00   0:00.00 
                 33945         0.0 S    31T   0:00.00   0:00.00 
                 33945         0.0 S    31T   0:03.13   0:01.01 
                 33945         0.0 S    31T   0:02.45   0:01.37 
                 33945         0.0 S    31T   0:00.00   0:00.00 
                 33945         0.0 S    31T   0:00.00   0:00.00 
                 33945         0.0 S    31T   0:13.29   0:03.91 
                 33945         0.0 S    31T   0:00.47   0:00.10 
                 33945         0.0 S    31T   0:00.00   0:00.00 
                 33945         0.0 S    19T   0:00.00   0:00.00 
                 33945         0.0 S    31T   0:00.14   0:00.07 
                 33945         0.0 S    31T   0:00.23   0:02.59 
                 33945         0.0 S    31T   0:00.00   0:00.00 
someuser     37665   ??    0.0 S    46T   0:09.04   0:10.03 /usr/bin/some_command with some parameters
                 37665         0.0 S    46T   0:00.13   0:00.07 
                 37665         0.0 S    37T   0:00.00   0:00.00 
                 37665         0.0 S    31T   0:00.00   0:00.00 
                 37665         0.0 S    37T   0:00.00   0:00.00 
someuser     37728   ??    0.0 S    31T   0:00.97   0:01.21 /usr/bin/some_command with some parameters
                 37728         0.0 S    31T   0:00.00   0:00.00 
                 37728         0.0 S     0T   0:00.03   0:00.02 
                 37728         0.0 S    31T   0:00.42   0:00.39 
                 37728         0.0 S    31T   0:00.00   0:00.00 
                 37728         0.0 S    31T   0:00.00   0:00.00 
                 37728         0.0 S    31T   0:00.00   0:00.00 
                 37728         0.0 S    31T   0:00.00   0:00.00 
                 37728         0.0 S    31T   0:00.00   0:00.00 
                 37728         0.0 S    31T   0:00.00   0:00.00 
                 37728         0.0 S    31T   0:00.00   0:00.00 
                 37728         0.0 S    31T   0:00.00   0:00.00 
                 37728         0.0 S    31T   0:00.09   0:00.03 
                 37728         0.0 S    31T   0:00.04   0:00.02 
                 37728         0.0 S    31T   0:00.00   0:00.00 
someuser     38532   ??    0.0 S     4T   0:00.07   0:00.05 /usr/bin/some_command with some parameters
                 38532         0.0 S     4T   0:00.03   0:00.01 
root             38747   ??    0.0 S     4T   0:00.06   0:00.06 /usr/bin/some_command with some parameters
                 38747         0.0 S     4T   0:00.00   0:00.00 
someuser     40037   ??    0.0 S     4T   0:09.30   0:08.43 /usr/bin/some_command with some parameters
                 40037         0.0 S     4T   0:00.00   0:00.00 
                 40037         0.0 S     4T   0:01.34   0:00.54 
                 40037         0.0 S     4T   0:00.01   0:00.00 
                 40037         0.0 S     4T   0:00.07   0:00.02 
                 40037         0.0 S     4T   0:00.00   0:00.00 
                 40037         0.0 S     4T   0:00.00   0:00.00 
someuser     40686   ??    0.0 S    31T   0:03.71   0:02.99 /usr/bin/some_command with some parameters
                 40686         0.0 S    31T   0:00.00   0:00.00 
                 40686         0.0 S     0T   0:00.03   0:00.02 
                 40686         0.0 S    31T   0:00.70   0:00.36 
                 40686         0.0 S    31T   0:00.00   0:00.00 
                 40686         0.0 S    31T   0:00.03   0:00.09 
                 40686         0.0 S    31T   0:00.10   0:00.02 
                 40686         0.0 S    31T   0:00.00   0:00.01 
                 40686         0.0 S    31T   0:00.00   0:00.00 
                 40686         0.0 S    31T   0:00.00   0:00.00 
                 40686         0.0 S    31T   0:00.00   0:00.00 
                 40686         0.0 S    31T   0:00.00   0:00.01 
                 40686         0.0 S    31T   0:00.12   0:00.03 
                 40686         0.0 S    31T   0:00.02   0:00.01 
                 40686         0.0 S    31T   0:00.01   0:00.01 
                 40686         0.0 S    31T   0:00.03   0:00.01 
someuser     40698   ??    0.0 S    31T   0:03.41   0:05.44 /usr/bin/some_command with some parameters
                 40698         0.0 S    31T   0:00.00   0:00.00 
                 40698         0.0 S     0T   0:00.03   0:00.02 
                 40698         0.0 S    31T   0:00.37   0:00.17 
                 40698         0.0 S    31T   0:00.00   0:00.00 
                 40698         0.0 S    31T   0:00.05   0:00.17 
                 40698         0.0 S    31T   0:00.00   0:00.00 
                 40698         0.0 S    31T   0:00.00   0:00.01 
                 40698         0.0 S    31T   0:00.00   0:00.01 
                 40698         0.0 S    31T   0:00.00   0:00.01 
                 40698         0.0 S    31T   0:00.00   0:00.02 
                 40698         0.0 S    31T   0:00.00   0:00.00 
                 40698         0.0 S    31T   0:00.00   0:00.00 
                 40698         0.0 S    31T   0:00.24   0:00.04 
                 40698         0.0 S    31T   0:00.02   0:00.00 
                 40698         0.0 S    31T   0:00.01   0:00.00 
someuser     40707   ??    0.0 S    31T   0:01.40   0:00.84 /usr/bin/some_command with some parameters
                 40707         0.0 S    31T   0:00.00   0:00.00 
                 40707         0.0 S     0T   0:00.04   0:00.02 
                 40707         0.0 S    31T   0:00.28   0:00.12 
                 40707         0.0 S    31T   0:00.00   0:00.00 
                 40707         0.0 S    31T   0:00.03   0:00.05 
                 40707         0.0 S    31T   0:00.00   0:00.00 
                 40707         0.0 S    31T   0:00.00   0:00.00 
                 40707         0.0 S    31T   0:00.00   0:00.00 
                 40707         0.0 S    31T   0:00.00   0:00.01 
                 40707         0.0 S    31T   0:00.00   0:00.00 
                 40707         0.0 S    31T   0:00.00   0:00.00 
                 40707         0.0 S    31T   0:00.10   0:00.03 
                 40707         0.0 S    31T   0:00.02   0:00.00 
                 40707         0.0 S    31T   0:00.01   0:00.01 
someuser     41159   ??    0.0 S    31T   0:00.78   0:00.57 /usr/bin/some_command with some parameters
                 41159         0.0 S    31T   0:00.00   0:00.00 
                 41159         0.0 S     0T   0:00.03   0:00.02 
                 41159         0.0 S    31T   0:00.21   0:00.09 
                 41159         0.0 S    31T   0:00.00   0:00.00 
                 41159         0.0 S    31T   0:00.02   0:00.07 
                 41159         0.0 S    31T   0:00.00   0:00.00 
                 41159         0.0 S    31T   0:00.00   0:00.01 
                 41159         0.0 S    31T   0:00.00   0:00.00 
                 41159         0.0 S    31T   0:00.00   0:00.00 
                 41159         0.0 S    31T   0:00.00   0:00.00 
                 41159         0.0 S    31T   0:00.00   0:00.00 
                 41159         0.0 S    31T   0:00.11   0:00.03 
                 41159         0.0 S    31T   0:00.04   0:00.03 
                 41159         0.0 S    31T   0:00.01   0:00.00 
root             41458   ??    0.0 S    31T   0:00.24   0:00.05 /usr/bin/some_command with some parameters
                 41458         0.0 S     4T   0:00.00   0:00.00 
root             41491   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 41491         0.0 S     4T   0:00.00   0:00.00 
someuser     41501   ??    0.0 S     4T   0:00.04   0:00.04 /usr/bin/some_command with some parameters
                 41501         0.0 S     4T   0:00.02   0:00.01 
someuser     41507   ??    0.0 S     4T   0:00.61   0:01.35 /usr/bin/some_command with some parameters
                 41507         0.0 S     4T   0:00.05   0:00.04 
                 41507         0.0 S     4T   0:00.04   0:00.04 
                 41507         0.0 S     4T   0:00.02   0:00.02 
                 41507         0.0 S     4T   0:00.01   0:00.01 
                 41507         0.0 S     4T   0:00.00   0:00.00 
root             41513   ??    0.0 S     4T   0:00.02   0:00.02 /usr/bin/some_command with some parameters
                 41513         0.0 S     4T   0:00.00   0:00.00 
root             41520   ??    0.0 S     4T   0:00.01   0:00.03 /usr/bin/some_command with some parameters
                 41520         0.0 S     4T   0:00.00   0:00.00 
someuser     41747   ??    0.0 S     4T   0:00.34   0:00.10 /usr/bin/some_command with some parameters
                 41747         0.0 S     4T   0:00.00   0:00.00 
                 41747         0.0 S     4T   0:00.00   0:00.00 
root             41837   ??    0.0 S     4T   0:00.24   0:00.19 /usr/bin/some_command with some parameters
                 41837         0.0 S     4T   0:00.00   0:00.00 
                 41837         0.0 S     4T   0:00.01   0:00.00 
root             41852   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 41852         0.0 S     4T   0:00.00   0:00.00 
root             41855   ??    0.0 S     4T   0:00.02   0:00.05 /usr/bin/some_command with some parameters
                 41855         0.0 S     4T   0:00.00   0:00.00 
someuser     41869   ??    0.0 S     4T   0:00.01   0:00.04 /usr/bin/some_command with some parameters
                 41869         0.0 S     4T   0:00.01   0:00.00 
someuser     41875   ??    0.0 S     4T   0:00.01   0:00.01 /usr/bin/some_command with some parameters
                 41875         0.0 S     4T   0:00.00   0:00.00 
someuser     41878   ??    0.0 S    46R   0:00.18   0:00.08 /usr/bin/some_command with some parameters
                 41878         0.0 S    20T   0:00.00   0:00.00 
root             41886   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 41886         0.0 S     4T   0:00.00   0:00.01 
root             41890   ??    0.0 S     4T   0:00.08   0:00.02 /usr/bin/some_command with some parameters
                 41890         0.0 S     4T   0:00.01   0:00.00 
                 41890         0.0 S     4T   0:00.00   0:00.00 
                 41890         0.0 S     4T   0:00.00   0:00.00 
root             41897   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 41897         0.0 S     4T   0:00.15   0:00.04 
someuser     41908   ??    0.0 S    31T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 41908         0.0 S    37T   0:00.00   0:00.00 
                 41908         0.0 S    37T   0:00.00   0:00.00 
                 41908         0.0 S    31T   0:00.00   0:00.00 
root             41912   ??    0.0 S     4T   0:00.06   0:00.03 /usr/bin/some_command with some parameters
                 41912         0.0 S     4T   0:00.00   0:00.00 
root             41926   ??    0.0 S    31T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 41926         0.0 S    20T   0:00.00   0:00.00 
                 41926         0.0 S    31T   0:01.15   0:00.50 
                 41926         0.0 S    31T   0:00.01   0:00.01 
_netbios         42029   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 42029         0.0 S     4T   0:00.00   0:00.00 
someuser     42082   ??    0.0 S    20T   0:00.34   0:00.31 /usr/bin/some_command with some parameters
                 42082         0.0 S    20T   0:00.03   0:00.01 
                 42082         0.0 S    20T   0:00.00   0:00.00 
                 42082         0.0 S    20T   0:00.00   0:00.00 
_driverkit       42094   ??    0.0 S    63R   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 42094         0.0 S    31T   0:00.00   0:00.00 
_driverkit       42095   ??    0.0 S    63R   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 42095         0.0 S    31T   0:00.00   0:00.00 
_driverkit       42096   ??    0.0 S    63R   0:00.75   0:00.30 /usr/bin/some_command with some parameters
                 42096         0.0 S    31T   0:00.00   0:00.00 
_driverkit       42097   ??    0.0 S    63R   0:00.02   0:00.00 /usr/bin/some_command with some parameters
                 42097         0.0 S    31T   0:00.00   0:00.00 
_driverkit       42098   ??    0.0 S    63R   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 42098         0.0 S    31T   0:00.00   0:00.00 
_driverkit       42100   ??    0.0 S    63R   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 42100         0.0 S    31T   0:00.00   0:00.00 
root             42115   ??    0.0 S     4T   0:00.03   0:00.01 /usr/bin/some_command with some parameters
                 42115         0.0 S     4T   0:00.01   0:00.00 
someuser     42121   ??    0.0 S     4T   0:00.17   0:00.09 /usr/bin/some_command with some parameters
                 42121         0.0 S     4T   0:00.00   0:00.00 
someuser     42139   ??    0.0 S     4T   0:00.10   0:00.09 /usr/bin/some_command with some parameters
                 42139         0.0 S     4T   0:00.00   0:00.00 
someuser     42155   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 42155         0.0 S     4T   0:00.00   0:00.00 
_spotlight       42306   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 42306         0.0 S     4T   0:00.00   0:00.00 
newrelic         42930   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 42930         0.0 S     4T   0:00.00   0:00.00 
666              42931   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 42931         0.0 S     4T   0:00.00   0:00.00 
someuser     42958   ??    0.0 S    31T   0:04.06   0:01.29 /usr/bin/some_command with some parameters
                 42958         0.0 S    19T   0:00.00   0:00.00 
                 42958         0.0 S    37T   0:00.32   0:00.07 
                 42958         0.0 S    60R   0:00.00   0:00.00 
                 42958         0.0 S    55R   0:00.00   0:00.00 
                 42958         0.0 S    31T   0:00.00   0:00.00 
                 42958         0.0 S    31T   0:00.00   0:00.00 
someuser     43266   ??    0.0 S     4T   0:00.35   0:00.23 /usr/bin/some_command with some parameters
                 43266         0.0 S     4T   0:00.04   0:00.01 
                 43266         0.0 S     4T   0:00.00   0:00.00 
                 43266         0.0 S     4T   0:00.00   0:00.00 
someuser     43267   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 43267         0.0 S     4T   0:00.02   0:00.02 
someuser     43686   ??    0.0 S     4T   0:00.07   0:00.18 /usr/bin/some_command with some parameters
                 43686         0.0 S     4T   0:00.00   0:00.00 
someuser     43718   ??    0.0 S    31T   0:03.94   0:13.45 /usr/bin/some_command with some parameters
                 43718         0.0 S    31T   0:00.00   0:00.00 
                 43718         0.0 S     0T   0:00.01   0:00.01 
                 43718         0.0 S    31T   0:00.91   0:01.19 
                 43718         0.0 S    31T   0:00.00   0:00.00 
                 43718         0.0 S    31T   0:00.00   0:00.00 
                 43718         0.0 S    31T   0:00.00   0:00.00 
                 43718         0.0 S    31T   0:00.00   0:00.00 
                 43718         0.0 S    31T   0:00.00   0:00.00 
                 43718         0.0 S    31T   0:00.00   0:00.00 
                 43718         0.0 S    31T   0:00.00   0:00.00 
                 43718         0.0 S    31T   0:00.00   0:00.00 
                 43718         0.0 S    31T   0:00.01   0:00.00 
                 43718         0.0 S    31T   0:00.50   0:00.19 
                 43718         0.0 S    31T   0:00.05   0:00.04 
                 43718         0.0 S    31T   0:00.02   0:00.01 
                 43718         0.0 S    31T   0:00.02   0:00.01 
                 43718         0.0 S    31T   0:00.02   0:00.02 
                 43718         0.0 S    31T   0:00.02   0:00.02 
                 43718         0.0 S    31T   0:00.02   0:00.01 
                 43718         0.0 S    31T   0:00.03   0:00.01 
                 43718         0.0 S    31T   0:00.01   0:00.00 
                 43718         0.0 S    31T   0:00.01   0:00.00 
                 43718         0.0 S    31T   0:00.00   0:00.00 
_gamecontrollerd 43719   ??    0.0 S     4T   0:19.83   0:24.56 /usr/bin/some_command with some parameters
                 43719         0.0 S     4T   0:00.24   0:00.19 
                 43719         0.0 S     4T   0:00.04   0:00.03 
                 43719         0.0 S     4T   0:00.02   0:00.01 
                 43719         0.0 S     4T   0:00.00   0:00.00 
_coreaudiod      43720   ??    0.0 S     4T   0:00.03   0:00.01 Core Audio Driver (ZoomAudioDevice.driver)
                 43720         0.0 S     4T   0:00.23   0:00.25 
                 43720         0.0 S     4T   0:00.00   0:00.00 
someuser     43724   ??    0.0 S    20T   0:00.28   0:00.28 /usr/bin/some_command with some parameters
                 43724         0.0 S    20T   0:00.02   0:00.01 
                 43724         0.0 S    20T   0:00.00   0:00.00 
                 43724         0.0 S    20T   0:00.00   0:00.00 
someuser     43725   ??    0.0 S    31T   0:00.05   0:00.13 /usr/bin/some_command with some parameters
                 43725         0.0 S    31T   0:00.00   0:00.00 
someuser     43726   ??    0.0 S     4T   0:00.04   0:00.04 /usr/bin/some_command with some parameters
                 43726         0.0 S     4T   0:00.00   0:00.00 
someuser     43728   ??    0.0 S    31T   0:00.31   0:00.77 /usr/bin/some_command with some parameters
                 43728         0.0 S    31T   0:00.00   0:00.00 
                 43728         0.0 S     0T   0:00.01   0:00.01 
                 43728         0.0 S    31T   0:00.08   0:00.06 
                 43728         0.0 S    31T   0:00.00   0:00.00 
                 43728         0.0 S    31T   0:00.00   0:00.00 
                 43728         0.0 S    31T   0:00.00   0:00.00 
                 43728         0.0 S    31T   0:00.00   0:00.00 
                 43728         0.0 S    31T   0:00.00   0:00.00 
                 43728         0.0 S    31T   0:00.00   0:00.00 
                 43728         0.0 S    31T   0:00.00   0:00.00 
                 43728         0.0 S    31T   0:00.00   0:00.00 
                 43728         0.0 S    31T   0:00.01   0:00.00 
                 43728         0.0 S    31T   0:00.01   0:00.01 
                 43728         0.0 S    31T   0:00.01   0:00.00 
someuser     43729   ??    0.0 S    31T   0:00.39   0:00.76 /usr/bin/some_command with some parameters
                 43729         0.0 S    31T   0:00.00   0:00.00 
                 43729         0.0 S     0T   0:00.01   0:00.01 
                 43729         0.0 S    31T   0:00.07   0:00.05 
                 43729         0.0 S    31T   0:00.00   0:00.00 
                 43729         0.0 S    31T   0:00.00   0:00.00 
                 43729         0.0 S    31T   0:00.00   0:00.00 
                 43729         0.0 S    31T   0:00.00   0:00.00 
                 43729         0.0 S    31T   0:00.00   0:00.00 
                 43729         0.0 S    31T   0:00.00   0:00.00 
                 43729         0.0 S    31T   0:00.00   0:00.00 
                 43729         0.0 S    31T   0:00.00   0:00.00 
                 43729         0.0 S    31T   0:00.02   0:00.00 
                 43729         0.0 S    31T   0:00.01   0:00.01 
                 43729         0.0 S    31T   0:00.01   0:00.00 
root             43731   ??    0.0 S    31T   0:00.07   0:00.04 /usr/bin/some_command with some parameters
                 43731         0.0 S    31T   0:00.01   0:00.00 
someuser     43865   ??    0.0 S     4T   0:00.20   0:00.09 /usr/bin/some_command with some parameters
                 43865         0.0 S     4T   0:00.00   0:00.00 
someuser     43867   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 43867         0.0 S     4T   0:00.00   0:00.00 
root             43868   ??    0.0 S    31T   0:07.98   0:13.93 /usr/bin/some_command with some parameters
                 43868         0.0 S    19T   0:00.00   0:00.00 
                 43868         0.0 S    31T   0:00.00   0:00.00 
someuser     43869   ??    0.0 S     4T   0:00.05   0:00.06 /usr/bin/some_command with some parameters
                 43869         0.0 S     4T   0:00.00   0:00.00 
someuser     43871   ??    0.0 S     4T   0:00.04   0:00.04 /usr/bin/some_command with some parameters
                 43871         0.0 S     4T   0:00.00   0:00.00 
                 43871         0.0 S     4T   0:00.00   0:00.00 
root             43873   ??    0.0 S     4T   0:00.02   0:00.04 /usr/bin/some_command with some parameters
                 43873         0.0 S     4T   0:00.01   0:00.00 
_fpsd            43874   ??    0.0 S     4T   0:00.03   0:00.02 /usr/bin/some_command with some parameters
                 43874         0.0 S     4T   0:00.00   0:00.00 
root             43880   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 43880         0.0 S     4T   0:00.00   0:00.00 
someuser     43881   ??    0.0 S     4T   0:00.01   0:00.00 /usr/bin/some_command with some parameters
                 43881         0.0 S     4T   0:00.00   0:00.00 
someuser     43882   ??    0.0 S    46T   0:00.73   0:00.88 /usr/bin/some_command with some parameters
                 43882         0.0 S    46T   0:00.08   0:00.03 
                 43882         0.0 S    37T   0:00.00   0:00.00 
root             43883   ??    0.0 S    31T   0:00.05   0:00.04 /usr/bin/some_command with some parameters
                 43883         0.0 S    31T   0:00.01   0:00.00 
someuser     43889   ??    0.0 S    31T   0:00.29   0:00.16 /usr/bin/some_command with some parameters
                 43889         0.0 S    37T   0:00.03   0:00.01 
                 43889         0.0 S    37T   0:00.00   0:00.00 
someuser     43890   ??    0.0 S     4T   0:00.02   0:00.01 /usr/bin/some_command with some parameters
                 43890         0.0 S     4T   0:00.01   0:00.00 
root             43892   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 43892         0.0 S     4T   0:00.00   0:00.00 
root             43893   ??    0.0 S    20T   0:00.19   0:00.38 /usr/bin/some_command with some parameters
                 43893         0.0 S    20T   0:00.09   0:00.07 
                 43893         0.0 S    20T   0:00.17   0:00.20 
                 43893         0.0 S    20T   0:00.05   0:00.06 
                 43893         0.0 S    20T   0:00.12   0:00.19 
                 43893         0.0 S    20T   0:00.05   0:00.08 
                 43893         0.0 S    20T   0:00.04   0:00.05 
                 43893         0.0 S    20T   0:00.42   0:00.30 
                 43893         0.0 S    20T   0:00.17   0:00.44 
                 43893         0.0 S    20T   0:03.44   0:14.51 
                 43893         0.0 S    20T   0:00.00   0:00.00 
                 43893         0.0 S    20T   0:00.28   0:00.93 
                 43893         0.0 S    20T   0:00.01   0:00.00 
                 43893         0.0 S    20T   0:01.11   0:02.00 
                 43893         0.0 S    20T   0:00.02   0:00.01 
                 43893         1.8 S    20T   1:03.41   4:28.47 
                 43893         0.0 S    20T   0:03.14   0:02.00 
                 43893         0.0 S    20T   0:38.76   1:20.10 
                 43893         0.0 S    20T   0:00.00   0:00.00 
                 43893         0.0 S    20T   0:00.00   0:00.00 
                 43893         0.0 S    20T   0:00.00   0:00.00 
                 43893         0.0 S    20T   0:00.01   0:00.01 
someuser     43895   ??    0.0 S     4T   0:00.21   0:00.08 /usr/bin/some_command with some parameters
                 43895         0.0 S     4T   0:00.01   0:00.00 
                 43895         0.0 S     4T   0:00.00   0:00.00 
                 43895         0.0 S     4T   0:00.00   0:00.00 
someuser     43896   ??    0.0 S    31T   0:00.01   0:00.02 /usr/bin/some_command with some parameters
                 43896         0.0 S    31T   0:00.02   0:00.01 
someuser     43898   ??    0.0 S     4T   0:00.27   0:00.10 /usr/bin/some_command with some parameters
                 43898         0.0 S     4T   0:00.00   0:00.00 
someuser     43901   ??    0.0 S    46T   0:00.21   0:00.12 /usr/bin/some_command with some parameters
                 43901         0.0 S    46T   0:00.03   0:00.01 
                 43901         0.0 S    37T   0:00.00   0:00.00 
someuser     43904   ??    0.0 S     4T   0:00.20   0:00.10 /usr/bin/some_command with some parameters
                 43904         0.0 S     4T   0:00.01   0:00.00 
someuser     43907   ??    0.0 S     4T   0:00.04   0:00.05 /usr/bin/some_command with some parameters
                 43907         0.0 S     4T   0:00.01   0:00.00 
_installcoordinationd 43908   ??    0.0 S     4T   0:00.02   0:00.03 /usr/bin/some_command with some parameters
                 43908         0.0 S     4T   0:00.00   0:00.00 
root             43910   ??    0.0 S     4T   0:00.01   0:00.00 /usr/bin/some_command with some parameters
                 43910         0.0 S     4T   0:00.04   0:00.07 
root             43916   ??    0.0 S    31T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 43916         0.0 S    20T   0:00.01   0:00.00 
root             43918   ??    0.0 S    31T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 43918         0.0 S     4T   0:00.01   0:00.00 
someuser     43936   ??    0.0 S    31T   0:01.79   0:12.34 /usr/bin/some_command with some parameters
                 43936         0.0 S    37T   0:00.00   0:00.00 
someuser     43941   ??    0.0 S     4T   0:00.01   0:00.01 /usr/bin/some_command with some parameters
                 43941         0.0 S     4T   0:00.00   0:00.00 
root             43942   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 43942         0.0 S     4T   0:00.01   0:00.00 
root             43956   ??    0.0 S     4T   0:00.06   0:00.08 /usr/bin/some_command with some parameters
                 43956         0.0 S     4T   0:00.01   0:00.00 
root             43957   ??    0.0 S    31T   0:00.01   0:00.00 /usr/bin/some_command with some parameters
                 43957         0.0 S    37T   0:00.00   0:00.00 
someuser     43966   ??    0.0 S     4T   0:00.06   0:00.05 /usr/bin/some_command with some parameters
                 43966         0.0 S     4T   0:00.00   0:00.00 
someuser     43971   ??    0.0 S     4T   0:00.03   0:00.01 /usr/bin/some_command with some parameters
                 43971         0.0 S     4T   0:00.00   0:00.00 
someuser     43973   ??    0.0 S     4T   0:00.01   0:00.03 /usr/bin/some_command with some parameters
                 43973         0.0 S     4T   0:00.00   0:00.00 
someuser     43974   ??    0.0 S     4T   0:00.02   0:00.01 /usr/bin/some_command with some parameters
                 43974         0.0 S     4T   0:00.00   0:00.00 
someuser     43975   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 43975         0.0 S     4T   0:00.00   0:00.00 
someuser     43976   ??    0.0 S     4T   0:00.02   0:00.03 /usr/bin/some_command with some parameters
                 43976         0.0 S     4T   0:00.00   0:00.00 
                 43976         0.0 S     4T   0:00.00   0:00.00 
_assetcache      43977   ??    0.0 S     4T   0:00.03   0:00.03 /usr/bin/some_command with some parameters
                 43977         0.0 S     4T   0:00.00   0:00.00 
root             43978   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 43978         0.0 S     4T   0:00.00   0:00.00 
root             43983   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 43983         0.0 S    20T   0:00.00   0:00.00 
root             43984   ??    0.0 S     4T   0:00.01   0:00.00 /usr/bin/some_command with some parameters
                 43984         0.0 S     4T   0:00.00   0:00.00 
someuser     44067   ??    0.0 S     4T   0:00.02   0:00.03 /usr/bin/some_command with some parameters
                 44067         0.0 S     4T   0:00.00   0:00.00 
                 44067         0.0 S     4T   0:00.00   0:00.00 
someuser     44068   ??    0.0 S     4T   0:00.17   0:00.07 /usr/bin/some_command with some parameters
                 44068         0.0 S     4T   0:00.01   0:00.01 
                 44068         0.0 S     4T   0:00.08   0:00.03 
                 44068         0.0 S     4T   0:00.03   0:00.01 
someuser     44070   ??    0.0 S     4T   0:00.02   0:00.01 /usr/bin/some_command with some parameters
                 44070         0.0 S     4T   0:00.00   0:00.00 
someuser     44072   ??    0.0 S     4T   0:00.43   0:00.17 /usr/bin/some_command with some parameters
                 44072         0.0 S     4T   0:00.01   0:00.01 
                 44072         0.0 S     4T   0:00.00   0:00.00 
                 44072         0.0 S     4T   0:00.00   0:00.00 
                 44072         0.0 S     4T   0:00.00   0:00.00 
                 44072         0.0 S     4T   0:00.00   0:00.00 
someuser     44073   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 44073         0.0 S     4T   0:00.01   0:00.01 
someuser     44074   ??    0.0 S     4T   0:00.02   0:00.01 /usr/bin/some_command with some parameters
                 44074         0.0 S     4T   0:00.00   0:00.00 
someuser     44075   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 44075         0.0 S     4T   0:00.00   0:00.00 
someuser     44076   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 44076         0.0 S     4T   0:00.00   0:00.00 
someuser     44083   ??    0.0 S     4T   0:00.03   0:00.04 /usr/bin/some_command with some parameters
                 44083         0.0 S     4T   0:00.01   0:00.00 
someuser     44084   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 44084         0.0 S     4T   0:00.00   0:00.00 
someuser     44085   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 44085         0.0 S     4T   0:00.00   0:00.00 
root             44086   ??    0.0 S     4T   0:00.01   0:00.03 /usr/bin/some_command with some parameters
                 44086         0.0 S     4T   0:00.02   0:00.01 
someuser     44090   ??    0.0 S    31T   0:00.16   0:00.09 /usr/bin/some_command with some parameters
                 44090         0.0 S    37T   0:00.03   0:00.01 
                 44090         0.0 S    37T   0:00.00   0:00.00 
someuser     44098   ??    0.0 S     4T   0:00.01   0:00.03 /usr/bin/some_command with some parameters
                 44098         0.0 S     4T   0:00.00   0:00.00 
root             44099   ??    0.0 S     4T   0:00.02   0:00.04 /usr/bin/some_command with some parameters
                 44099         0.0 S     4T   0:00.00   0:00.00 
                 44099         0.0 S     4T   0:00.00   0:00.00 
someuser     44100   ??    0.0 S     4T   0:00.23   0:00.13 /usr/bin/some_command with some parameters
                 44100         0.0 S     4T   0:00.04   0:00.01 
                 44100         0.0 S     4T   0:00.00   0:00.00 
                 44100         0.0 S     4T   0:00.00   0:00.00 
root             44101   ??    0.0 S     4T   0:00.01   0:00.03 /usr/bin/some_command with some parameters
                 44101         0.0 S     4T   0:00.00   0:00.00 
someuser     44103   ??    0.0 S    46T   0:00.20   0:00.13 /usr/bin/some_command with some parameters
                 44103         0.0 S    46T   0:00.03   0:00.00 
                 44103         0.0 S    37T   0:00.00   0:00.00 
root             44153   ??    0.0 S    31T   0:00.02   0:00.01 /usr/bin/some_command with some parameters
                 44153         0.0 S    31T   0:00.00   0:00.00 
                 44153         0.0 S     4T   0:00.00   0:00.00 
root             44167   ??    0.0 S    31T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 44167         0.0 S    31T   0:00.00   0:00.00 
someuser     44185   ??    0.0 S     4T   0:00.30   0:00.67 /usr/bin/some_command with some parameters
                 44185         0.0 S     4T   0:00.01   0:00.00 
                 44185         0.0 S     4T   0:00.01   0:00.00 
                 44185         0.0 S     4T   0:00.00   0:00.00 
root             44520   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 44520         0.0 S     4T   0:00.01   0:00.04 
someuser     44805   ??    0.0 S     4T   0:00.24   0:00.39 /usr/bin/some_command with some parameters
                 44805         0.0 S     4T   0:00.05   0:00.05 
                 44805         0.0 S     4T   0:00.00   0:00.00 
                 44805         0.0 S     4T   0:00.02   0:00.13 
                 44805         0.0 S     4T   0:00.01   0:00.00 
                 44805         0.0 S     4T   0:00.00   0:00.01 
                 44805         0.0 S     4T   0:00.00   0:00.00 
                 44805         0.0 S     4T   0:00.00   0:00.00 
root             44913   ??    0.0 S    31T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 44913         0.0 S    20T   0:00.01   0:00.00 
root             45056   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 45056         0.0 S     4T   0:00.00   0:00.00 
root             45060   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 45060         0.0 S     4T   0:00.00   0:00.00 
root             45062   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 45062         0.0 S     4T   0:00.00   0:00.00 
root             45063   ??    0.0 S    31T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 45063         0.0 S    31T   0:00.00   0:00.00 
someuser     45064   ??    0.0 S     4T   0:00.02   0:00.03 /usr/bin/some_command with some parameters
                 45064         0.0 S     4T   0:00.00   0:00.00 
someuser     45065   ??    0.0 S    31T   0:00.03   0:00.01 /usr/bin/some_command with some parameters
                 45065         0.0 S    31T   0:00.00   0:00.00 
root             45066   ??    0.0 S     4T   0:00.01   0:00.00 /usr/bin/some_command with some parameters
                 45066         0.0 S     4T   0:00.00   0:00.00 
root             45067   ??    0.0 S     4T   0:00.01   0:00.00 /usr/bin/some_command with some parameters
                 45067         0.0 S     4T   0:00.00   0:00.00 
root             45068   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 45068         0.0 S     4T   0:00.00   0:00.00 
someuser     45069   ??    0.0 S    31T   0:00.01   0:00.01 /usr/bin/some_command with some parameters
                 45069         0.0 S    31T   0:00.00   0:00.00 
someuser     45070   ??    0.0 S    31T   0:00.16   0:00.07 /usr/bin/some_command with some parameters
                 45070         0.0 S    37T   0:00.00   0:00.00 
                 45070         0.0 S    31T   0:00.00   0:00.00 
someuser     45071   ??    0.0 S    31T   0:00.01   0:00.01 /usr/bin/some_command with some parameters
                 45071         0.0 S    31T   0:00.00   0:00.00 
root             45073   ??    0.0 S     4T   0:00.01   0:00.01 /usr/bin/some_command with some parameters
                 45073         0.0 S     4T   0:00.00   0:00.00 
_appstore        45096   ??    0.0 S     4T   0:00.18   0:00.07 /usr/bin/some_command with some parameters
                 45096         0.0 S     4T   0:00.00   0:00.00 
someuser     45097   ??    0.0 S     4T   0:00.03   0:00.05 /usr/bin/some_command with some parameters
                 45097         0.0 S     4T   0:00.01   0:00.00 
root             45098   ??    0.0 S     4T   0:00.01   0:00.05 /usr/bin/some_command with some parameters
                 45098         0.0 S     4T   0:00.00   0:00.00 
someuser     45101   ??    0.0 S     4T   0:00.02   0:00.04 /usr/bin/some_command with some parameters
                 45101         0.0 S     4T   0:00.00   0:00.00 
root             45104   ??    0.0 S    20T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 45104         0.0 S     4T   0:00.00   0:00.00 
root             45105   ??    0.0 S    20T   0:00.01   0:00.00 /usr/bin/some_command with some parameters
                 45105         0.0 S     4T   0:00.01   0:00.00 
root             45106   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 45106         0.0 S     4T   0:00.00   0:00.00 
_applepay        45111   ??    0.0 S    50T   0:00.03   0:00.03 /usr/bin/some_command with some parameters
                 45111         0.0 S    31T   0:00.00   0:00.00 
someuser     45174   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 45174         0.0 S     4T   0:00.02   0:00.02 
someuser     45206   ??    0.0 S    31T   0:04.32   0:10.39 /usr/bin/some_command with some parameters
                 45206         0.0 S    31T   0:00.00   0:00.00 
                 45206         0.0 S     0T   0:00.12   0:00.09 
                 45206         0.0 S    31T   0:02.48   0:02.72 
                 45206         0.0 S    31T   0:00.00   0:00.00 
                 45206         0.0 S    31T   0:00.01   0:00.00 
                 45206         0.0 S    31T   0:00.00   0:00.00 
                 45206         0.0 S    31T   0:00.00   0:00.00 
                 45206         0.0 S    31T   0:00.00   0:00.00 
                 45206         0.0 S    31T   0:00.00   0:00.00 
                 45206         0.0 S    31T   0:00.00   0:00.00 
                 45206         0.0 S    31T   0:00.00   0:00.00 
                 45206         0.0 S    31T   0:00.14   0:00.03 
                 45206         0.0 S    31T   0:00.00   0:00.00 
                 45206         0.0 S    31T   0:00.02   0:00.00 
someuser     45624   ??    0.0 S     4T   0:00.03   0:00.01 /usr/bin/some_command with some parameters
                 45624         0.0 S     4T   0:00.00   0:00.00 
someuser     45782   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 45782         0.0 S     4T   0:00.00   0:00.00 
someuser     45792   ??    0.0 S    31T   0:00.69   0:01.23 /usr/bin/some_command with some parameters
                 45792         0.0 S    31T   0:00.05   0:00.02 
                 45792         0.0 S    31T   0:00.00   0:00.00 
                 45792         0.0 S     0T   0:00.00   0:00.00 
                 45792         0.0 S    31T   0:00.16   0:00.09 
                 45792         0.0 S    31T   0:00.00   0:00.00 
                 45792         0.0 S    31T   0:00.01   0:00.03 
                 45792         0.0 S    31T   0:00.02   0:00.01 
                 45792         0.0 S    31T   0:00.00   0:00.00 
                 45792         0.0 S    31T   0:00.00   0:00.00 
                 45792         0.0 S    31T   0:00.00   0:00.01 
                 45792         0.0 S    31T   0:00.00   0:00.00 
                 45792         0.0 S    31T   0:00.00   0:00.00 
                 45792         0.0 S    31T   0:00.01   0:00.00 
                 45792         0.0 S    31T   0:00.01   0:00.01 
someuser     45933   ??    0.0 S    20T   0:00.04   0:00.02 /usr/bin/some_command with some parameters
                 45933         0.0 S    20T   0:00.00   0:00.00 
_iconservices    45982   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 45982         0.0 S     4T   0:00.00   0:00.00 
someuser     46122   ??    0.0 S    42T   0:03.35   0:04.46 /usr/bin/some_command with some parameters
                 46122         0.0 S    31T   0:21.72   0:06.13 
                 46122         0.0 S    31T   0:00.09   0:00.09 
                 46122         0.0 S    31T   0:00.24   0:00.26 
                 46122         0.0 S    31T   0:00.01   0:00.00 
                 46122         1.0 S    31T  24:06.44   0:28.11 
                 46122         1.5 S    31T  29:27.74   2:20.05 
                 46122         0.0 S    31T   0:00.00   0:00.00 
                 46122         0.0 S    31T   0:12.63   0:07.90 
                 46122         0.0 S    31T   0:00.00   0:00.00 
                 46122         0.0 S    31T   0:07.66   0:02.06 
                 46122         0.0 S    31T   0:27.64   0:10.88 
                 46122         0.0 S    31T   0:02.82   0:00.63 
                 46122         0.0 S    31T   0:00.00   0:00.00 
                 46122         0.0 S    31T   0:00.14   0:00.07 
                 46122         0.0 S    31T   0:00.21   0:00.26 
                 46122         0.0 S    31T   0:21.79   0:11.83 
                 46122         0.0 S    31T   0:06.17   0:05.60 
                 46122         0.0 S    31T   0:00.00   0:00.00 
                 46122         0.0 S    31T   0:00.00   0:00.00 
                 46122         0.0 S    31T   0:03.87   0:00.84 
                 46122         0.0 S    31T   0:04.06   0:03.00 
                 46122         0.0 S    31T   0:00.01   0:00.00 
                 46122         0.0 S    31T   0:00.00   0:00.00 
                 46122         0.0 S    31T   0:26.09   0:06.42 
                 46122         0.0 S    31T   0:00.98   0:00.22 
                 46122         0.0 S    31T   0:00.00   0:00.00 
                 46122         0.0 S    19T   0:00.00   0:00.00 
                 46122         0.0 S    31T   0:00.14   0:00.07 
                 46122         0.0 S    31T   0:12.82   0:10.30 
                 46122         0.0 S    31T   0:00.00   0:00.00 
someuser     46396   ??    0.0 S     4T   0:00.05   0:00.04 /usr/bin/some_command with some parameters
                 46396         0.0 S     4T   0:00.00   0:00.00 
someuser     46645   ??    0.0 S    31T   0:00.23   0:00.60 /usr/bin/some_command with some parameters
                 46645         0.0 S    31T   0:00.02   0:00.01 
                 46645         0.0 S    31T   0:00.00   0:00.00 
                 46645         0.0 S     0T   0:00.00   0:00.00 
                 46645         0.0 S    31T   0:00.06   0:00.03 
                 46645         0.0 S    31T   0:00.00   0:00.00 
                 46645         0.0 S    31T   0:00.02   0:00.04 
                 46645         0.0 S    31T   0:00.00   0:00.00 
                 46645         0.0 S    31T   0:00.00   0:00.01 
                 46645         0.0 S    31T   0:00.00   0:00.01 
                 46645         0.0 S    31T   0:00.00   0:00.02 
                 46645         0.0 S    31T   0:00.00   0:00.02 
                 46645         0.0 S    31T   0:00.00   0:00.00 
                 46645         0.0 S    31T   0:00.00   0:00.00 
                 46645         0.0 S    31T   0:00.00   0:00.01 
someuser     46738   ??    0.0 S    31T   0:00.59   0:01.17 /usr/bin/some_command with some parameters
                 46738         0.0 S    31T   0:00.05   0:00.02 
                 46738         0.0 S    31T   0:00.00   0:00.00 
                 46738         0.0 S     0T   0:00.00   0:00.00 
                 46738         0.0 S    31T   0:00.14   0:00.08 
                 46738         0.0 S    31T   0:00.00   0:00.00 
                 46738         0.0 S    31T   0:00.02   0:00.06 
                 46738         0.0 S    31T   0:00.03   0:00.01 
                 46738         0.0 S    31T   0:00.00   0:00.00 
                 46738         0.0 S    31T   0:00.00   0:00.01 
                 46738         0.0 S    31T   0:00.00   0:00.00 
                 46738         0.0 S    31T   0:00.00   0:00.00 
                 46738         0.0 S    31T   0:00.00   0:00.00 
                 46738         0.0 S    31T   0:00.00   0:00.00 
                 46738         0.0 S    31T   0:00.03   0:00.02 
someuser     47353   ??    0.0 S    31T   0:00.88   0:04.50 /usr/bin/some_command with some parameters
                 47353         0.0 S    31T   0:00.07   0:00.03 
                 47353         0.0 S    31T   0:00.00   0:00.00 
                 47353         0.0 S     0T   0:00.00   0:00.00 
                 47353         0.0 S    31T   0:00.25   0:00.23 
                 47353         0.0 S    31T   0:00.00   0:00.00 
                 47353         0.0 S    31T   0:00.23   0:01.09 
                 47353         0.0 S    31T   0:00.00   0:00.00 
                 47353         0.0 S    31T   0:00.01   0:00.03 
                 47353         0.0 S    31T   0:00.02   0:00.03 
                 47353         0.0 S    31T   0:00.01   0:00.03 
                 47353         0.0 S    31T   0:00.01   0:00.03 
                 47353         0.0 S    31T   0:00.00   0:00.00 
                 47353         0.0 S    31T   0:00.00   0:00.00 
                 47353         0.0 S    31T   0:00.02   0:00.02 
someuser     47355   ??    0.0 S    31T   0:00.46   0:02.51 /usr/bin/some_command with some parameters
                 47355         0.0 S    31T   0:00.04   0:00.02 
                 47355         0.0 S    31T   0:00.00   0:00.00 
                 47355         0.0 S     0T   0:00.00   0:00.00 
                 47355         0.0 S    31T   0:00.09   0:00.05 
                 47355         0.0 S    31T   0:00.00   0:00.00 
                 47355         0.0 S    31T   0:00.04   0:00.18 
                 47355         0.0 S    31T   0:00.00   0:00.00 
                 47355         0.0 S    31T   0:00.01   0:00.04 
                 47355         0.0 S    31T   0:00.00   0:00.01 
                 47355         0.0 S    31T   0:00.00   0:00.03 
                 47355         0.0 S    31T   0:00.00   0:00.02 
                 47355         0.0 S    31T   0:00.00   0:00.00 
                 47355         0.0 S    31T   0:00.01   0:00.00 
                 47355         0.0 S    31T   0:00.02   0:00.02 
root             49788   ??    0.0 S     4T   0:00.03   0:00.01 /usr/bin/some_command with some parameters
                 49788         0.0 S     4T   0:00.03   0:00.01 
_softwareupdate  51166   ??    0.0 S     4T   0:08.83   0:00.85 /usr/bin/some_command with some parameters
                 51166         0.0 S     4T   0:00.58   0:00.03 
                 51166         0.0 S     4T   0:00.00   0:00.00 
                 51166         0.0 S     4T   0:00.04   0:00.02 
                 51166         0.0 S     4T   0:00.01   0:00.00 
root             51168   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 51168         0.0 S     4T   0:00.00   0:00.00 
_atsserver       51169   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 51169         0.0 S     4T   0:00.00   0:00.00 
someuser     51368   ??    0.0 S     4T   0:00.82   0:00.33 /usr/bin/some_command with some parameters
                 51368         0.0 S     4T   0:00.01   0:00.00 
someuser     52356   ??    0.0 S    31T   0:00.36   0:00.97 /usr/bin/some_command with some parameters
                 52356         0.0 S    31T   0:00.03   0:00.01 
                 52356         0.0 S    31T   0:00.00   0:00.00 
                 52356         0.0 S     0T   0:00.00   0:00.00 
                 52356         0.0 S    31T   0:00.05   0:00.04 
                 52356         0.0 S    31T   0:00.00   0:00.00 
                 52356         0.0 S    31T   0:00.01   0:00.03 
                 52356         0.0 S    31T   0:00.01   0:00.00 
                 52356         0.0 S    31T   0:00.00   0:00.00 
                 52356         0.0 S    31T   0:00.00   0:00.00 
                 52356         0.0 S    31T   0:00.00   0:00.01 
                 52356         0.0 S    31T   0:00.00   0:00.00 
                 52356         0.0 S    31T   0:00.00   0:00.00 
                 52356         0.0 S    31T   0:00.01   0:00.00 
                 52356         0.0 S    31T   0:00.01   0:00.01 
someuser     52359   ??    0.0 S    31T   0:00.57   0:03.45 /usr/bin/some_command with some parameters
                 52359         0.0 S    31T   0:00.04   0:00.02 
                 52359         0.0 S    31T   0:00.00   0:00.00 
                 52359         0.0 S     0T   0:00.00   0:00.00 
                 52359         0.0 S    31T   0:00.26   0:00.39 
                 52359         0.0 S    31T   0:00.00   0:00.00 
                 52359         0.0 S    31T   0:00.44   0:01.68 
                 52359         0.0 S    31T   0:00.00   0:00.00 
                 52359         0.0 S    31T   0:00.01   0:00.02 
                 52359         0.0 S    31T   0:00.00   0:00.02 
                 52359         0.0 S    31T   0:00.01   0:00.03 
                 52359         0.0 S    31T   0:00.01   0:00.01 
                 52359         0.0 S    31T   0:00.00   0:00.00 
                 52359         0.0 S    31T   0:00.01   0:00.00 
                 52359         0.0 S    31T   0:00.00   0:00.00 
root             53270   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 53270         0.0 S     4T   0:00.00   0:00.00 
root             53628   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 53628         0.0 S     4T   0:00.00   0:00.00 
root             53631   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 53631         0.0 S     4T   0:00.00   0:00.00 
someuser     53753   ??    0.0 S     4T   0:00.05   0:00.06 /usr/bin/some_command with some parameters
                 53753         0.0 S     4T   0:00.00   0:00.00 
root             53792   ??    0.0 S    31T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 53792         0.0 S    19T   0:00.00   0:00.00 
                 53792         0.0 S    31T   0:00.00   0:00.00 
root             53793   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 53793         0.0 S     4T   0:00.00   0:00.00 
someuser     53835   ??    0.0 S    46T   0:00.04   0:00.06 /usr/bin/some_command with some parameters
                 53835         0.0 S    46T   0:00.00   0:00.00 
                 53835        24.1 S    31T   1:21.34   3:38.44 
                 53835         0.1 S    20T   0:00.12   0:00.08 
                 53835         0.1 S    20T   0:00.06   0:00.04 
                 53835         0.2 S    46T   0:00.03   0:00.02 
someuser     53836   ??    0.4 S    46T   0:04.23   0:05.61 /usr/bin/some_command with some parameters
                 53836         0.0 S    46T   0:00.00   0:00.00 
                 53836         6.1 S    31T   0:16.08   1:47.22 
                 53836         0.5 S    37T   0:00.90   0:00.16 
                 53836         0.4 S    46T   0:00.48   0:00.09 
                 53836         0.0 S    31T   0:00.00   0:00.00 
someuser     53837   ??    0.0 S     4T   0:00.01   0:00.03 /usr/bin/some_command with some parameters
                 53837         0.0 S     4T   0:00.00   0:00.00 
                 53837         0.0 S     4T   0:00.00   0:00.00 
someuser     53838   ??    0.0 S     4T   0:00.12   0:00.01 /usr/bin/some_command with some parameters
                 53838         0.0 S     4T   0:00.00   0:00.00 
someuser     53839   ??    0.0 S     4T   0:00.24   0:00.02 /usr/bin/some_command with some parameters
                 53839         0.0 S     4T   0:00.00   0:00.00 
someuser     53885   ??    0.0 S    31T   0:00.20   0:00.89 /usr/bin/some_command with some parameters
                 53885         0.0 S    31T   0:00.02   0:00.01 
                 53885         0.0 S    31T   0:00.00   0:00.00 
                 53885         0.0 S     0T   0:00.00   0:00.00 
                 53885         0.0 S    31T   0:00.04   0:00.04 
                 53885         0.0 S    31T   0:00.00   0:00.00 
                 53885         0.0 S    31T   0:00.02   0:00.06 
                 53885         0.0 S    31T   0:00.01   0:00.00 
                 53885         0.0 S    31T   0:00.00   0:00.00 
                 53885         0.0 S    31T   0:00.00   0:00.00 
                 53885         0.0 S    31T   0:00.00   0:00.02 
                 53885         0.0 S    31T   0:00.00   0:00.00 
                 53885         0.0 S    31T   0:00.00   0:00.00 
                 53885         0.0 S    31T   0:00.00   0:00.00 
                 53885         0.0 S    31T   0:00.00   0:00.01 
someuser     53929   ??    0.0 S    31T   0:00.20   0:01.08 /usr/bin/some_command with some parameters
                 53929         0.0 S    31T   0:00.01   0:00.00 
                 53929         0.0 S    31T   0:00.00   0:00.00 
                 53929         0.0 S     0T   0:00.00   0:00.00 
                 53929         0.0 S    31T   0:00.05   0:00.07 
                 53929         0.0 S    31T   0:00.00   0:00.00 
                 53929         0.0 S    31T   0:00.06   0:00.22 
                 53929         0.0 S    31T   0:00.00   0:00.00 
                 53929         0.0 S    31T   0:00.00   0:00.02 
                 53929         0.0 S    31T   0:00.00   0:00.03 
                 53929         0.0 S    31T   0:00.00   0:00.01 
                 53929         0.0 S    31T   0:00.00   0:00.02 
                 53929         0.0 S    31T   0:00.00   0:00.00 
                 53929         0.0 S    31T   0:00.00   0:00.00 
                 53929         0.0 S    31T   0:00.01   0:00.00 
someuser     53931   ??    0.0 S    31T   0:00.03   0:00.08 /usr/bin/some_command with some parameters
                 53931         0.0 S    31T   0:00.00   0:00.00 
                 53931         0.0 S    31T   0:00.00   0:00.00 
                 53931         0.0 S    31T   0:00.00   0:00.00 
                 53931         0.0 S     0T   0:00.00   0:00.00 
                 53931         0.0 S    31T   0:00.00   0:00.00 
                 53931         0.0 S    31T   0:00.00   0:00.00 
                 53931         0.0 S    31T   0:00.00   0:00.00 
                 53931         0.0 S    31T   0:00.00   0:00.00 
                 53931         0.0 S    31T   0:00.00   0:00.00 
                 53931         0.0 S    31T   0:00.00   0:00.00 
                 53931         0.0 S    31T   0:00.00   0:00.00 
                 53931         0.0 S    31T   0:00.00   0:00.00 
                 53931         0.0 S    31T   0:00.00   0:00.00 
someuser     54166   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 54166         0.0 S     4T   0:00.00   0:00.00 
                 54166         0.0 S     4T   0:00.00   0:00.00 
                 54166         0.0 S     4T   0:00.00   0:00.00 
someuser     55004   ??    0.0 S     4T   0:00.78   0:02.70 /usr/bin/some_command with some parameters
                 55004         0.0 S     4T   0:00.05   0:00.03 
                 55004         0.0 S     4T   0:00.00   0:00.00 
                 55004         0.0 S     4T   0:00.00   0:00.00 
someuser     55005   ??    0.0 S     4T   0:00.03   0:00.03 /usr/bin/some_command with some parameters
                 55005         0.0 S     4T   0:00.00   0:00.00 
                 55005         0.0 S     4T   0:00.00   0:00.00 
someuser     55006   ??    0.0 S     4T   0:00.03   0:00.04 /usr/bin/some_command with some parameters
                 55006         0.0 S     4T   0:00.01   0:00.00 
someuser     55007   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 55007         0.0 S     4T   0:00.00   0:00.00 
someuser     55008   ??    0.0 S     4T   0:00.01   0:00.00 /usr/bin/some_command with some parameters
                 55008         0.0 S     4T   0:00.00   0:00.00 
someuser     55010   ??    0.0 S     4T   0:00.03   0:00.04 /usr/bin/some_command with some parameters
                 55010         0.0 S     4T   0:00.00   0:00.00 
someuser     55011   ??    0.0 S     4T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 55011         0.0 S     4T   0:00.00   0:00.00 
_spotlight       55287   ??    0.0 S     4T   0:00.01   0:00.01 /usr/bin/some_command with some parameters
                 55287         0.0 S     4T   0:00.00   0:00.04 
                 55287         0.0 S     4T   0:00.00   0:00.00 
someuser     55291   ??    0.0 S     4T   0:00.01   0:00.01 /usr/bin/some_command with some parameters
                 55291         0.0 S     4T   0:00.00   0:00.04 
                 55291         0.0 S     4T   0:00.10   0:00.09 
                 55291         0.0 S     4T   0:00.00   0:00.00 
someuser     55294   ??    0.0 S     4T   0:00.01   0:00.00 /usr/bin/some_command with some parameters
                 55294         0.0 S     4T   0:00.00   0:00.04 
                 55294         0.0 S     4T   0:00.05   0:00.07 
                 55294         0.0 S     4T   0:00.00   0:00.00 
someuser     55348   ??    0.0 S     4T   0:00.01   0:00.01 /usr/bin/some_command with some parameters
                 55348         0.0 S     4T   0:00.00   0:00.04 
                 55348         0.0 S     4T   0:00.00   0:00.00 
                 55348         0.0 S     4T   0:00.00   0:00.00 
someuser     55349   ??    0.0 S     4T   0:00.01   0:00.00 /usr/bin/some_command with some parameters
                 55349         0.0 S     4T   0:00.00   0:00.04 
                 55349         0.0 S     4T   0:00.00   0:00.00 
                 55349         0.0 S     4T   0:00.00   0:00.00 
root             55706   ??    0.0 S    31T   0:00.05   0:00.01 /usr/bin/some_command with some parameters
                 55706         0.0 S    20T   0:00.00   0:00.00 
someuser     56786   ??    0.0 S    31T   0:21.59   1:26.39 /usr/bin/some_command with some parameters
                 56786         0.0 S    31T   0:00.00   0:00.00 
                 56786         0.0 S     0T   0:00.04   0:00.02 
                 56786         0.0 S    31T   0:01.50   0:01.81 
                 56786         0.0 S    31T   0:00.01   0:00.01 
                 56786         0.0 S    31T   0:00.10   0:00.47 
                 56786         0.0 S    31T   0:00.02   0:00.01 
                 56786         0.0 S    31T   0:00.00   0:00.02 
                 56786         0.0 S    31T   0:00.01   0:00.03 
                 56786         0.0 S    31T   0:00.00   0:00.01 
                 56786         0.0 S    31T   0:00.00   0:00.01 
                 56786         0.0 S    31T   0:00.00   0:00.00 
                 56786         0.0 S    31T   0:00.09   0:00.03 
                 56786         0.0 S    31T   0:00.02   0:00.04 
                 56786         0.0 S    31T   0:00.19   0:00.07 
                 56786         0.0 S    31T   0:00.01   0:00.08 
                 56786         0.0 S    31T   0:00.00   0:00.00 
                 56786         0.0 S    31T   0:00.00   0:00.00 
                 56786         0.0 S    31T   0:00.00   0:00.00 
                 56786         0.0 S    31T   0:00.00   0:00.00 
someuser     67087   ??    0.0 S    20T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 67087         0.0 S    20T   0:00.00   0:00.00 
root             70071   ??    0.0 S    37T   0:00.20   0:00.09 /usr/bin/some_command with some parameters
                 70071         0.0 S    31T   0:00.02   0:00.01 
                 70071         0.0 S    20T   0:00.00   0:00.00 
_usbmuxd         70682   ??    0.0 S    31T   0:00.09   0:00.04 /usr/bin/some_command with some parameters
                 70682         0.0 S    31T   0:00.06   0:00.01 
                 70682         0.0 S    31T   0:00.00   0:00.00 
someuser     70696   ??    0.0 S     4T   0:00.79   0:00.35 /usr/bin/some_command with some parameters
                 70696         0.0 S     4T   0:00.00   0:00.00 
                 70696         0.0 S     4T   0:00.00   0:00.00 
                 70696         0.0 S     4T   0:00.12   0:00.02 
                 70696         0.0 S     4T   0:00.00   0:00.00 
                 70696         0.0 S     4T   0:00.00   0:00.00 
someuser     70752   ??    0.0 S     4T   0:00.07   0:00.03 /usr/bin/some_command with some parameters
                 70752         0.0 S     4T   0:00.00   0:00.00 
                 70752         0.0 S     4T   0:00.00   0:00.00 
                 70752         0.0 S     4T   0:00.01   0:00.00 
_driverkit       70896   ??    0.0 S    63R   0:00.01   0:00.00 /usr/bin/some_command with some parameters
                 70896         0.0 S    31T   0:00.00   0:00.00 
_driverkit       70898   ??    0.0 S    31T   0:00.00   0:00.00 /usr/bin/some_command with some parameters
                 70898         0.0 S    37T   0:00.14   0:00.05 
                 70898         0.0 S    63R   0:00.03   0:00.01 
_driverkit       70899   ??    0.0 S    63R   0:38.05   0:25.27 /usr/bin/some_command with some parameters
                 70899         0.0 S    31T   0:00.00   0:00.00 
root             71311   ??    0.0 S    31T   0:00.37   0:00.25 /usr/bin/some_command with some parameters
                 71311         0.0 S    19T   0:00.00   0:00.00 
                 71311         0.0 S     4T   0:00.00   0:00.00 
                 71311         0.0 S     4T   0:00.00   0:00.00 
someuser     75951   ??    0.0 S    31T   0:03.06   0:05.41 /usr/bin/some_command with some parameters
                 75951         0.0 S    31T   0:00.00   0:00.00 
                 75951         0.0 S     0T   0:00.09   0:00.06 
                 75951         0.0 S    31T   0:01.48   0:01.12 
                 75951         0.0 S    31T   0:00.00   0:00.00 
                 75951         0.0 S    31T   0:00.03   0:00.10 
                 75951         0.0 S    31T   0:00.00   0:00.00 
                 75951         0.0 S    31T   0:00.00   0:00.00 
                 75951         0.0 S    31T   0:00.00   0:00.01 
                 75951         0.0 S    31T   0:00.00   0:00.00 
                 75951         0.0 S    31T   0:00.00   0:00.00 
                 75951         0.0 S    31T   0:00.00   0:00.00 
                 75951         0.0 S    31T   0:00.12   0:00.03 
                 75951         0.0 S    31T   0:00.08   0:00.02 
                 75951         0.0 S    31T   0:00.00   0:00.00 
someuser     76232   ??    0.0 S    31T   0:15.22   0:22.98 /usr/bin/some_command with some parameters
                 76232         0.0 S    31T   0:00.00   0:00.00 
                 76232         0.0 S     0T   0:00.08   0:00.06 
                 76232         0.0 S    31T   0:02.42   0:02.74 
                 76232         0.0 S    31T   0:00.01   0:00.02 
                 76232         0.0 S    31T   0:00.10   0:00.34 
                 76232         0.0 S    31T   0:00.00   0:00.00 
                 76232         0.0 S    31T   0:00.01   0:00.02 
                 76232         0.0 S    31T   0:00.01   0:00.01 
                 76232         0.0 S    31T   0:00.00   0:00.02 
                 76232         0.0 S    31T   0:00.01   0:00.01 
                 76232         0.0 S    31T   0:00.00   0:00.00 
                 76232         0.0 S    31T   0:00.01   0:00.04 
                 76232         0.0 S    31T   0:00.17   0:00.04 
                 76232         0.0 S    31T   0:00.00   0:00.00 
                 76232         0.0 S    31T   0:00.09   0:00.03 
someuser     79317   ??    0.0 S    31T   0:05.42   0:07.07 /usr/bin/some_command with some parameters
                 79317         0.0 S    31T   0:00.00   0:00.00 
                 79317         0.0 S     0T   0:00.08   0:00.05 
                 79317         0.0 S    31T   0:01.01   0:00.60 
                 79317         0.0 S    31T   0:00.00   0:00.00 
                 79317         0.0 S    31T   0:00.06   0:00.25 
                 79317         0.0 S    31T   0:00.00   0:00.00 
                 79317         0.0 S    31T   0:00.00   0:00.03 
                 79317         0.0 S    31T   0:00.00   0:00.01 
                 79317         0.0 S    31T   0:00.00   0:00.01 
                 79317         0.0 S    31T   0:00.00   0:00.02 
                 79317         0.0 S    31T   0:00.00   0:00.00 
                 79317         0.0 S    31T   0:00.34   0:00.04 
                 79317         0.0 S    31T   0:00.01   0:00.00 
                 79317         0.0 S    31T   0:00.20   0:00.04 
                 79317         0.0 S    31T   0:00.02   0:00.01 
someuser     79623   ??    0.0 S    31T   0:10.60   0:19.96 /usr/bin/some_command with some parameters
                 79623         0.0 S    31T   0:00.00   0:00.00 
                 79623         0.0 S     0T   0:00.02   0:00.02 
                 79623         0.0 S    31T   0:01.10   0:01.15 
                 79623         0.0 S    31T   0:00.00   0:00.00 
                 79623         0.0 S    31T   0:00.00   0:00.00 
                 79623         0.0 S    31T   0:00.00   0:00.00 
                 79623         0.0 S    31T   0:00.00   0:00.00 
                 79623         0.0 S    31T   0:00.00   0:00.00 
                 79623         0.0 S    31T   0:00.00   0:00.00 
                 79623         0.0 S    31T   0:00.00   0:00.00 
                 79623         0.0 S    31T   0:00.00   0:00.00 
                 79623         0.0 S    31T   0:00.02   0:00.01 
                 79623         0.0 S    31T   0:00.04   0:00.01 
                 79623         0.0 S    31T   0:00.17   0:00.06 
                 79623         0.0 S    31T   0:00.02   0:00.01 
                 79623         0.0 S    31T   0:00.00   0:00.00 
someuser     79636   ??    0.0 S    31T   0:10.19   0:18.21 /usr/bin/some_command with some parameters
                 79636         0.0 S    31T   0:00.00   0:00.00 
                 79636         0.0 S     0T   0:00.02   0:00.02 
                 79636         0.0 S    31T   0:01.04   0:01.12 
                 79636         0.0 S    31T   0:00.00   0:00.00 
                 79636         0.0 S    31T   0:00.00   0:00.00 
                 79636         0.0 S    31T   0:00.00   0:00.00 
                 79636         0.0 S    31T   0:00.00   0:00.00 
                 79636         0.0 S    31T   0:00.00   0:00.00 
                 79636         0.0 S    31T   0:00.00   0:00.00 
                 79636         0.0 S    31T   0:00.00   0:00.00 
                 79636         0.0 S    31T   0:00.00   0:00.00 
                 79636         0.0 S    31T   0:00.01   0:00.01 
                 79636         0.0 S    31T   0:00.03   0:00.01 
                 79636         0.0 S    31T   0:00.15   0:00.06 
                 79636         0.0 S    31T   0:00.01   0:00.00 
                 79636         0.0 S    31T   0:00.00   0:00.00 
someuser     79637   ??    0.0 S    31T   0:00.26   0:00.20 /usr/bin/some_command with some parameters
                 79637         0.0 S    31T   0:00.00   0:00.00 
                 79637         0.0 S    31T   0:00.03   0:00.02 
                 79637         0.0 S     0T   0:00.02   0:00.02 
                 79637         0.0 S    31T   0:00.17   0:00.05 
                 79637         0.0 S    31T   0:00.00   0:00.00 
                 79637         0.0 S    31T   0:00.00   0:00.00 
                 79637         0.0 S    31T   0:00.00   0:00.00 
                 79637         0.0 S    31T   0:00.00   0:00.00 
                 79637         0.0 S    31T   0:00.00   0:00.00 
                 79637         0.0 S    31T   0:00.00   0:00.00 
                 79637         0.0 S    31T   0:00.00   0:00.00 
                 79637         0.0 S    31T   0:00.00   0:00.00 
                 79637         0.0 S    31T   0:00.04   0:00.01 
                 79637         0.0 S    31T   0:00.00   0:00.00 
someuser     79692   ??    0.0 S    31T   0:11.25   0:18.01 /usr/bin/some_command with some parameters
                 79692         0.0 S    31T   0:00.00   0:00.00 
                 79692         0.0 S     0T   0:00.02   0:00.02 
                 79692         0.0 S    31T   0:01.06   0:01.05 
                 79692         0.0 S    31T   0:00.01   0:00.02 
                 79692         0.0 S    31T   0:00.04   0:00.17 
                 79692         0.0 S    31T   0:00.00   0:00.00 
                 79692         0.0 S    31T   0:00.00   0:00.00 
                 79692         0.0 S    31T   0:00.00   0:00.00 
                 79692         0.0 S    31T   0:00.00   0:00.01 
                 79692         0.0 S    31T   0:00.00   0:00.01 
                 79692         0.0 S    31T   0:00.00   0:00.00 
                 79692         0.0 S    31T   0:00.10   0:00.01 
                 79692         0.0 S    31T   0:00.14   0:00.05 
                 79692         0.0 S    31T   0:00.10   0:00.05 
someuser     79727   ??    0.0 S     4T   0:47.45   1:38.46 /usr/bin/some_command with some parameters
                 79727         0.0 S     4T   0:00.85   0:00.52 
                 79727         0.0 S     4T   0:00.28   0:00.22 
                 79727         0.0 S     4T   0:00.08   0:00.07 
                 79727         0.0 S     4T   0:00.00   0:00.00 
someuser     79738   ??    0.0 S    31T   0:12.99   0:22.71 /usr/bin/some_command with some parameters
                 79738         0.0 S    31T   0:00.00   0:00.00 
                 79738         0.0 S     0T   0:00.02   0:00.02 
                 79738         0.0 S    31T   0:01.21   0:01.39 
                 79738         0.0 S    31T   0:00.01   0:00.01 
                 79738         0.0 S    31T   0:00.37   0:00.69 
                 79738         0.0 S    31T   0:00.00   0:00.00 
                 79738         0.0 S    31T   0:00.07   0:00.06 
                 79738         0.0 S    31T   0:00.07   0:00.06 
                 79738         0.0 S    31T   0:00.07   0:00.07 
                 79738         0.0 S    31T   0:00.07   0:00.07 
                 79738         0.0 S    31T   0:00.00   0:00.00 
                 79738         0.0 S    31T   0:00.05   0:00.01 
                 79738         0.0 S    31T   0:00.17   0:00.06 
                 79738         0.0 S    31T   0:00.04   0:00.06 
someuser     80172   ??    0.0 S    31T   0:03.00   0:06.88 /usr/bin/some_command with some parameters
                 80172         0.0 S    31T   0:00.00   0:00.00 
                 80172         0.0 S     0T   0:00.02   0:00.02 
                 80172         0.0 S    31T   0:00.30   0:00.20 
                 80172         0.0 S    31T   0:00.00   0:00.00 
                 80172         0.0 S    31T   0:00.06   0:00.15 
                 80172         0.0 S    31T   0:00.00   0:00.00 
                 80172         0.0 S    31T   0:00.00   0:00.00 
                 80172         0.0 S    31T   0:00.01   0:00.01 
                 80172         0.0 S    31T   0:00.01   0:00.01 
                 80172         0.0 S    31T   0:00.00   0:00.01 
                 80172         0.0 S    31T   0:00.00   0:00.00 
                 80172         0.0 S    31T   0:00.11   0:00.02 
                 80172         0.0 S    31T   0:00.09   0:00.03 
                 80172         0.0 S    31T   0:00.00   0:00.00 
someuser     87339   ??    0.0 S    31T   0:16.87   1:17.95 /usr/bin/some_command with some parameters
                 87339         0.0 S    31T   0:00.00   0:00.00 
                 87339         0.0 S     0T   0:00.02   0:00.02 
                 87339         0.0 S    31T   0:03.27   0:03.72 
                 87339         0.0 S    31T   0:00.00   0:00.00 
                 87339         0.0 S    31T   0:01.53   0:09.72 
                 87339         0.0 S    31T   0:00.00   0:00.00 
                 87339         0.0 S    31T   0:00.07   0:00.24 
                 87339         0.0 S    31T   0:00.09   0:00.27 
                 87339         0.0 S    31T   0:00.08   0:00.26 
                 87339         0.0 S    31T   0:00.08   0:00.26 
                 87339         0.0 S    31T   0:00.00   0:00.00 
                 87339         0.0 S    31T   0:00.09   0:00.03 
                 87339         0.0 S    31T   0:00.02   0:00.01 
                 87339         0.0 S    31T   0:00.17   0:00.06 
                 87339         0.0 S    31T   0:00.02   0:00.01 
                 87339         0.0 S    31T   0:00.00   0:00.00 
someuser     89436   ??    0.0 S     4T   0:00.04   0:00.02 /usr/bin/some_command with some parameters
                 89436         0.0 S     4T   0:00.00   0:00.00 
someuser     89517   ??    0.0 S    31T   1:21.10  12:08.73 /usr/bin/some_command with some parameters
                 89517         0.0 S    31T   0:00.00   0:00.00 
                 89517         0.0 S     0T   0:00.05   0:00.03 
                 89517         0.0 S    31T   0:24.50   0:33.51 
                 89517         0.0 S    31T   0:00.00   0:00.00 
                 89517         0.0 S    31T   1:10.56   3:32.25 
                 89517         0.0 S    31T   0:00.00   0:00.00 
                 89517         0.0 S    31T   0:00.14   0:00.17 
                 89517         0.0 S    31T   0:00.10   0:00.15 
                 89517         0.0 S    31T   0:00.21   0:00.23 
                 89517         0.0 S    31T   0:00.10   0:00.18 
                 89517         0.0 S    31T   0:00.00   0:00.00 
                 89517         0.0 S    31T   0:00.04   0:00.03 
                 89517         0.0 S    31T   0:00.18   0:00.15 
                 89517         0.0 S    31T   0:00.20   0:00.16 
                 89517         0.0 S    31T   0:00.20   0:00.15 
                 89517         0.0 S    31T   0:00.18   0:00.15 
                 89517         0.0 S    31T   0:00.17   0:00.12 
                 89517         0.0 S    31T   0:00.18   0:00.12 
                 89517         0.0 S    31T   0:00.18   0:00.12 
                 89517         0.0 S    31T   0:00.22   0:00.12 
                 89517         0.0 S    31T   0:00.14   0:00.02 
                 89517         0.0 S    31T   0:00.12   0:00.05 
                 89517         0.0 S    31T   0:00.10   0:00.17 
someuser     92412   ??    0.0 S    31T   0:19.36   1:03.93 /usr/bin/some_command with some parameters
                 92412         0.0 S    31T   0:00.00   0:00.00 
                 92412         0.0 S     0T   0:00.02   0:00.02 
                 92412         0.0 S    31T   0:02.58   0:02.93 
                 92412         0.0 S    31T   0:00.00   0:00.00 
                 92412         0.0 S    31T   0:01.08   0:06.32 
                 92412         0.0 S    31T   0:00.00   0:00.00 
                 92412         0.0 S    31T   0:00.06   0:00.17 
                 92412         0.0 S    31T   0:00.04   0:00.18 
                 92412         0.0 S    31T   0:00.04   0:00.17 
                 92412         0.0 S    31T   0:00.05   0:00.17 
                 92412         0.0 S    31T   0:00.00   0:00.00 
                 92412         0.0 S    31T   0:00.11   0:00.02 
                 92412         0.0 S    31T   0:00.03   0:00.02 
                 92412         0.0 S    31T   0:00.03   0:00.02 
                 92412         0.0 S    31T   0:00.01   0:00.02 
                 92412         0.0 S    31T   0:00.20   0:00.07 
                 92412         0.0 S    31T   0:00.01   0:00.00 
                 92412         0.0 S    31T   0:00.00   0:00.00 
someuser     96559   ??    0.0 S    46T   0:13.24   0:26.60 /usr/bin/some_command with some parameters
                 96559         0.0 S    46T   0:00.60   0:00.29 
                 96559         0.0 S    31T   0:00.00   0:00.00 
someuser     97411   ??    0.0 S    31T   0:01.26   0:01.54 /usr/bin/some_command with some parameters
                 97411         0.0 S    31T   0:00.00   0:00.00 
                 97411         0.0 S     0T   0:00.04   0:00.03 
                 97411         0.0 S    31T   0:00.64   0:00.45 
                 97411         0.0 S    31T   0:00.00   0:00.00 
                 97411         0.0 S    31T   0:00.00   0:00.00 
                 97411         0.0 S    31T   0:00.00   0:00.00 
                 97411         0.0 S    31T   0:00.00   0:00.00 
                 97411         0.0 S    31T   0:00.00   0:00.00 
                 97411         0.0 S    31T   0:00.00   0:00.00 
                 97411         0.0 S    31T   0:00.00   0:00.00 
                 97411         0.0 S    31T   0:00.00   0:00.00 
                 97411         0.0 S    31T   0:00.19   0:00.04 
                 97411         0.0 S    31T   0:00.01   0:00.01 
                 97411         0.0 S    31T   0:00.00   0:00.00 
someuser     98939   ??    0.0 S    31T   0:05.17   0:23.65 /usr/bin/some_command with some parameters
                 98939         0.0 S    31T   0:00.00   0:00.00 
                 98939         0.0 S     0T   0:00.02   0:00.02 
                 98939         0.0 S    31T   0:00.81   0:00.64 
                 98939         0.0 S    31T   0:00.00   0:00.00 
                 98939         0.0 S    31T   0:00.88   0:02.66 
                 98939         0.0 S    31T   0:00.00   0:00.00 
                 98939         0.0 S    31T   0:00.02   0:00.04 
                 98939         0.0 S    31T   0:00.01   0:00.05 
                 98939         0.0 S    31T   0:00.04   0:00.07 
                 98939         0.0 S    31T   0:00.02   0:00.03 
                 98939         0.0 S    31T   0:00.00   0:00.01 
                 98939         0.0 S    31T   0:00.12   0:00.02 
                 98939         0.0 S    31T   0:00.14   0:00.05 
                 98939         0.0 S    31T   0:00.08   0:00.15 
                 98939         0.0 S    31T   0:00.01   0:00.07 
someuser     99779   ??    0.0 S    31T   0:02.61   0:08.14 /usr/bin/some_command with some parameters
                 99779         0.0 S    31T   0:00.00   0:00.00 
                 99779         0.0 S     0T   0:00.02   0:00.02 
                 99779         0.0 S    31T   0:00.47   0:00.22 
                 99779         0.0 S    31T   0:00.00   0:00.00 
                 99779         0.0 S    31T   0:00.09   0:00.32 
                 99779         0.0 S    31T   0:00.00   0:00.00 
                 99779         0.0 S    31T   0:00.00   0:00.00 
                 99779         0.0 S    31T   0:00.00   0:00.00 
                 99779         0.0 S    31T   0:00.00   0:00.00 
                 99779         0.0 S    31T   0:00.00   0:00.01 
                 99779         0.0 S    31T   0:00.00   0:00.00 
                 99779         0.0 S    31T   0:00.08   0:00.02 
                 99779         0.0 S    31T   0:00.07   0:00.02 
                 99779         0.0 S    31T   0:00.00   0:00.00 
someuser     99817   ??    0.0 S    31T   0:00.60   0:00.17 /usr/bin/some_command with some parameters
                 99817         0.0 S    31T   0:00.00   0:00.00 
                 99817         0.0 S    31T   0:00.07   0:00.05 
                 99817         0.0 S     0T   0:00.06   0:00.05 
                 99817         0.0 S    31T   0:00.14   0:00.04 
                 99817         0.0 S    31T   0:00.00   0:00.00 
                 99817         0.0 S    31T   0:00.12   0:00.05 
                 99817         0.0 S    31T   0:00.00   0:00.00 
                 99817         0.0 S    31T   0:00.00   0:00.00 
                 99817         0.0 S    31T   0:00.00   0:00.00 
                 99817         0.0 S    31T   0:00.00   0:00.00 
                 99817         0.0 S    31T   0:00.00   0:00.00 
                 99817         0.0 S    31T   0:00.00   0:00.00 
                 99817         0.0 S    31T   0:00.00   0:00.00 
someuser     99889   ??    0.0 S    31T   0:02.90   0:03.20 /usr/bin/some_command with some parameters
                 99889         0.0 S    31T   0:00.00   0:00.00 
                 99889         0.0 S     0T   0:00.02   0:00.01 
                 99889         0.0 S    31T   0:00.47   0:00.24 
                 99889         0.0 S    31T   0:00.00   0:00.00 
                 99889         0.0 S    31T   0:00.05   0:00.15 
                 99889         0.0 S    31T   0:00.06   0:00.01 
                 99889         0.0 S    31T   0:00.00   0:00.00 
                 99889         0.0 S    31T   0:00.01   0:00.01 
                 99889         0.0 S    31T   0:00.00   0:00.01 
                 99889         0.0 S    31T   0:00.00   0:00.02 
                 99889         0.0 S    31T   0:00.00   0:00.00 
                 99889         0.0 S    31T   0:00.09   0:00.03 
                 99889         0.0 S    31T   0:00.02   0:00.01 
                 99889         0.0 S    31T   0:00.01   0:00.01 
root              2956 s000    0.0 S    31T   0:00.03   0:00.02 /usr/bin/some_command with some parameters
                  2956         0.0 S    31T   0:00.00   0:00.00 
someuser      2959 s000    0.0 S    31T   0:00.30   0:00.26 -bash
someuser      6945 s000    0.0 S    31T   0:00.05   0:00.01 tmux
someuser      6948 s004    0.0 S    31T   0:00.58   0:00.38 -bash
someuser      6999 s005    0.0 S    31T   0:00.52   0:00.29 -bash
someuser      7049 s006    0.0 S    31T   0:00.20   0:00.20 -bash
someuser     11147 s007    0.0 S    31T   0:00.42   0:00.46 -bash
someuser     65815 s008    0.0 S    31T   0:01.10   0:00.67 -bash
someuser      1393 s010    0.0 S    31T   0:00.36   0:00.31 -bash
someuser     26136 s014    0.0 S    31T   0:00.54   0:00.33 /usr/bin/some_command with some parameters
someuser     42855 s026    0.0 S    31T   0:00.64   0:00.36 -bash
root             55350 s026    0.0 R    31T   0:00.00   0:00.00 ps -ax -M
`
