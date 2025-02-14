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

//go:build linux

package process

import (
	"errors"
	"fmt"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/v2/pkg/internal/helpers"
)

func TestLinuxProcess_CmdLine(t *testing.T) {
	hostProc := os.Getenv("HOST_PROC")
	defer os.Setenv("HOST_PROC", hostProc)
	tmpDir, err := os.MkdirTemp("", "proc")
	require.NoError(t, err)
	processDir := path.Join(tmpDir, "12345")
	require.NoError(t, os.MkdirAll(processDir, 0o755))
	_ = os.Setenv("HOST_PROC", tmpDir)

	testCases := []struct {
		rawProcCmdline   []byte
		expectedExec     string
		expectedExecPath string
		expectedArgs     []string
		expectedCmdLine  string
	}{
		{[]byte{0}, "", "", nil, ""},
		{[]byte{'b', 'a', 's', 'h', 0}, "bash", "bash", nil, "bash"},
		{[]byte{'/', 'b', 'i', 'n', '/', 'b', 'a', 's', 'h', 0}, "bash", "/bin/bash", nil, "/bin/bash"},
		{[]byte{'/', 'b', 'i', 'n', '/', 'b', 'a', 's', 'h', 0, 'a', 'r', 'g', 0}, "bash", "/bin/bash", []string{"arg"}, "/bin/bash arg"},
		{[]byte{'-', '/', 'b', 'i', 'n', '/', 'b', 'a', 's', 'h', 0, 'a', 'r', 'g', 0}, "bash", "/bin/bash", []string{"arg"}, "/bin/bash arg"},
		{
			[]byte{'/', 'a', ' ', 'f', 'o', 'l', 'd', 'e', 'r', '/', 'c', 'm', 'd', 0, '-', 'a', 'g', 0, 'x', 'x', 0},
			"cmd", "/a folder/cmd", []string{"-ag", "xx"}, "/a folder/cmd -ag xx",
		},
	}
	for _, tc := range testCases {
		require.NoError(t, os.WriteFile(path.Join(processDir, "cmdline"), tc.rawProcCmdline, 0o600))
		lp := linuxProcess{pid: 12345, procFSRoot: tmpDir}
		lp.fetchCommandInfo()
		assert.Equal(t, tc.expectedExecPath, lp.execPath)
		assert.Equal(t, tc.expectedArgs, lp.commandArgs)
		assert.Equal(t, tc.expectedCmdLine, lp.commandLine)
	}
}

// Test nonstandard implementations of the /proc/<pid>/cmdline format, which don't use zeroes to separate nor
// end the command lines. (e.g. Nginx create processes whose cmdline is "nginx: master process /usr/sbin/nginx"
func TestLinuxProcess_CmdLine_NotStandard(t *testing.T) {
	hostProc := os.Getenv("HOST_PROC")
	defer os.Setenv("HOST_PROC", hostProc)
	tmpDir, err := os.MkdirTemp("", "proc")
	require.NoError(t, err)
	processDir := path.Join(tmpDir, "12345")
	require.NoError(t, os.MkdirAll(processDir, 0o755))
	_ = os.Setenv("HOST_PROC", tmpDir)

	testCases := []struct {
		rawProcCmdline []byte
		expected       string
	}{
		{[]byte("nginx: worker process"), "nginx: worker process"},
		{[]byte("nginx: master process /usr/sbin/nginx"), "nginx: master process /usr/sbin/nginx"},
		{
			[]byte("nginx: master process /usr/sbin/nginx -c /etc/nginx/nginx.conf"),
			"nginx: master process /usr/sbin/nginx -c /etc/nginx/nginx.conf",
		},
	}
	for _, tc := range testCases {
		require.NoError(t, os.WriteFile(path.Join(processDir, "cmdline"), tc.rawProcCmdline, 0o600))
		lp := linuxProcess{pid: 12345, procFSRoot: tmpDir}

		lp.fetchCommandInfo()
		assert.Equal(t, tc.expected, lp.commandLine)
	}
}

func TestLinuxProcess_CmdLine_ProcessNotExist(t *testing.T) {
	lp := linuxProcess{pid: 999999999}
	lp.fetchCommandInfo()
	assert.Empty(t, lp.execPath)
	assert.Empty(t, lp.commandArgs)
	assert.Empty(t, lp.commandLine)
}

func TestParseProcStatMultipleWordsProcess(t *testing.T) {
	content := `465 (node /home/ams-) S 7648 465 465 0 -1 4202496 85321 6128 0 0 378 60 9 2 20 0 11 0 6384148 1005015040 21241 18446744073709551615 4194304 36236634 140729243085280 140729243069424 140119099392231 0 0 4096 16898 18446744073709551615 0 0 17 1 0 0 0 0 0 38337168 38426896 57044992 140729243093258 140729243093333 140729243093333 140729243095018 0`

	expected := procStats{
		command:    "node /home/ams-",
		ppid:       7648,
		numThreads: 11,
		state:      "S",
		vmRSS:      87003136,
		vmSize:     1005015040,
		cpu: CPUInfo{
			UserTime:   3.78,
			SystemTime: 0.6,
			WaitTime:   0.11,
		},
	}
	actual, err := parseProcStat(content)
	assert.NoError(t, err)

	assert.Equal(t, expected, actual)
}

func TestParseProcStatSingleWordProcess(t *testing.T) {
	content := `1232 (foo-bar) S 1 1232 1232 0 -1 1077960960 4799 282681 88 142 24 15 193 94 20 0 12 0 1071 464912384 4490 18446744073709551615 1 1 0 0 0 0 0 0 2143420159 0 0 0 17 0 0 0 14 0 0 0 0 0 0 0 0 0 0`

	expected := procStats{
		command:    "foo-bar",
		ppid:       1,
		numThreads: 12,
		state:      "S",
		vmRSS:      18391040,
		vmSize:     464912384,
		cpu: CPUInfo{
			UserTime:   0.24,
			SystemTime: 0.15,
			WaitTime:   2.87,
		},
	}
	actual, err := parseProcStat(content)
	assert.NoError(t, err)

	assert.Equal(t, expected, actual)
}

func TestParseProcStatUntrimmedCommand(t *testing.T) {
	cases := []struct {
		input    string
		expected procStats
	}{{
		input:    "11155 (/usr/bin/spamd ) S 1 11155 11155 0 -1 1077944640 19696 1028 0 0 250 32 0 0 20 0 1 0 6285571 300249088 18439 18446744073709551615 4194304 4198572 140721992060048 140721992059288 139789215727443 0 0 4224 92163 18446744072271262725 0 0 17 1 0 0 0 0 0 6298944 6299796 18743296 140721992060730 140721992060807 140721992060807 140721992060905 0\n",
		expected: procStats{command: "/usr/bin/spamd ", state: "S", ppid: 1, cpu: CPUInfo{UserTime: 2.50, SystemTime: 0.32}, numThreads: 1, vmSize: 300249088, vmRSS: 18439 * pageSize},
	}, {
		input:    "11159 (spamd child) S 11155 11155 11155 0 -1 1077944384 459 0 0 0 1 0 0 0 20 0 1 0 6285738 300249088 17599 18446744073709551615 4194304 4198572 140721992060048 140721992059288 139789215727443 0 0 4224 2048 18446744072271262725 0 0 17 0 0 0 0 0 0 6298944 6299796 18743296 140721992060730 140721992060807 140721992060807 140721992060905 0\n",
		expected: procStats{command: "spamd child", state: "S", ppid: 11155, cpu: CPUInfo{UserTime: 0.01, SystemTime: 0}, numThreads: 1, vmSize: 300249088, vmRSS: 17599 * pageSize},
	}, {
		input:    "11160 ( spamd child) S 11155 11155 11155 0 -1 1077944384 459 0 0 0 0 0 0 0 20 0 1 0 6285738 300249088 17599 18446744073709551615 4194304 4198572 140721992060048 140721992059288 139789215727443 0 0 4224 2048 18446744072271262725 0 0 17 0 0 0 0 0 0 6298944 6299796 18743296 140721992060730 140721992060807 140721992060807 140721992060905 0\n",
		expected: procStats{command: " spamd child", state: "S", ppid: 11155, cpu: CPUInfo{UserTime: 0, SystemTime: 0}, numThreads: 1, vmSize: 300249088, vmRSS: 17599 * pageSize},
	}}

	for n, c := range cases {
		t.Run(fmt.Sprint("test", n), func(t *testing.T) {
			actual, err := parseProcStat(c.input)
			assert.NoError(t, err)
			assert.Equal(t, c.expected, actual)
		})
	}
}

func Test_usernameFromGetent(t *testing.T) { //nolint:paralleltest
	testCases := []struct {
		name             string
		getEntResult     string
		getEntError      error
		expectedUsername string
		expectedError    error
	}{
		{
			name:             "happy path, user exists",
			getEntResult:     "deleteme:x:63367:63367:Dynamic User:/:/usr/sbin/nologin",
			expectedUsername: "deleteme",
		},
		{
			name:             "getent returns error (i.e. does not exist)",
			getEntError:      errors.New("some error"),
			expectedUsername: "",
			expectedError:    errors.New("some error"),
		},
		{
			name:             "getent returns unexpected formatted entry",
			getEntResult:     "this is an unexpected format",
			expectedUsername: "",
			expectedError:    errMalformedGetentEntry,
		},
	}

	for i := range testCases {
		testCase := testCases[i]
		t.Run(testCase.name, func(t *testing.T) {
			getEntCommand = func(_, _ string, _ ...string) (string, error) {
				return testCase.getEntResult, testCase.getEntError
			}
			defer func() {
				getEntCommand = helpers.RunCommand
			}()

			username, err := usernameFromGetent(123)
			assert.Equal(t, testCase.expectedUsername, username)
			assert.Equal(t, testCase.expectedError, err)
		})
	}
}

func TestNetworkBytes(t *testing.T) {
	netDev := []byte(`Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:   41292     444    0    0    0     0          0         0    33111     444    0    0    0     0       0          0
  eth0:  233606    1024    0    0    0     0          0         0   44123     775    0    0    0     0       0          0
br-26b494c37194:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0
docker0:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0
br-a3d66a1fd7b9:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0
`)
	rx, tx := parseProcNetDev(netDev)
	assert.EqualValues(t, 41292+233606, rx)
	assert.EqualValues(t, 33111+44123, tx)
}

func TestNetworkBytes_Corrupt(t *testing.T) {
	t.Run("nil net/dev", func(t *testing.T) {
		assert.NotPanics(t, func() {
			parseProcNetDev(nil)
		})
	})
	t.Run("empty net/dev", func(t *testing.T) {
		assert.NotPanics(t, func() {
			parseProcNetDev([]byte{})
		})
	})
	t.Run("arbitrary/random net/dev", func(t *testing.T) {
		assert.NotPanics(t, func() {
			parseProcNetDev([]byte{1, 2, 3, 4, 5, '\n', 3, 34, 56, 12, 67})
		})
	})
	t.Run("net/dev without proper header", func(t *testing.T) {
		netDev := []byte(`lo:   41292     444    0    0    0     0          0         0    33111     444    0    0    0     0       0          0
  eth0:  233606    1024    0    0    0     0          0         0   44123     775    0    0    0     0       0          0
br-26b494c37194:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0
docker0:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0
br-a3d66a1fd7b9:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0
`)
		rx, tx := parseProcNetDev(netDev)
		assert.EqualValues(t, 233606, rx)
		assert.EqualValues(t, 44123, tx)
	})
	t.Run("incomplete net/dev", func(t *testing.T) {
		netDev := []byte(`Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:   41292     444    0    0    0     0          0         0    33111     444    0    0    0     0       0          0
  eth0:  233606    1024    0    0    0     0      `)
		rx, tx := parseProcNetDev(netDev)
		assert.EqualValues(t, 41292, rx)
		assert.EqualValues(t, 33111, tx)
	})
}
