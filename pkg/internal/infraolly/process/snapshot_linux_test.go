// Copyright 2020 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
//nolint:goerr113
package process

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"testing"

	"github.com/newrelic/infrastructure-agent/pkg/helpers"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLinuxProcess_CmdLine(t *testing.T) {
	hostProc := os.Getenv("HOST_PROC")
	defer os.Setenv("HOST_PROC", hostProc)
	tmpDir, err := ioutil.TempDir("", "proc")
	require.NoError(t, err)
	processDir := path.Join(tmpDir, "12345")
	require.NoError(t, os.MkdirAll(processDir, 0o755))
	_ = os.Setenv("HOST_PROC", tmpDir)

	testCases := []struct {
		rawProcCmdline []byte
		expected       string
	}{
		{[]byte{0}, ""},
		{[]byte{'b', 'a', 's', 'h', 0}, "bash"},
		{[]byte{'/', 'b', 'i', 'n', '/', 'b', 'a', 's', 'h', 0}, "/bin/bash"},
		{[]byte{'/', 'b', 'i', 'n', '/', 'b', 'a', 's', 'h', 0, 'a', 'r', 'g', 0}, "/bin/bash arg"},
		{[]byte{'-', '/', 'b', 'i', 'n', '/', 'b', 'a', 's', 'h', 0, 'a', 'r', 'g', 0}, "/bin/bash arg"},
		{
			[]byte{'/', 'a', ' ', 'f', 'o', 'l', 'd', 'e', 'r', '/', 'c', 'm', 'd', 0, '-', 'a', 'g', 0, 'x', 'x', 0},
			"/a folder/cmd -ag xx",
		},
	}
	for _, tc := range testCases {
		require.NoError(t, ioutil.WriteFile(path.Join(processDir, "cmdline"), tc.rawProcCmdline, 0o600))
		lp := linuxProcess{pid: 12345}
		actual, err := lp.CmdLine(true)
		assert.NoError(t, err)
		assert.Equal(t, tc.expected, actual)
	}
}

func TestLinuxProcess_CmdLine_NoArgs(t *testing.T) {
	hostProc := os.Getenv("HOST_PROC")
	defer os.Setenv("HOST_PROC", hostProc)
	tmpDir, err := ioutil.TempDir("", "proc")
	require.NoError(t, err)
	processDir := path.Join(tmpDir, "12345")
	require.NoError(t, os.MkdirAll(processDir, 0o755))
	_ = os.Setenv("HOST_PROC", tmpDir)

	testCases := []struct {
		rawProcCmdline []byte
		expected       string
	}{
		{[]byte{0}, ""},
		{[]byte{'b', 'a', 's', 'h', 0}, "bash"},
		{[]byte{'-', 'b', 'a', 's', 'h', 0}, "bash"},
		{[]byte{'/', 'b', 'i', 'n', '/', 'b', 'a', 's', 'h', 0}, "/bin/bash"},
		{[]byte{'/', 'b', 'i', 'n', '/', 'b', 'a', 's', 'h', 0, 'a', 'r', 'g', 0}, "/bin/bash"},
		{
			[]byte{'/', 'a', ' ', 'f', 'o', 'l', 'd', 'e', 'r', '/', 'c', 'm', 'd', 0, '-', 'a', 'g', 0, 'x', 'x', 0},
			"/a folder/cmd",
		},
	}
	for _, tc := range testCases {
		require.NoError(t, ioutil.WriteFile(path.Join(processDir, "cmdline"), tc.rawProcCmdline, 0o600))
		lp := linuxProcess{pid: 12345}
		actual, err := lp.CmdLine(false)
		assert.NoError(t, err)
		assert.Equal(t, tc.expected, actual)
	}
}

// Test nonstandard implementations of the /proc/<pid>/cmdline format, which don't use zeroes to separate nor
// end the command lines. (e.g. Nginx create processes whose cmdline is "nginx: master process /usr/sbin/nginx"
func TestLinuxProcess_CmdLine_NotStandard(t *testing.T) {
	hostProc := os.Getenv("HOST_PROC")
	defer os.Setenv("HOST_PROC", hostProc)
	tmpDir, err := ioutil.TempDir("", "proc")
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
		require.NoError(t, ioutil.WriteFile(path.Join(processDir, "cmdline"), tc.rawProcCmdline, 0o600))
		lp := linuxProcess{pid: 12345}

		// Testing both the cases with and without command line stripping
		actual, err := lp.CmdLine(true)
		assert.NoError(t, err)
		assert.Equal(t, tc.expected, actual)

		actual, err = lp.CmdLine(false)
		assert.NoError(t, err)
		assert.Equal(t, tc.expected, actual)
	}
}

func TestLinuxProcess_CmdLine_ProcessNotExist(t *testing.T) {
	lp := linuxProcess{pid: 999999999}
	actual, err := lp.CmdLine(true)
	assert.NoError(t, err)
	assert.Equal(t, "", actual)
}

func TestLinuxProcess_CmdLine_ProcessNotExist_NoStrip(t *testing.T) {
	lp := linuxProcess{pid: 999999999}
	actual, err := lp.CmdLine(false)
	assert.NoError(t, err)
	assert.Equal(t, "", actual)
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
			Percent: 0,
			User:    3.78,
			System:  0.6,
		},
	}
	actual, err := parseProcStat(content)
	assert.NoError(t, err)

	assert.Equal(t, expected, actual)
}

func TestParseProcStatSingleWordProcess(t *testing.T) {
	content := `1232 (newrelic-infra) S 1 1232 1232 0 -1 1077960960 4799 282681 88 142 24 15 193 94 20 0 12 0 1071 464912384 4490 18446744073709551615 1 1 0 0 0 0 0 0 2143420159 0 0 0 17 0 0 0 14 0 0 0 0 0 0 0 0 0 0`

	expected := procStats{
		command:    "newrelic-infra",
		ppid:       1,
		numThreads: 12,
		state:      "S",
		vmRSS:      18391040,
		vmSize:     464912384,
		cpu: CPUInfo{
			Percent: 0,

			User:   0.24,
			System: 0.15,
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
		expected: procStats{command: "/usr/bin/spamd ", state: "S", ppid: 1, cpu: CPUInfo{User: 2.50, System: 0.32}, numThreads: 1, vmSize: 300249088, vmRSS: 18439 * pageSize},
	}, {
		input:    "11159 (spamd child) S 11155 11155 11155 0 -1 1077944384 459 0 0 0 1 0 0 0 20 0 1 0 6285738 300249088 17599 18446744073709551615 4194304 4198572 140721992060048 140721992059288 139789215727443 0 0 4224 2048 18446744072271262725 0 0 17 0 0 0 0 0 0 6298944 6299796 18743296 140721992060730 140721992060807 140721992060807 140721992060905 0\n",
		expected: procStats{command: "spamd child", state: "S", ppid: 11155, cpu: CPUInfo{User: 0.01, System: 0}, numThreads: 1, vmSize: 300249088, vmRSS: 17599 * pageSize},
	}, {
		input:    "11160 ( spamd child) S 11155 11155 11155 0 -1 1077944384 459 0 0 0 0 0 0 0 20 0 1 0 6285738 300249088 17599 18446744073709551615 4194304 4198572 140721992060048 140721992059288 139789215727443 0 0 4224 2048 18446744072271262725 0 0 17 0 0 0 0 0 0 6298944 6299796 18743296 140721992060730 140721992060807 140721992060807 140721992060905 0\n",
		expected: procStats{command: " spamd child", state: "S", ppid: 11155, cpu: CPUInfo{User: 0, System: 0}, numThreads: 1, vmSize: 300249088, vmRSS: 17599 * pageSize},
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

	//nolint:paralleltest
	for i := range testCases {
		testCase := testCases[i]
		t.Run(testCase.name, func(t *testing.T) {
			getEntCommand = func(command string, stdin string, args ...string) (string, error) {
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
