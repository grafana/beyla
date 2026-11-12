//go:build linux && integration

package surveywatcher

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/procfs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/obi"
)

// Run explicitly with BEYLA_TEST_SURVEY_BPF=1 and BPF privileges. Also run inside
// a nested PID namespace. Set BEYLA_TEST_SURVEY_PIDNS=1 with CAP_SYS_ADMIN to
// give every helper a separate PID namespace: their PID 1 keys must not collide.
func TestSurveyWatcherKernel(t *testing.T) {
	if os.Getenv("BEYLA_TEST_SURVEY_BPF") != "1" {
		t.Skip("set BEYLA_TEST_SURVEY_BPF=1 to run the privileged socket watcher test")
	}
	require.NoError(t, rlimit.RemoveMemlock())
	server := startSocketHelper(t)
	address := server.command(t, "listen")
	keepalive := startSocketHelper(t)
	require.Equal(t, "ok", keepalive.command(t, "keepalive "+address))
	client := startSocketHelper(t)
	listener := startSocketHelper(t)
	unixClient := startSocketHelper(t)
	unixPath := filepath.Join(t.TempDir(), "socket")
	unixListener, err := net.Listen("unix", unixPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = unixListener.Close() })

	privileged := startSocketHelper(t)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	state, err := Start(ctx, &obi.DefaultConfig, &ebpfcommon.EBPFEventContext{})
	require.NoError(t, err)
	assert.NotZero(t, server.flags(state), "seed existing listeners")
	assert.NotZero(t, keepalive.flags(state), "seed existing established connections")
	assert.Zero(t, client.flags(state), "idle processes must remain held")

	// The connection closes before userspace reads the map. A thread exiting
	// immediately afterwards must not erase the process's evidence either.
	require.Equal(t, "ok", client.command(t, "thread_connect "+address))
	require.Eventually(t, func() bool {
		return client.flags(state) != 0
	}, 3*time.Second, 10*time.Millisecond)
	require.NotEmpty(t, listener.command(t, "listen"))
	require.Equal(t, "ok", unixClient.command(t, "unix "+unixPath))
	require.Eventually(t, func() bool {
		return listener.flags(state) != 0 && unixClient.flags(state) != 0
	}, 3*time.Second, 10*time.Millisecond)

	// Port flags: the seeded helper listened on an ephemeral port, the kprobe
	// observed listener too. A privileged bind requires CAP_NET_BIND_SERVICE.
	require.Eventually(t, func() bool {
		return server.flags(state)&FlagNonPrivileged != 0 && server.flags(state)&FlagPrivileged == 0
	}, 3*time.Second, 10*time.Millisecond, "seeded ephemeral listener must be flagged unprivileged")
	require.NotEmpty(t, privileged.command(t, "listen_privileged"))
	require.Eventually(t, func() bool {
		return privileged.flags(state)&FlagPrivileged != 0
	}, 3*time.Second, 10*time.Millisecond, "kprobe must flag a privileged listener")

	client.stop(t)
	require.Eventually(t, func() bool {
		return client.flags(state) == 0
	}, 2*recoveryInterval, 50*time.Millisecond, "remove evidence on the last thread's exit")
	assert.NotZero(t, server.flags(state))
	assert.NotZero(t, keepalive.flags(state))
}

func TestSurveyWatcherUnixSockets(t *testing.T) {
	if os.Getenv("BEYLA_TEST_SURVEY_BPF") != "1" {
		t.Skip("set BEYLA_TEST_SURVEY_BPF=1 to run the privileged socket watcher test")
	}
	require.NoError(t, rlimit.RemoveMemlock())
	for _, abstract := range []bool{false, true} {
		name := "filesystem"
		if abstract {
			name = "abstract"
		}
		t.Run(name, func(t *testing.T) {
			address := filepath.Join(t.TempDir(), "sock")
			if abstract {
				address = "@" + address
			}
			server := startSocketHelper(t)
			require.Equal(t, address, server.command(t, "listen_unix "+address))
			keepalive := startSocketHelper(t)
			require.Equal(t, "ok", keepalive.command(t, "keepalive_unix "+address))
			client := startSocketHelper(t)
			listener := startSocketHelper(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			state, err := Start(ctx, &obi.DefaultConfig, &ebpfcommon.EBPFEventContext{})
			require.NoError(t, err)
			assert.Equal(t, FlagAny, server.flags(state), "seed a Unix listener without port flags")
			assert.Equal(t, FlagAny, keepalive.flags(state), "seed an established Unix connection")
			assert.Zero(t, client.flags(state))
			require.Equal(t, "ok", client.command(t, "unix "+address))
			require.Equal(t, address+"-live", listener.command(t, "listen_unix "+address+"-live"))
			require.Eventually(t, func() bool {
				return client.flags(state) == FlagAny && listener.flags(state) == FlagAny
			}, 3*time.Second, 10*time.Millisecond, "observe new Unix connects and listeners without port flags")
		})
	}
}

// Workers created after the startup iterator inherit their listener without
// calling connect or listen. Their first accept must supply socket evidence.
func TestSurveyWatcherInheritedListeners(t *testing.T) {
	if os.Getenv("BEYLA_TEST_SURVEY_BPF") != "1" {
		t.Skip("set BEYLA_TEST_SURVEY_BPF=1 to run the privileged socket watcher test")
	}
	require.NoError(t, rlimit.RemoveMemlock())
	for _, network := range []string{"unix", "tcp4"} {
		t.Run(network, func(t *testing.T) {
			address := "127.0.0.1:0"
			expectedFlags := FlagAny | FlagNonPrivileged
			if network == "unix" {
				address = filepath.Join(t.TempDir(), "sock")
				expectedFlags = FlagAny
			}
			listener, err := net.Listen(network, address)
			require.NoError(t, err)
			defer listener.Close()
			file, err := listener.(interface{ File() (*os.File, error) }).File()
			require.NoError(t, err)
			defer file.Close()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			state, err := Start(ctx, &obi.DefaultConfig, &ebpfcommon.EBPFEventContext{})
			require.NoError(t, err)
			worker := startSocketHelper(t, file)
			assert.Zero(t, worker.flags(state), "worker starts after the startup iterator")
			conn, err := net.DialTimeout(network, listener.Addr().String(), time.Second)
			require.NoError(t, err)
			defer conn.Close()
			require.Equal(t, "ok", worker.command(t, "accept"))
			require.Eventually(t, func() bool {
				return worker.flags(state) == expectedFlags
			}, 3*time.Second, 10*time.Millisecond, "admit the accepting worker with the listener's port policy")
			worker.stop(t)
			require.Eventually(t, func() bool {
				return worker.flags(state) == 0
			}, 2*recoveryInterval, 50*time.Millisecond, "remove the worker's evidence on exit")
		})
	}
}

type socketHelper struct {
	cmd      *exec.Cmd
	input    io.WriteCloser
	output   *bufio.Scanner
	identity Process
}

func startSocketHelper(t *testing.T, files ...*os.File) *socketHelper {
	t.Helper()
	executable, err := os.Executable()
	require.NoError(t, err)
	// testing cancels t.Context before Cleanup. Let the helpers exit gracefully
	// when their input closes, so cleanup doesn't race CommandContext's SIGKILL.
	childCtx, cancel := context.WithCancel(context.WithoutCancel(t.Context()))
	cmd := exec.CommandContext(childCtx, executable, "-test.run=^TestSurveySocketHelper$")
	cmd.ExtraFiles = files
	if os.Getenv("BEYLA_TEST_SURVEY_PIDNS") == "1" {
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWPID}
	}
	cmd.Env = append(os.Environ(), "BEYLA_SOCKET_HELPER=1")
	cmd.Stderr = os.Stderr
	input, err := cmd.StdinPipe()
	require.NoError(t, err)
	output, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	h := &socketHelper{cmd: cmd, input: input, output: bufio.NewScanner(output)}
	t.Cleanup(func() {
		defer cancel()
		h.stop(t)
	})
	require.True(t, h.output.Scan())
	require.Equal(t, "ready", h.output.Text())
	p, err := procfs.NewProc(cmd.Process.Pid)
	require.NoError(t, err)
	stat, err := p.Stat()
	require.NoError(t, err)
	status, err := p.NewStatus()
	require.NoError(t, err)
	require.NotEmpty(t, status.NSpids)
	namespaces, err := p.Namespaces()
	require.NoError(t, err)
	h.identity = Process{
		PID: uint32(status.NSpids[len(status.NSpids)-1]), Namespace: namespaces["pid"].Inode, StartTime: stat.Starttime,
	}
	return h
}

func (h *socketHelper) flags(state *State) uint8 {
	for process := range state.Snapshot() {
		if process.PID == h.identity.PID && process.Namespace == h.identity.Namespace && process.StartTime == h.identity.StartTime {
			return process.Flags
		}
	}
	return 0
}

func (h *socketHelper) command(t *testing.T, command string) string {
	t.Helper()
	_, err := fmt.Fprintln(h.input, command)
	require.NoError(t, err)
	require.True(t, h.output.Scan(), "helper response: %v", h.output.Err())
	response := h.output.Text()
	require.False(t, strings.HasPrefix(response, "error:"), response)
	return response
}

func (h *socketHelper) stop(t *testing.T) {
	t.Helper()
	if h.cmd.ProcessState != nil {
		return
	}
	_ = h.input.Close()
	assert.NoError(t, h.cmd.Wait())
}

func TestSurveySocketHelper(t *testing.T) {
	if os.Getenv("BEYLA_SOCKET_HELPER") != "1" {
		return
	}
	fmt.Println("ready")
	commands := bufio.NewScanner(os.Stdin)
	var sockets []io.Closer
	defer func() {
		for _, socket := range sockets {
			_ = socket.Close()
		}
	}()
	for commands.Scan() {
		fields := strings.Fields(commands.Text())
		if fields[0] == "accept" {
			file := os.NewFile(3, "inherited-listener")
			listener, err := net.FileListener(file)
			_ = file.Close()
			if err != nil {
				fmt.Println("error:", err)
				continue
			}
			_ = listener.(interface{ SetDeadline(time.Time) error }).SetDeadline(time.Now().Add(3 * time.Second))
			conn, err := listener.Accept()
			_ = listener.Close()
			if err != nil {
				fmt.Println("error:", err)
				continue
			}
			_ = conn.Close()
			fmt.Println("ok")
			continue
		}
		if fields[0] == "listen" || fields[0] == "listen_privileged" || fields[0] == "listen_unix" {
			network := "tcp4"
			address := "127.0.0.1:0"
			switch fields[0] {
			case "listen_privileged":
				address = "127.0.0.1:1"
			case "listen_unix":
				network, address = "unix", fields[1]
			}
			listener, err := net.Listen(network, address)
			if err != nil {
				fmt.Println("error:", err)
				continue
			}
			sockets = append(sockets, listener)
			fmt.Println(listener.Addr())
			continue
		}
		connect := func() {
			network := "tcp4"
			if fields[0] == "unix" || fields[0] == "keepalive_unix" {
				network = "unix"
			}
			conn, err := net.DialTimeout(network, fields[1], time.Second)
			if err != nil {
				fmt.Println("error:", err)
				return
			}
			if fields[0] == "keepalive" || fields[0] == "keepalive_unix" {
				sockets = append(sockets, conn)
			} else {
				_ = conn.Close()
			}
			fmt.Println("ok")
		}
		if fields[0] == "thread_connect" {
			done := make(chan struct{})
			go func() {
				// Returning while locked terminates this OS thread.
				runtime.LockOSThread()
				defer close(done)
				connect()
			}()
			<-done
		} else {
			connect()
		}
	}
}
