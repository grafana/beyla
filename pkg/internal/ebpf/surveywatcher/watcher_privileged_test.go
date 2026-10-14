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
	assert.Contains(t, state.Snapshot(), server.identity, "seed existing listeners")
	assert.Contains(t, state.Snapshot(), keepalive.identity, "seed existing established connections")
	assert.NotContains(t, state.Snapshot(), client.identity, "idle processes must remain held")

	// The connection closes before userspace reads the map. A thread exiting
	// immediately afterwards must not erase the process's evidence either.
	require.Equal(t, "ok", client.command(t, "thread_connect "+address))
	require.Eventually(t, func() bool {
		_, ok := state.Snapshot()[client.identity]
		return ok
	}, 3*time.Second, 10*time.Millisecond)
	require.NotEmpty(t, listener.command(t, "listen"))
	require.Equal(t, "ok", unixClient.command(t, "unix "+unixPath))
	require.Eventually(t, func() bool {
		_, listening := state.Snapshot()[listener.identity]
		_, unixConnected := state.Snapshot()[unixClient.identity]
		return listening && unixConnected
	}, 3*time.Second, 10*time.Millisecond)

	// Port flags: the seeded helper listened on an ephemeral port, the kprobe
	// observed listener too. A privileged bind requires CAP_NET_BIND_SERVICE.
	require.Eventually(t, func() bool {
		snapshot := state.Snapshot()
		for process := range snapshot {
			if process.PID == server.identity.PID && process.Namespace == server.identity.Namespace {
				return process.Flags&FlagNonPrivileged != 0 && process.Flags&FlagPrivileged == 0
			}
		}
		return false
	}, 3*time.Second, 10*time.Millisecond, "seeded ephemeral listener must be flagged unprivileged")
	require.NotEmpty(t, privileged.command(t, "listen_privileged"))
	require.Eventually(t, func() bool {
		snapshot := state.Snapshot()
		for process := range snapshot {
			if process.PID == privileged.identity.PID && process.Namespace == privileged.identity.Namespace {
				return process.Flags&FlagPrivileged != 0
			}
		}
		return false
	}, 3*time.Second, 10*time.Millisecond, "kprobe must flag a privileged listener")

	client.stop(t)
	require.Eventually(t, func() bool {
		_, ok := state.Snapshot()[client.identity]
		return !ok
	}, 2*recoveryInterval, 50*time.Millisecond, "remove evidence on the last thread's exit")
	assert.Contains(t, state.Snapshot(), server.identity)
	assert.Contains(t, state.Snapshot(), keepalive.identity)
}

type socketHelper struct {
	cmd      *exec.Cmd
	input    io.WriteCloser
	output   *bufio.Scanner
	identity Process
}

func startSocketHelper(t *testing.T) *socketHelper {
	t.Helper()
	executable, err := os.Executable()
	require.NoError(t, err)
	// testing cancels t.Context before Cleanup. Let the helpers exit gracefully
	// when their input closes, so cleanup doesn't race CommandContext's SIGKILL.
	childCtx, cancel := context.WithCancel(context.WithoutCancel(t.Context()))
	cmd := exec.CommandContext(childCtx, executable, "-test.run=^TestSurveySocketHelper$")
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
		if fields[0] == "listen" || fields[0] == "listen_privileged" {
			address := "127.0.0.1:0"
			if fields[0] == "listen_privileged" {
				address = "127.0.0.1:1"
			}
			listener, err := net.Listen("tcp4", address)
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
			if fields[0] == "unix" {
				network = "unix"
			}
			conn, err := net.DialTimeout(network, fields[1], time.Second)
			if err != nil {
				fmt.Println("error:", err)
				return
			}
			if fields[0] == "keepalive" {
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
