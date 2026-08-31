// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package jvm // import "go.opentelemetry.io/obi/pkg/internal/jvmtools/jvm"

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/internal/procs"
)

// Check if remote JVM has already opened socket for Dynamic Attach
func checkSocket(pid int, tmpPath string) bool {
	path := fmt.Sprintf("%s/.java_pid%d", tmpPath, pid)
	info, err := os.Stat(path)
	return err == nil && (info.Mode()&os.ModeSocket != 0)
}

func createAttachFile(targetCWD *os.File, nspid int, tmpPath string) (func(), error) {
	name := fmt.Sprintf(".attach_pid%d", nspid)
	if targetCWD != nil {
		fd, err := unix.Openat(
			int(targetCWD.Fd()), name,
			unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC|unix.O_CLOEXEC,
			0o666,
		)
		if err == nil {
			var stat unix.Stat_t
			statErr := unix.Fstat(fd, &stat)
			closeErr := unix.Close(fd)
			if statErr == nil && closeErr == nil && int(stat.Uid) == os.Geteuid() {
				return func() { _ = unix.Unlinkat(int(targetCWD.Fd()), name, 0) }, nil
			}
			_ = unix.Unlinkat(int(targetCWD.Fd()), name, 0)
		}
	}

	path := filepath.Join(tmpPath, name)
	fd, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	if err := fd.Close(); err != nil {
		_ = os.Remove(path)
		return nil, err
	}
	return func() { _ = os.Remove(path) }, nil
}

func sleepContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// Force remote JVM to start Attach listener.
// HotSpot will start Attach listener in response to SIGQUIT if it sees .attach_pid file
func startAttachMechanism(
	ctx context.Context,
	process *procs.ProcessHandle,
	nspid int,
	targetCWD *os.File,
	tmpPath string,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	removeAttachFile, err := createAttachFile(targetCWD, nspid, tmpPath)
	if err != nil {
		return err
	}
	defer removeAttachFile()

	if err := process.SendSignal(unix.SIGQUIT); err != nil {
		return err
	}

	ts := 20 * time.Millisecond
	for range 300 {
		if err := sleepContext(ctx, ts); err != nil {
			return err
		}
		if checkSocket(nspid, tmpPath) {
			return nil
		}
		ts += 20 * time.Millisecond
	}

	return errors.New("could not start the attach mechanism")
}

// Connect to UNIX domain socket created by JVM for Dynamic Attach
func connectSocket(ctx context.Context, pid int, tmpPath string) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, "unix", fmt.Sprintf("%s/.java_pid%d", tmpPath, pid))
}

// Send command with arguments to socket
func writeHotspotCommand(
	ctx context.Context,
	process *procs.ProcessHandle,
	conn net.Conn,
	args []string,
) error {
	request := make([]byte, 0)

	request = append(request, byte('1'))
	request = append(request, byte(0))

	for i := range 4 {
		if i < len(args) {
			request = append(request, []byte(args[i])...)
		}
		request = append(request, byte(0))
	}

	if err := ctx.Err(); err != nil {
		return err
	}
	if err := process.Alive(); err != nil {
		return fmt.Errorf("target process exited before writing attach command: %w", err)
	}

	stop := context.AfterFunc(ctx, func() {
		_ = conn.Close()
	})
	_, err := conn.Write(request)
	stop()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return err
}

func jattachHotspot(
	ctx context.Context,
	process *procs.ProcessHandle,
	nspid int,
	args []string,
	targetCWD *os.File,
	tmpPath string,
	logger *slog.Logger,
) (io.ReadCloser, error) {
	if !checkSocket(nspid, tmpPath) {
		if err := startAttachMechanism(ctx, process, nspid, targetCWD, tmpPath); err != nil {
			return nil, err
		}
	}

	conn, err := connectSocket(ctx, nspid, tmpPath)
	if err != nil {
		return nil, fmt.Errorf("could not connect to JVM socket: %w", err)
	}

	logger.Debug("connected to the JVM")

	if err := writeHotspotCommand(ctx, process, conn, args); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("error writing to the JVM socket: %w", err)
	}

	return conn, nil
}
