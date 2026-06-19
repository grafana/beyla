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
	"syscall"
	"time"
)

// Check if remote JVM has already opened socket for Dynamic Attach
func checkSocket(pid int, tmpPath string) bool {
	path := fmt.Sprintf("%s/.java_pid%d", tmpPath, pid)
	info, err := os.Stat(path)
	return err == nil && (info.Mode()&os.ModeSocket != 0)
}

// Check if a file is owned by current user
func getFileOwner(path string) int {
	info, err := os.Stat(path)
	if err != nil {
		return -1
	}
	stat := info.Sys().(*syscall.Stat_t)
	return int(stat.Uid)
}

func createAttachFile(attachPid, nspid int, tmpPath string) (string, error) {
	path := fmt.Sprintf("/proc/%d/cwd/.attach_pid%d", attachPid, nspid)
	fd, err := os.Create(path)
	if err == nil {
		err = fd.Close()
	}
	if err != nil || getFileOwner(path) != os.Geteuid() {
		_ = os.Remove(path)
		path = fmt.Sprintf("%s/.attach_pid%d", tmpPath, nspid)
		fd, err = os.Create(path)
		if err != nil {
			return "", err
		}
		if err := fd.Close(); err != nil {
			_ = os.Remove(path)
			return "", err
		}
	}

	return path, nil
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
func startAttachMechanism(ctx context.Context, pid, nspid, attachPid int, tmpPath string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	path, err := createAttachFile(attachPid, nspid, tmpPath)
	if err != nil {
		return err
	}
	defer os.Remove(path)

	if err := syscall.Kill(pid, syscall.SIGQUIT); err != nil {
		return err
	}

	ts := 20 * time.Millisecond
	for i := 0; i < 300; i++ {
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
func writeHotspotCommand(ctx context.Context, conn net.Conn, args []string) error {
	request := make([]byte, 0)

	request = append(request, byte('1'))
	request = append(request, byte(0))

	for i := 0; i < 4; i++ {
		if i < len(args) {
			request = append(request, []byte(args[i])...)
		}
		request = append(request, byte(0))
	}

	if err := ctx.Err(); err != nil {
		return err
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

func jattachHotspot(ctx context.Context, pid, nspid, attachPid int, args []string, tmpPath string, logger *slog.Logger) (io.ReadCloser, error) {
	if !checkSocket(nspid, tmpPath) {
		if err := startAttachMechanism(ctx, pid, nspid, attachPid, tmpPath); err != nil {
			return nil, err
		}
	}

	conn, err := connectSocket(ctx, nspid, tmpPath)
	if err != nil {
		return nil, fmt.Errorf("could not connect to JVM socket: %w", err)
	}

	logger.Debug("connected to the JVM")

	if err := writeHotspotCommand(ctx, conn, args); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("error writing to the JVM socket: %w", err)
	}

	return conn, nil
}
