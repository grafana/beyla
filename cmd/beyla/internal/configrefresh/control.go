package configrefresh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
)

// ControlFDEnv names the environment variable holding the number of a file descriptor that a
// parent process, such as Alloy, passes to Beyla: a connected unix stream socket over which the
// parent submits configuration refreshes. The parent keeps the other end, so no other process
// can connect to it.
const ControlFDEnv = "BEYLA_CONFIG_CONTROL_FD"

// controlRequest asks the running Beyla to refresh from a complete YAML configuration.
type controlRequest struct {
	Config string `json:"config"`
}

// controlResponse answers a controlRequest. An empty Error means that the running Beyla applied
// the configuration. Otherwise, Beyla keeps running the previous configuration.
type controlResponse struct {
	Error string `json:"error,omitempty"`
}

// ControlConn returns the control socket passed by the parent process, or nil if there is none.
func ControlConn() (net.Conn, error) {
	value := os.Getenv(ControlFDEnv)
	if value == "" {
		return nil, nil
	}

	fd, err := strconv.Atoi(value)
	if err != nil || fd < 0 {
		return nil, fmt.Errorf("invalid %s value %q", ControlFDEnv, value)
	}

	file := os.NewFile(uintptr(fd), "beyla-config-control")
	defer file.Close()

	// FileConn duplicates the descriptor with close-on-exec, so it isn't inherited any further.
	conn, err := net.FileConn(file)
	if err != nil {
		return nil, fmt.Errorf("%s=%d is not a socket: %w", ControlFDEnv, fd, err)
	}

	if _, ok := conn.(*net.UnixConn); !ok {
		conn.Close()
		return nil, fmt.Errorf("%s=%d is not a unix socket", ControlFDEnv, fd)
	}

	return conn, nil
}

// Serve answers the configuration refresh requests sent over conn, one at a time and in order,
// until ctx is done or the parent closes conn. Each request and response is a JSON object.
func Serve(ctx context.Context, conn net.Conn, refresh func(context.Context, []byte) error) {
	log := slog.With("component", "config.Control")

	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	defer conn.Close()

	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)
	for {
		var request controlRequest
		// When decoding fails, we assume there's some major problem, Alloy sent us malformed
		// payload or terminated the connection with EOF. We close ours to notify Alloy and
		// have it restart the component.
		if err := decoder.Decode(&request); err != nil {
			if ctx.Err() == nil && !errors.Is(err, io.EOF) {
				log.Error("can't read configuration refresh request; closing the control socket", "error", err)
			}
			return
		}

		var response controlResponse
		if err := refresh(ctx, []byte(request.Config)); err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Warn("configuration refresh rejected; continuing with the running configuration", "error", err)
			response.Error = err.Error()
		} else {
			log.Info("discovery criteria refreshed")
		}

		// Same here, if we can't encode the response back to Alloy, we close the socket and have Alloy reload us.
		if err := encoder.Encode(response); err != nil {
			if ctx.Err() == nil {
				log.Error("can't answer configuration refresh request; closing the control socket", "error", err)
			}
			return
		}
	}
}
