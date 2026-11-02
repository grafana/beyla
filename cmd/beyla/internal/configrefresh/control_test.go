package configrefresh

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// controlSocket returns the parent end of a connected socket pair and passes the other end to
// ControlConn through the environment, as a parent process would.
func controlSocket(t *testing.T) (parent, child net.Conn) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	require.NoError(t, err)

	parentFile := os.NewFile(uintptr(fds[0]), "parent")
	defer parentFile.Close()
	parent, err = net.FileConn(parentFile)
	require.NoError(t, err)
	t.Cleanup(func() { parent.Close() })

	t.Setenv(ControlFDEnv, strconv.Itoa(fds[1]))
	child, err = ControlConn()
	require.NoError(t, err)
	require.NotNil(t, child)
	return parent, child
}

type controlClient struct {
	t       *testing.T
	encoder *json.Encoder
	decoder *json.Decoder
}

func newControlClient(t *testing.T, conn net.Conn) *controlClient {
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	return &controlClient{t: t, encoder: json.NewEncoder(conn), decoder: json.NewDecoder(conn)}
}

func (c *controlClient) refresh(config []byte) controlResponse {
	c.t.Helper()
	require.NoError(c.t, c.encoder.Encode(controlRequest{Config: string(config)}))
	var response controlResponse
	require.NoError(c.t, c.decoder.Decode(&response))
	return response
}

func TestControlConn_NotProvided(t *testing.T) {
	t.Setenv(ControlFDEnv, "")
	conn, err := ControlConn()
	require.NoError(t, err)
	assert.Nil(t, conn)
}

func TestControlConn_Invalid(t *testing.T) {
	t.Setenv(ControlFDEnv, "not-a-number")
	_, err := ControlConn()
	require.ErrorContains(t, err, "invalid")

	file, err := os.Create(filepath.Join(t.TempDir(), "regular"))
	require.NoError(t, err)
	defer file.Close()
	t.Setenv(ControlFDEnv, strconv.Itoa(int(file.Fd())))
	_, err = ControlConn()
	require.ErrorContains(t, err, "not a socket")
}

func TestServe(t *testing.T) {
	parent, child := controlSocket(t)
	var received [][]byte
	served := make(chan struct{})
	go func() {
		defer close(served)
		Serve(t.Context(), child, func(_ context.Context, data []byte) error {
			received = append(received, data)
			if bytes.Contains(data, []byte("reject")) {
				return errors.New("restart Beyla to apply this configuration")
			}
			return nil
		})
	}()

	client := newControlClient(t, parent)
	assert.Empty(t, client.refresh([]byte("accept: first")).Error)
	assert.Equal(t, "restart Beyla to apply this configuration", client.refresh([]byte("reject: second")).Error)
	assert.Empty(t, client.refresh([]byte("accept: third")).Error)

	// Closing its end tells Beyla that the parent won't send more requests.
	require.NoError(t, parent.Close())
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after the parent closed the socket")
	}
	assert.Equal(t, [][]byte{[]byte("accept: first"), []byte("reject: second"), []byte("accept: third")}, received)
}

func TestServe_StopsWithContext(t *testing.T) {
	parent, child := controlSocket(t)
	ctx, cancel := context.WithCancel(t.Context())
	served := make(chan struct{})
	go func() {
		defer close(served)
		Serve(ctx, child, func(context.Context, []byte) error { return nil })
	}()

	cancel()
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after its context was canceled")
	}

	require.NoError(t, parent.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, err := parent.Read(make([]byte, 1))
	assert.ErrorIs(t, err, io.EOF, "the parent must see the control socket closed")
}

func TestServe_Refresher(t *testing.T) {
	initial := watcherConfig(8080)
	refresher := newAcceptingRefresher(t, initial)
	parent, child := controlSocket(t)
	go Serve(t.Context(), child, refresher.Refresh)

	client := newControlClient(t, parent)
	assert.Empty(t, client.refresh(watcherConfig(9090)).Error)
	criteria, _ := refresher.Updater().Updates().Current()
	require.Len(t, criteria, 1)
	assert.True(t, criteria[0].GetOpenPorts().Matches(9090))

	rejected := client.refresh(bytes.Replace(watcherConfig(9090), []byte("localhost:4318"), []byte("collector:4318"), 1))
	assert.Contains(t, rejected.Error, "restart Beyla")
	criteria, _ = refresher.Updater().Updates().Current()
	assert.True(t, criteria[0].GetOpenPorts().Matches(9090), "a rejected refresh must keep the running criteria")
}
