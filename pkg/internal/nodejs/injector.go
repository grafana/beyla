package nodejs

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

type message struct {
	ID     int                    `json:"id"`
	Method string                 `json:"method"`
	Params map[string]interface{} `json:"params,omitempty"`
}

type inspectorTarget struct {
	WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
}

// IMPORTANT: the code in this file needs to run in the network namespace of the
// target process in order to be able to connect to its inspector port - the
// network namespace switching is done by the withNetNS function, which locks
// the current go routine to the current thread, ensuring the current thread
// runs in the right network namespace - as a result, we need to manually
// initiate the connection, as net/http and gorilla/websocket dialers may
// spawn go routines of their own, which can potentially end up on a different
// thread (and consequently, in the wrong namespace)

func connect(addr string, port int) (net.Conn, error) {
	ip := net.ParseIP(addr).To4()

	if ip == nil {
		return nil, fmt.Errorf("only IPv4 supported, got: %s", addr)
	}

	sa := &syscall.SockaddrInet4{
		Port: port,
	}

	copy(sa.Addr[:], ip)

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)

	if err != nil {
		return nil, fmt.Errorf("socket: %w", err)
	}

	if err := syscall.Connect(fd, sa); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("connect: %w", err)
	}

	file := os.NewFile(uintptr(fd), fmt.Sprintf("tcp:%s:%d", addr, port))

	if file == nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("failed to create os.File from fd")
	}

	conn, err := net.FileConn(file)

	if err != nil {
		file.Close()
		return nil, fmt.Errorf("fileconn: %w", err)
	}

	file.Close()

	return conn, nil
}

func connectWait(ip string, port int, timeout time.Duration, interval time.Duration) (net.Conn, error) {
	deadline := time.Now().Add(timeout)

	for {
		conn, err := connect(ip, port)

		if err == nil {
			return conn, nil
		}

		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timed out waiting for %s:%d", ip, port)
		}

		time.Sleep(interval)
		continue
	}
}

func httpGet(conn net.Conn, path string) ([]byte, error) {
	req, err := http.NewRequest("GET", path, nil)

	if err != nil {
		return []byte{}, fmt.Errorf("request error: %w", err)
	}

	if err = req.Write(conn); err != nil {
		return []byte{}, fmt.Errorf("error writing request: %w", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)

	if err != nil {
		return []byte{}, fmt.Errorf("error reading response: %w", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)

	if err != nil {
		return []byte{}, fmt.Errorf("response body error: %w", err)
	}

	return body, nil
}

func (i *NodeInjector) requestDebuggerURL(conn net.Conn) (string, error) {
	res, err := httpGet(conn, "/json/list")

	if err != nil {
		return "", err
	}

	i.log.Debug("received response", "response", res)

	if err != nil {
		return "", err
	}

	var targets []inspectorTarget

	if err := json.Unmarshal(res, &targets); err != nil {
		return "", fmt.Errorf("invalid JSON %w", err)
	}

	if len(targets) == 0 {
		return "", fmt.Errorf("no debugging targets available")
	}

	return targets[0].WebSocketDebuggerURL, nil
}

func upgradeConn(conn net.Conn, wsURL string) (*websocket.Conn, *http.Response, error) {
	dialer := websocket.Dialer{
		NetDial: func(_, _ string) (net.Conn, error) {
			return conn, nil
		},
	}

	wsConn, resp, err := dialer.Dial(wsURL, nil)
	return wsConn, resp, err
}

// nolint:cyclop
func (i *NodeInjector) injectFileWS(wsConn *websocket.Conn, file string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	defer func() {
		_ = wsConn.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
			time.Now().Add(time.Second),
		)
	}()

	respMap := make(map[int]chan map[string]interface{})
	var mu sync.Mutex

	go func() {
		for {
			_, msg, err := wsConn.ReadMessage()

			if err != nil {
				if !websocket.IsCloseError(err, websocket.CloseNormalClosure) {
					i.log.Error("WebSocket read error", "error", err)
				}

				wsConn.Close()
				return
			}

			var parsed map[string]interface{}

			if err := json.Unmarshal(msg, &parsed); err != nil {
				continue
			}

			if idRaw, ok := parsed["id"]; ok {
				id := int(idRaw.(float64))
				mu.Lock()
				ch, ok := respMap[id]
				mu.Unlock()

				if ok {
					ch <- parsed
				}

			} else {
				b, _ := json.MarshalIndent(parsed, "", "  ")
				i.log.Debug("[event]", "payload", string(b))
			}
		}
	}()

	send := func(id int, method string, params map[string]interface{}) (map[string]interface{}, error) {
		ch := make(chan map[string]interface{}, 1)

		mu.Lock()
		respMap[id] = ch
		mu.Unlock()

		if err := wsConn.WriteJSON(message{ID: id, Method: method, Params: params}); err != nil {
			return nil, err
		}

		select {
		case resp := <-ch:
			return resp, nil
		case <-ctx.Done():
			return nil, fmt.Errorf("timeout waiting for response to %d", id)
		}
	}

	if _, err := send(1, "Runtime.enable", nil); err != nil {
		return fmt.Errorf("failed to enable runtime: %w", err)
	}

	expr := fmt.Sprintf("require(%q)", file)

	res, err := send(2, "Runtime.evaluate", map[string]interface{}{
		"expression":            expr,
		"includeCommandLineAPI": true,
		"silent":                false,
	})

	if err != nil {
		return fmt.Errorf("evaluation error: %w", err)
	}

	if result, ok := res["result"].(map[string]interface{}); ok {
		if ex, ok := result["exceptionDetails"]; ok {
			return fmt.Errorf("injection failed: %+v", ex)
		}
	} else {
		return fmt.Errorf("injection failed")
	}

	i.log.Info("Script successfully injected")

	return nil
}

func (i *NodeInjector) injectFile(file string) error {
	conn, err := connectWait("127.0.0.1", 9229, 5*time.Second, 200*time.Millisecond)

	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	wsURL, err := i.requestDebuggerURL(conn)

	if err != nil {
		conn.Close()
		return err
	}

	i.log.Debug("found debugger url", "url", wsURL)

	wsConn, _, err := upgradeConn(conn, wsURL)

	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to connect to inspector WebSocket: %w", err)
	}

	return i.injectFileWS(wsConn, file)
}

func (i *NodeInjector) inject(pid int, file string) error {
	return withNetNS(pid, func() error { return i.injectFile(file) })
}
