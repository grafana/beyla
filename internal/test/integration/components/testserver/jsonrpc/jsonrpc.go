package jsonrpc

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/rpc"
	"net/rpc/jsonrpc"
)

// Args defines the arguments for the RPC methods.
type Args struct {
	A, B int
}

// Arith provides methods for arithmetic operations.
type Arith struct {
	Logger *slog.Logger
}

// Multiply multiplies two numbers and returns the result.
func (t *Arith) Multiply(args *Args, reply *int) error {
	t.Logger.Debug("calling", "method", "Arith.Multiply")
	*reply = args.A * args.B
	return nil
}

func (t *Arith) Traceme(args *Args, reply *int) error {
	t.Logger.Debug("calling", "method", "Arith.Traceme")
	requestURL := "http://pytestserver:7773/tracemetoo"

	t.Logger.Debug("calling", "url", requestURL)

	res, err := http.Get(requestURL)
	if err != nil {
		slog.Error("error making http request", "error", err)
		return err
	}

	defer res.Body.Close()
	return t.Multiply(args, reply)
}

// ReadWriteCloserWrapper wraps an io.Reader and io.Writer to implement io.ReadWriteCloser.
type ReadWriteCloserWrapper struct {
	io.Reader
	io.Writer
}

// Close is a no-op to satisfy the io.ReadWriteCloser interface.
func (w *ReadWriteCloserWrapper) Close() error {
	return nil
}

func Setup(port int) {
	log := slog.With("component", "jsonrpc.Arith")
	arith := &Arith{
		Logger: log,
	}
	_ = rpc.Register(arith)

	address := fmt.Sprintf(":%d", port)
	log.Info("starting JSON-RPC server", "address", address)
	err := http.ListenAndServe(address, HTTPHandler(log))
	log.Error("JSON-RPC server has unexpectedly stopped", "error", err)
}

func HTTPHandler(log *slog.Logger) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		log.Debug("received request", "url", req.RequestURI)
		if req.RequestURI == "/jsonrpc" {
			if req.Method != http.MethodPost {
				http.Error(rw, "Only POST method is allowed", http.StatusMethodNotAllowed)
				return
			}
			// Wrap the request body and response writer in a ReadWriteCloser.
			conn := &ReadWriteCloserWrapper{Reader: req.Body, Writer: rw}
			// Serve the request using JSON-RPC codec.
			rpc.ServeCodec(jsonrpc.NewServerCodec(conn))
		} else {
			rw.WriteHeader(http.StatusOK)
		}
	}
}
