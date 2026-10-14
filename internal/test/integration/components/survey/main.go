package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func main() {
	// Use a different executable path for health checks so discovery only sees
	// the long-lived fixtures selected by exe_path: /survey-fixture.
	if filepath.Base(os.Args[0]) == "survey-healthcheck" {
		ready := filepath.Join("/control", os.Getenv("OTEL_SERVICE_NAME")+".ready")
		if _, err := os.Stat(ready); err != nil {
			os.Exit(1)
		}
		return
	}
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	id := flag.String("id", "", "fixture identity")
	listen := flag.String("listen", "", "initial TCP listen port")
	connect := flag.String("connect", "", "initial TCP connection address")
	flag.Parse()
	if *id == "" {
		return fmt.Errorf("id is required")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	f := socketFixture{}
	defer f.close()
	if *listen != "" {
		if err := f.apply(ctx, "listen "+*listen); err != nil {
			return err
		}
	}
	if *connect != "" {
		if err := f.apply(ctx, "connect "+*connect); err != nil {
			return err
		}
	}
	base := filepath.Join("/control", *id)
	if err := os.WriteFile(base+".ready", []byte(fmt.Sprint(os.Getuid())), 0o644); err != nil {
		return err
	}
	log.Printf("ready: %s, real UID %d", *id, os.Getuid())
	return f.waitForCommands(ctx, base)
}

type socketFixture struct {
	sockets []io.Closer
}

func (f *socketFixture) close() {
	for _, socket := range f.sockets {
		_ = socket.Close()
	}
	f.sockets = nil
}

func (f *socketFixture) apply(ctx context.Context, command string) error {
	action, address, _ := strings.Cut(command, " ")
	switch action {
	case "listen":
		listener, err := net.Listen("tcp", ":"+address)
		if err != nil {
			return err
		}
		f.sockets = append(f.sockets, listener)
	case "connect":
		dialer := net.Dialer{Timeout: 5 * time.Second}
		connection, err := dialer.DialContext(ctx, "tcp", address)
		if err != nil {
			return err
		}
		f.sockets = append(f.sockets, connection)
	case "close":
		f.close()
	default:
		return fmt.Errorf("unknown command %q", command)
	}
	return nil
}

func (f *socketFixture) waitForCommands(ctx context.Context, base string) error {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	var previous string
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			data, err := os.ReadFile(base + ".command")
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				return err
			}
			command := string(data)
			if command == "" || command == previous {
				continue
			}
			if err := f.apply(ctx, command); err != nil {
				return err
			}
			previous = command
			if err := os.WriteFile(base+".result", data, 0o644); err != nil {
				return err
			}
		}
	}
}
