package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
)

const (
	address = "localhost:50055"
)

// simple example program that shows how to connect a gRPC+protobuf client to the Kube API cache
func main() {
	// Set up a connection to the server.
	conn, err := grpc.NewClient(address,
		grpc.WithTransportCredentials(insecure.NewCredentials()))

	if err != nil {
		slog.Error("could not connect", "address", address, "error", err)
		os.Exit(-1)
	}
	client := informer.NewEventStreamServiceClient(conn)

	// Subscribe to the event stream.
	stream, err := client.Subscribe(context.TODO(), &informer.SubscribeMessage{})
	if err != nil {
		slog.Error("could not subscribe", "error", err)
		_ = conn.Close()
		os.Exit(-1)
	}
	defer conn.Close()

	// Receive and print messages.
	for {
		event, err := stream.Recv()
		if err != nil {
			slog.Error("receiving message", "error", err)
			break
		}
		fmt.Printf("Received event: %v\n", event)
	}
}
