package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	grpcclient "github.com/grafana/beyla/v2/internal/test/integration/components/testserver/grpc/client"
)

func main() {

	// Adding shutdown hook for graceful stop.
	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	for {
		if err := grpcclient.PingCtx(ctx, grpcclient.WithServerAddr(os.Getenv("TARGET_URL"))); err != nil {
			fmt.Println("error pinging:", err)
		} else {
			fmt.Println("ping succeed!")
		}
		select {
		case <-time.After(time.Second):
		// go to the next loop!
		case <-ctx.Done():
			fmt.Println("got signal. Exiting")
			os.Exit(0)
		}
	}
}
