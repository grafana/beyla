package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	// Adding shutdown hook for graceful stop.
	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	for {
		r, err := http.Get(os.Getenv("TARGET_URL"))
		if err != nil {
			fmt.Println("error!", err)
		}
		if r != nil {
			fmt.Println("response:", r.Status)
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
