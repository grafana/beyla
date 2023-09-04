package main

import (
	"fmt"
	"os"
	"time"

	grpcclient "github.com/grafana/beyla/test/integration/components/testserver/grpc/client"
)

func main() {
	for {
		if err := grpcclient.Ping(grpcclient.WithServerAddr(os.Getenv("TARGET_URL"))); err != nil {
			fmt.Println("error pinging:", err)
		} else {
			fmt.Println("ping succeed!")
		}
		time.Sleep(time.Second)
	}
}
