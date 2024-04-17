package main

import (
	"fmt"
	"net/http"
	"os"
	"time"
)

func main() {
	for {
		r, err := http.Get(os.Getenv("TARGET_URL"))
		if err != nil {
			fmt.Println("error!", err)
		}
		if r != nil {
			fmt.Println("response:", r.Status)
		}
		time.Sleep(time.Second)
	}
}
