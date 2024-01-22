package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"time"

	"golang.org/x/net/http2"
)

func checkErr(err error, msg string) {
	if err == nil {
		return
	}
	fmt.Printf("ERROR: %s: %s\n", msg, err)
	os.Exit(1)
}

func main() {
	for {
		fmt.Printf("Waiting on input, press any key to continue...")
		var input string
		fmt.Scanln(&input)
		HttpClientExample()
		RoundTripExample()
	}
}

const url = "https://localhost:8080/ping"

func RoundTripExample() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	checkErr(err, "during new request")

	tr := &http2.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	resp, err := tr.RoundTrip(req)
	checkErr(err, "during roundtrip")

	fmt.Printf("RoundTrip Proto: %d\n", resp.ProtoMajor)
}

func HttpClientExample() {
	client := http.Client{
		Transport: &http2.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Get(url)
	checkErr(err, "during get")

	fmt.Printf("Client Proto: %d\n", resp.ProtoMajor)
}
