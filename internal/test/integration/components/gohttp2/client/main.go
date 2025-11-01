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
}

func main() {
	for {
		HttpClientExample()
		RoundTripExample()
		HttpClientDoExample()

		time.Sleep(time.Second)
	}
}

func RoundTripExample() {
	req, err := http.NewRequestWithContext(context.Background(), "GET", os.Getenv("TARGET_URL")+"/pingrt", nil)
	checkErr(err, "during new request")

	tr := &http2.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	resp, err := tr.RoundTrip(req)
	checkErr(err, "during roundtrip")

	if err == nil {
		fmt.Printf("RoundTrip Proto: %d\n", resp.ProtoMajor)
	}
}

func HttpClientExample() {
	client := http.Client{
		Transport: &http2.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Get(os.Getenv("TARGET_URL") + "/ping")
	checkErr(err, "during get")

	if err == nil {
		fmt.Printf("Client Proto: %d\n", resp.ProtoMajor)
	}
}

func HttpClientDoExample() {
	client := http.Client{
		Transport: &http2.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, err := http.NewRequestWithContext(context.Background(), "GET", os.Getenv("TARGET_URL")+"/pingdo", nil)
	checkErr(err, "during new request")

	resp, err := client.Do(req)
	checkErr(err, "during get")

	if err == nil {
		fmt.Printf("Client.Do Proto: %d\n", resp.ProtoMajor)
	}
}
