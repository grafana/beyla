package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
)

var tr = &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
}
var testHTTPClient = &http.Client{Transport: tr}

func main() {
	for {
		r, err := testHTTPClient.Get("https://grafana.com")
		if err != nil {
			fmt.Println("error!", err)
		}
		if r != nil {
			fmt.Println("response:", r.Status)
		}
		time.Sleep(time.Second)
	}
}
