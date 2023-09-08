package main

import (
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"
)

var tr = &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
}
var testHTTPClient = &http.Client{Transport: tr}

func main() {
	counter := 1
	for {
		req, err := http.NewRequest("GET", "https://grafana.com", nil)
		if err != nil {
			fmt.Println("error creating request:", err)
			return
		}
		var traceID [16]byte
		var spanID [8]byte
		binary.BigEndian.PutUint64(traceID[:8], uint64(counter))
		binary.BigEndian.PutUint64(spanID[:], uint64(counter))

		// Generate a traceparent that we easily recognize
		tp := fmt.Sprintf("00-%s-%s-01", hex.EncodeToString(traceID[:]), hex.EncodeToString(spanID[:]))
		req.Header.Set("traceparent", tp)

		r, err := testHTTPClient.Do(req)
		if err != nil {
			fmt.Println("error!", err)
		}
		if r != nil {
			fmt.Println("response:", r.Status)
		}
		time.Sleep(time.Second)
		counter++
	}
}
