package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"
)

var tr = &http.Transport{
	TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
	ForceAttemptHTTP2: true,
}
var testHTTPClient = &http.Client{Transport: tr, Timeout: 10 * time.Second}

func regularGetRequest(url string, counter int) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
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
}

type MyRoundTripper struct{}

func (rt *MyRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(req.Context(), 10*time.Second)
	defer cancel()

	req = req.WithContext(ctx)
	req.Header.Add("X-My-Header", "my-value")

	// send the request using the custom transport
	res, err := tr.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	// process the response as needed
	return res, nil
}

func rtRequest(url string, counter int) {
	req, err := http.NewRequest(http.MethodOptions, url, nil)
	if err != nil {
		fmt.Println("error creating request:", err)
		return
	}
	var traceID [16]byte
	var spanID [8]byte
	binary.BigEndian.PutUint64(traceID[:8], uint64(counter))
	binary.BigEndian.PutUint64(traceID[8:], uint64(1))
	binary.BigEndian.PutUint64(spanID[:], uint64(counter))

	// Generate a traceparent that we easily recognize
	tp := fmt.Sprintf("00-%s-%s-01", hex.EncodeToString(traceID[:]), hex.EncodeToString(spanID[:]))
	req.Header.Set("traceparent", tp)

	mt := &MyRoundTripper{}

	r, err := mt.RoundTrip(req)
	if err != nil {
		fmt.Println("error!", err)
	}
	if r != nil {
		fmt.Println("response:", r.Status)
	}
}

func main() {
	counter := 1
	for {
		regularGetRequest("https://grafana.com/oss/", counter)
		rtRequest("https://grafana.com/oss/", counter)
		time.Sleep(time.Second)
		counter++
	}
}
