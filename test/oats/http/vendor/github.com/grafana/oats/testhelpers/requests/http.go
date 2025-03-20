package requests

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/http"
)

var tr = &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
}
var testHTTPClient = &http.Client{Transport: tr}

func DisableKeepAlives(disableKeepAlives bool) {
	testHTTPClient.Transport.(*http.Transport).DisableKeepAlives = disableKeepAlives
}

func doRequest(req *http.Request, statusCode int) error {
	req.Header.Set("Content-Type", "application/json")

	r, err := testHTTPClient.Do(req)

	if err != nil {
		return err
	}

	if r.StatusCode != statusCode {
		return fmt.Errorf("expected HTTP status %d, but got: %d", statusCode, r.StatusCode)
	}

	return nil
}

func DoHTTPPost(url string, statusCode int, jsonBody []byte) error {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(jsonBody))

	if err != nil {
		return err
	}

	return doRequest(req, statusCode)
}

func DoHTTPGet(url string, statusCode int) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)

	if err != nil {
		return err
	}

	return doRequest(req, statusCode)
}
