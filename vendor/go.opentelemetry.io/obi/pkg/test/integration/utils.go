// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"bytes"
	"crypto/tls"
	"net/http"

	"github.com/stretchr/testify/require"
)

// HTTP client for testing
var testHTTPClient = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

func DoHTTPGet(t require.TestingT, path string, status int) {
	// Random fake body to cause the request to have some size (38 bytes)
	jsonBody := []byte(`{"productId": 123456, "quantity": 100}`)

	req, err := http.NewRequest(http.MethodGet, path, bytes.NewReader(jsonBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	r, err := testHTTPClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, status, r.StatusCode)
}
