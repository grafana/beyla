package http

import (
	"io"
	"net/http"
	"time"

	"github.com/vladimirvivien/gexe/vars"
)

// ResourceReader provides types and methods to read content of resources from a server using HTTP
type ResourceReader struct {
	client *http.Client
	err    error
	url    string
	vars   *vars.Variables
}

// Get initiates a "GET" operation for the specified resource
func Get(url string) *ResourceReader {
	return &ResourceReader{url: url, client: &http.Client{}, vars: &vars.Variables{}}
}

// Get initiates a "GET" operation and sets session variables
func GetWithVars(url string, variables *vars.Variables) *ResourceReader {
	r := Get(variables.Eval(url))
	r.vars = variables
	return r
}

// SetVars sets session variables for ResourceReader
func (r *ResourceReader) SetVars(variables *vars.Variables) *ResourceReader {
	r.vars = variables
	return r
}

// Err returns the last known error
func (r *ResourceReader) Err() error {
	return r.err
}

// WithTimeout sets the HTTP reader's timeout
func (r *ResourceReader) WithTimeout(to time.Duration) *ResourceReader {
	r.client.Timeout = to
	return r
}

// Do invokes the client.Get to "GET" the content from server
// Use Response.Err() to access server response errors
func (r *ResourceReader) Do() *Response {
	res, err := r.client.Get(r.url)
	if err != nil {
		return &Response{err: err}
	}
	return &Response{stat: res.Status, statCode: res.StatusCode, body: res.Body}
}

// Bytes returns the server response as a []byte
// This is a shorthad for ResourceReader.Do().Bytes()
func (r *ResourceReader) Bytes() []byte {
	resp := r.Do()
	if resp.Err() != nil {
		r.err = resp.Err()
		return nil
	}
	return resp.Bytes()
}

// String returns the server response as a string.
// It is a shorthad for ResourceReader.Do().String()
func (r *ResourceReader) String() string {
	resp := r.Do()
	if resp.Err() != nil {
		r.err = resp.Err()
		return ""
	}
	return resp.String()
}

// Body returns the server response body (as io.ReadCloser).
// It is a shorthand for ResourceReader().Do().Body()
// NOTE: ensure to close the stream when finished.
func (r *ResourceReader) Body() io.ReadCloser {
	resp := r.Do()
	if resp.Err() != nil {
		r.err = resp.Err()
		return nil
	}
	return resp.Body()
}
