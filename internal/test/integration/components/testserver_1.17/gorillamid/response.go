package gorillamid

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
)

// responseWriterSniffer properly handles responses that could not be written and exposes
// the statusCode and the underlying error.
type responseWriterSniffer struct {
	rw         http.ResponseWriter
	statusCode int
	writeError error // The error returned when downstream Write() fails.
}

// newResponseWriterSniffer makes a new responseWriterSniffer.
func newResponseWriterSniffer(rw http.ResponseWriter) *responseWriterSniffer {
	return &responseWriterSniffer{
		rw:         rw,
		statusCode: http.StatusOK,
	}
}

// Header returns the header map that will be sent by WriteHeader.
// Implements ResponseWriter.
func (b *responseWriterSniffer) Header() http.Header {
	return b.rw.Header()
}

// Write writes HTTP response data.
func (b *responseWriterSniffer) Write(data []byte) (int, error) {
	if b.statusCode == 0 {
		// WriteHeader has (probably) not been called, so we need to call it with StatusOK to fuflil the interface contract.
		// https://godoc.org/net/http#ResponseWriter
		b.WriteHeader(http.StatusOK)
	}
	n, err := b.rw.Write(data)
	if err != nil {
		b.writeError = err
	}
	return n, err
}

// WriteHeader writes the HTTP response header.
func (b *responseWriterSniffer) WriteHeader(statusCode int) {
	b.statusCode = statusCode
	b.rw.WriteHeader(statusCode)
}

// Hijack hijacks the first response writer that is a Hijacker.
func (b *responseWriterSniffer) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := b.rw.(http.Hijacker)
	if ok {
		return hj.Hijack()
	}
	return nil, nil, fmt.Errorf("responseWriterSniffer: can't cast underlying response writer to Hijacker")
}
