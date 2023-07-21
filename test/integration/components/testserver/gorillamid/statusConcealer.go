package gorillamid

import (
	"fmt"
	"net/http"
)

type StatusConcealer struct{}

func (sc StatusConcealer) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wrapped := newResponseWriterSniffer(w)
		next.ServeHTTP(wrapped, r)
		statusCode, writeErr := wrapped.statusCode, wrapped.writeError

		fmt.Printf("statusCode=%d, writeErr=%v\n", statusCode, writeErr)
	})
}
