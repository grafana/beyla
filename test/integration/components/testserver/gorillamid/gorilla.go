package gorillamid

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"golang.org/x/exp/slog"

	"github.com/grafana/ebpf-autoinstrument/test/integration/components/testserver/std"
)

func Setup(port, stdPort int) {
	log := slog.With("component", "gorilla.Server")
	r := mux.NewRouter()
	r.PathPrefix("/").HandlerFunc(std.HTTPHandler(log, stdPort))

	middlewares := []Interface{
		StatusConcealer{},
	}

	h := Merge(middlewares...).Wrap(r)

	address := fmt.Sprintf(":%d", port)
	log.Info("starting HTTP server with middleware", "address", address)
	err := http.ListenAndServe(address, h)
	log.Error("HTTP server has unexpectedly stopped", err)
}
