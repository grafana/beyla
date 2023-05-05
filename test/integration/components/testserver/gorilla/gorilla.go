package gorilla

import (
	"fmt"
	"net/http"

	"github.com/grafana/ebpf-autoinstrument/test/integration/components/testserver/std"

	"github.com/gorilla/mux"
	"golang.org/x/exp/slog"
)

func Setup(port, stdPort int) {
	log := slog.With("component", "gorilla.Server")
	r := mux.NewRouter()
	r.PathPrefix("/").HandlerFunc(std.HTTPHandler(log, stdPort))

	address := fmt.Sprintf(":%d", port)
	log.Info("starting HTTP server", "address", address)
	err := http.ListenAndServe(address, r)
	log.Error("HTTP server has unexpectedly stopped", err)
}
