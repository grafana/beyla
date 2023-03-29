package std

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/grafana/ebpf-autoinstrument/test/integration/components/testserver/arg"
	"golang.org/x/exp/slog"
)

func HTTPHandler(log *slog.Logger) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		log.Debug("received request", "url", req.RequestURI)
		status := arg.DefaultStatus
		for k, v := range req.URL.Query() {
			if len(v) == 0 {
				continue
			}
			switch k {
			case arg.Status:
				if s, err := strconv.Atoi(v[0]); err != nil {
					log.Debug("wrong status value. Ignoring", "error", err)
				} else {
					status = s
				}
			case arg.Delay:
				if d, err := time.ParseDuration(v[0]); err != nil {
					log.Debug("wrong delay value. Ignoring", "error", err)
				} else {
					time.Sleep(d)
				}
			}
		}
		rw.WriteHeader(status)
	}
}

func Setup(port int) {
	log := slog.With("component", "std.Server")
	address := fmt.Sprintf(":%d", port)
	log.Info("starting HTTP server", "address", address)
	err := http.ListenAndServe(address, HTTPHandler(log))
	log.Error("HTTP server has unexpectedly stopped", err)
}
