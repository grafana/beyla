package gin

import (
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/grafana/beyla/test/integration/components/testserver/arg"
)

func Setup(port int) {
	log := slog.With("component", "gin.Server")
	r := gin.Default()

	r.Any("/*path", func(ctx *gin.Context) {
		log.Debug("received request", "url", ctx.Request.RequestURI)
		status := arg.DefaultStatus
		if sstr := ctx.Query(arg.Status); sstr != "" {
			if s, err := strconv.Atoi(sstr); err != nil {
				log.Debug("wrong status value. Ignoring", "error", err)
			} else {
				status = s
			}
		}
		if dstr := ctx.Query(arg.Delay); dstr != "" {
			if d, err := time.ParseDuration(dstr); err != nil {
				log.Debug("wrong delay value. Ignoring", "error", err)
			} else {
				time.Sleep(d)
			}
		}
		ctx.String(status, "")
	})

	address := fmt.Sprintf(":%d", port)
	log.Info("starting HTTP server", "address", address)
	err := r.Run(address)
	log.Error("HTTP server has unexpectedly stopped", "error", err)
}
