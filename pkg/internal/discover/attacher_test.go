package discover

import (
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/grafana/beyla/pkg/beyla"
	"github.com/grafana/beyla/pkg/internal/ebpf"
	"github.com/grafana/beyla/pkg/internal/exec"
	"github.com/grafana/beyla/pkg/services"
)

func TestSkipSelfInstrumentation(t *testing.T) {
	pid := os.Getpid()

	for _, tt := range []struct {
		ta     *TraceAttacher
		isSelf bool
		test   string
	}{
		{
			ta: &TraceAttacher{
				log:      slog.With("component", "discover.TraceAttacher"),
				Cfg:      &beyla.DefaultConfig,
				beylaPID: pid,
			},
			isSelf: true,
			test:   "Default config",
		},
		{
			ta: &TraceAttacher{
				log:      slog.With("component", "discover.TraceAttacher"),
				Cfg:      &beyla.DefaultConfig,
				beylaPID: 0,
			},
			isSelf: false,
			test:   "Default config, non-beyla pid",
		},
		{
			ta: &TraceAttacher{
				log:      slog.With("component", "discover.TraceAttacher"),
				Cfg:      &beyla.Config{Discovery: services.DiscoveryConfig{AllowSelfInstrumentation: true}},
				beylaPID: pid,
			},
			isSelf: false,
			test:   "Beyla pid, allow self instrumentation",
		},
	} {
		t.Run(tt.test, func(t *testing.T) {
			i := ebpf.Instrumentable{FileInfo: &exec.FileInfo{Pid: int32(pid)}}

			assert.Equal(t, tt.isSelf, tt.ta.skipSelfInstrumentation(&i))
		})
	}
}
