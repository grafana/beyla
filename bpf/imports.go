//go:build beyla_bpf

package bpf

import (
	_ "github.com/grafana/beyla/v2/bpf/bpfcore"
	_ "github.com/grafana/beyla/v2/bpf/common"
	_ "github.com/grafana/beyla/v2/bpf/generictracer"
	_ "github.com/grafana/beyla/v2/bpf/gotracer"
	_ "github.com/grafana/beyla/v2/bpf/gpuevent"
	_ "github.com/grafana/beyla/v2/bpf/httptracer"
	_ "github.com/grafana/beyla/v2/bpf/logger"
	_ "github.com/grafana/beyla/v2/bpf/maps"
	_ "github.com/grafana/beyla/v2/bpf/netolly"
	_ "github.com/grafana/beyla/v2/bpf/pid"
	_ "github.com/grafana/beyla/v2/bpf/rdns"
	_ "github.com/grafana/beyla/v2/bpf/tctracer"
	_ "github.com/grafana/beyla/v2/bpf/watcher"
)
