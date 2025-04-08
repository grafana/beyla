//go:build beyla_bpf

package bpf

import _ "github.com/grafana/beyla/v2/bpf/bpfcore"
import _ "github.com/grafana/beyla/v2/bpf/common"
import _ "github.com/grafana/beyla/v2/bpf/generictracer"
import _ "github.com/grafana/beyla/v2/bpf/gotracer"
import _ "github.com/grafana/beyla/v2/bpf/gpuevent"
import _ "github.com/grafana/beyla/v2/bpf/httptracer"
import _ "github.com/grafana/beyla/v2/bpf/logger"
import _ "github.com/grafana/beyla/v2/bpf/maps"
import _ "github.com/grafana/beyla/v2/bpf/netolly"
import _ "github.com/grafana/beyla/v2/bpf/pid"
import _ "github.com/grafana/beyla/v2/bpf/rdns"
import _ "github.com/grafana/beyla/v2/bpf/tctracer"
import _ "github.com/grafana/beyla/v2/bpf/watcher"
