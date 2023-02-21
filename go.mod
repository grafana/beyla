module github.com/grafana/http-autoinstrument

go 1.19

require (
	github.com/cilium/ebpf v0.10.0
	github.com/gavv/monotime v0.0.0-20190418164738-30dba4353424
	github.com/go-logr/logr v1.2.3
	github.com/go-logr/zapr v1.2.2
	github.com/hashicorp/go-version v1.4.0
	github.com/mariomac/ebpf-template v0.0.0-20230208100606-fb7531f6968b
	github.com/mariomac/pipes v0.5.0
	github.com/prometheus/procfs v0.8.0
	go.opentelemetry.io/otel v1.13.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.13.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.13.0
	go.opentelemetry.io/otel/sdk v1.13.0
	go.opentelemetry.io/otel/trace v1.13.0
	go.uber.org/zap v1.20.0
	golang.org/x/arch v0.0.0-20210923205945-b76863e36670
	golang.org/x/exp v0.0.0-20230213192124-5e25df0256eb
)

require (
	github.com/cenkalti/backoff/v4 v4.2.0 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.7.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/internal/retry v1.13.0 // indirect
	go.opentelemetry.io/proto/otlp v0.19.0 // indirect
	go.uber.org/atomic v1.7.0 // indirect
	go.uber.org/multierr v1.6.0 // indirect
	golang.org/x/net v0.4.0 // indirect
	golang.org/x/sys v0.5.0 // indirect
	golang.org/x/text v0.5.0 // indirect
	google.golang.org/genproto v0.0.0-20221118155620-16455021b5e6 // indirect
	google.golang.org/grpc v1.52.3 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
)
