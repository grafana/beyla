module github.com/grafana/beyla

go 1.22

require (
	github.com/AlessandroPomponio/go-gibberish v0.0.0-20191004143433-a2d4156f0396
	github.com/caarlos0/env/v9 v9.0.0
	github.com/cilium/ebpf v0.16.0
	github.com/gavv/monotime v0.0.0-20190418164738-30dba4353424
	github.com/gin-gonic/gin v1.9.1
	github.com/go-logr/logr v1.4.2
	github.com/gobwas/glob v0.2.3
	github.com/goccy/go-json v0.10.2
	github.com/google/uuid v1.6.0
	github.com/gorilla/mux v1.8.1
	github.com/grafana/go-offsets-tracker v0.1.7
	github.com/hashicorp/golang-lru/v2 v2.0.7
	github.com/mariomac/guara v0.0.0-20230621100729-42bd7716e524
	github.com/mariomac/pipes v0.10.0
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.20.1
	github.com/prometheus/client_model v0.6.1
	github.com/prometheus/common v0.55.0
	github.com/prometheus/procfs v0.15.1
	github.com/shirou/gopsutil/v3 v3.24.4
	github.com/stretchr/testify v1.9.0
	github.com/vishvananda/netlink v1.1.0
	github.com/vladimirvivien/gexe v0.2.0
	github.com/xwb1989/sqlparser v0.0.0-20180606152119-120387863bf2
	github.com/yl2chen/cidranger v1.0.2
	go.opentelemetry.io/collector/component v0.108.1
	go.opentelemetry.io/collector/config/configgrpc v0.108.1
	go.opentelemetry.io/collector/config/confighttp v0.108.1
	go.opentelemetry.io/collector/config/configopaque v1.14.1
	go.opentelemetry.io/collector/config/configretry v1.14.1
	go.opentelemetry.io/collector/config/configtelemetry v0.108.1
	go.opentelemetry.io/collector/config/configtls v1.14.1
	go.opentelemetry.io/collector/consumer v0.108.1
	go.opentelemetry.io/collector/exporter v0.108.1
	go.opentelemetry.io/collector/exporter/otlpexporter v0.108.1
	go.opentelemetry.io/collector/exporter/otlphttpexporter v0.108.1
	go.opentelemetry.io/collector/pdata v1.14.1
	go.opentelemetry.io/contrib/detectors/aws/ec2 v1.28.0
	go.opentelemetry.io/contrib/detectors/aws/eks v1.28.0
	go.opentelemetry.io/contrib/detectors/azure/azurevm v0.0.1
	go.opentelemetry.io/contrib/detectors/gcp v1.28.0
	go.opentelemetry.io/otel v1.28.0
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc v1.28.0
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp v1.28.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.28.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.28.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.28.0
	go.opentelemetry.io/otel/metric v1.28.0
	go.opentelemetry.io/otel/sdk v1.28.0
	go.opentelemetry.io/otel/sdk/metric v1.28.0
	go.opentelemetry.io/otel/trace v1.28.0
	go.uber.org/zap v1.27.0
	golang.org/x/arch v0.7.0
	golang.org/x/mod v0.17.0
	golang.org/x/net v0.28.0
	golang.org/x/sys v0.24.0
	google.golang.org/grpc v1.65.0
	google.golang.org/protobuf v1.34.2
	gopkg.in/yaml.v3 v3.0.1
	k8s.io/api v0.29.4
	k8s.io/apimachinery v0.29.4
	k8s.io/client-go v0.29.4
	sigs.k8s.io/e2e-framework v0.3.0
)

require (
	cloud.google.com/go/compute/metadata v0.4.0 // indirect
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/detectors/gcp v1.24.0 // indirect
	github.com/aws/aws-sdk-go v1.54.13 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bytedance/sonic v1.9.1 // indirect
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/chenzhuoyu/base64x v0.0.0-20221115062448-fe3a3abad311 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/emicklei/go-restful/v3 v3.12.1 // indirect
	github.com/evanphx/json-patch v4.12.0+incompatible // indirect
	github.com/evanphx/json-patch/v5 v5.6.0 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/fsnotify/fsnotify v1.7.0 // indirect
	github.com/gabriel-vasile/mimetype v1.4.2 // indirect
	github.com/gin-contrib/sse v0.1.0 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/go-openapi/jsonpointer v0.21.0 // indirect
	github.com/go-openapi/jsonreference v0.21.0 // indirect
	github.com/go-openapi/swag v0.23.0 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-playground/validator/v10 v10.14.0 // indirect
	github.com/go-viper/mapstructure/v2 v2.1.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/gnostic-models v0.6.8 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/gorilla/websocket v1.5.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.20.0 // indirect
	github.com/hashicorp/go-version v1.7.0 // indirect
	github.com/imdario/mergo v0.3.15 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/compress v1.17.9 // indirect
	github.com/klauspost/cpuid/v2 v2.2.4 // indirect
	github.com/knadh/koanf/maps v0.1.1 // indirect
	github.com/knadh/koanf/providers/confmap v0.1.0 // indirect
	github.com/knadh/koanf/v2 v2.1.1 // indirect
	github.com/leodido/go-urn v1.2.4 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/moby/spdystream v0.2.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/mostynb/go-grpc-compression v1.2.3 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/mxk/go-flowrate v0.0.0-20140419014527-cca7078d478f // indirect
	github.com/pelletier/go-toml/v2 v2.0.8 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/power-devops/perfstat v0.0.0-20210106213030-5aafc221ea8c // indirect
	github.com/rs/cors v1.11.0 // indirect
	github.com/shoenig/go-m1cpu v0.1.6 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/tklauser/go-sysconf v0.3.13 // indirect
	github.com/tklauser/numcpus v0.7.0 // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	github.com/ugorji/go/codec v1.2.11 // indirect
	github.com/vishvananda/netns v0.0.0-20191106174202-0a2b9b5464df // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	go.opentelemetry.io/collector v0.108.1 // indirect
	go.opentelemetry.io/collector/client v1.14.1 // indirect
	go.opentelemetry.io/collector/config/configauth v0.108.1 // indirect
	go.opentelemetry.io/collector/config/configcompression v1.14.1 // indirect
	go.opentelemetry.io/collector/config/confignet v0.108.1 // indirect
	go.opentelemetry.io/collector/config/internal v0.108.1 // indirect
	go.opentelemetry.io/collector/confmap v1.14.1 // indirect
	go.opentelemetry.io/collector/consumer/consumerprofiles v0.108.1 // indirect
	go.opentelemetry.io/collector/extension v0.108.1 // indirect
	go.opentelemetry.io/collector/extension/auth v0.108.1 // indirect
	go.opentelemetry.io/collector/featuregate v1.14.1 // indirect
	go.opentelemetry.io/collector/pdata/pprofile v0.108.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.53.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.53.0 // indirect
	go.opentelemetry.io/proto/otlp v1.3.1 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.26.0 // indirect
	golang.org/x/exp v0.0.0-20230224173230-c95f2b4c22f2 // indirect
	golang.org/x/oauth2 v0.21.0 // indirect
	golang.org/x/term v0.23.0 // indirect
	golang.org/x/text v0.17.0 // indirect
	golang.org/x/time v0.5.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20240701130421-f6361c86f094 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240701130421-f6361c86f094 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	k8s.io/klog/v2 v2.130.1 // indirect
	k8s.io/kube-openapi v0.0.0-20240620174524-b456828f718b // indirect
	k8s.io/utils v0.0.0-20240502163921-fe8a2dddb1d0 // indirect
	sigs.k8s.io/controller-runtime v0.15.1 // indirect
	sigs.k8s.io/json v0.0.0-20221116044647-bc3834ca7abd // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.4.1 // indirect
	sigs.k8s.io/yaml v1.4.0 // indirect
)
