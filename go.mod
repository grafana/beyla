module github.com/grafana/beyla/v2

go 1.24.1

// opentelemetry-ebpf-instrumentation is not downloaded directly via go mod
// but included as a go submodule
replace go.opentelemetry.io/obi => ./.obi-src

require (
	github.com/caarlos0/env/v9 v9.0.0
	github.com/gin-gonic/gin v1.10.1
	github.com/goccy/go-json v0.10.5
	github.com/gorilla/mux v1.8.1
	github.com/grafana/pyroscope-go/godeltaprof v0.1.8
	github.com/hashicorp/golang-lru/v2 v2.0.7
	github.com/mariomac/guara v0.0.0-20250408105519-1e4dbdfb7136
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.22.0
	github.com/prometheus/client_model v0.6.2
	github.com/prometheus/common v0.65.0
	github.com/shirou/gopsutil/v3 v3.24.5
	github.com/stretchr/testify v1.10.0
	github.com/vladimirvivien/gexe v0.5.0
	go.opentelemetry.io/collector/consumer v1.34.0
	go.opentelemetry.io/collector/pdata v1.36.1
	go.opentelemetry.io/obi v0.0.0-20250721133745-502110d1c2c1
	go.opentelemetry.io/otel v1.37.0
	go.opentelemetry.io/otel/sdk v1.37.0
	go.opentelemetry.io/otel/sdk/metric v1.37.0
	go.opentelemetry.io/otel/trace v1.37.0
	golang.org/x/net v0.41.0
	golang.org/x/sync v0.16.0
	google.golang.org/grpc v1.73.0
	google.golang.org/protobuf v1.36.6
	gopkg.in/yaml.v3 v3.0.1
	k8s.io/apimachinery v0.29.4
	k8s.io/client-go v0.29.4
	sigs.k8s.io/e2e-framework v0.3.0
)

require (
	cloud.google.com/go/compute/metadata v0.6.0 // indirect
	github.com/AlessandroPomponio/go-gibberish v0.0.0-20191004143433-a2d4156f0396 // indirect
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/detectors/gcp v1.27.0 // indirect
	github.com/aws/aws-sdk-go v1.54.13 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bytedance/sonic v1.11.6 // indirect
	github.com/bytedance/sonic/loader v0.1.1 // indirect
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/cenkalti/backoff/v5 v5.0.2 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cilium/ebpf v0.19.0 // indirect
	github.com/cloudwego/base64x v0.1.4 // indirect
	github.com/cloudwego/iasm v0.2.0 // indirect
	github.com/containers/common v0.64.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/emicklei/go-restful/v3 v3.12.1 // indirect
	github.com/evanphx/json-patch/v5 v5.6.0 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/foxboron/go-tpm-keyfiles v0.0.0-20250323135004-b31fac66206e // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/gabriel-vasile/mimetype v1.4.3 // indirect
	github.com/gavv/monotime v0.0.0-20190418164738-30dba4353424 // indirect
	github.com/gin-contrib/sse v0.1.0 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/go-openapi/jsonpointer v0.21.0 // indirect
	github.com/go-openapi/jsonreference v0.21.0 // indirect
	github.com/go-openapi/swag v0.23.1 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-playground/validator/v10 v10.20.0 // indirect
	github.com/go-viper/mapstructure/v2 v2.3.0 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/golang/snappy v1.0.0 // indirect
	github.com/google/gnostic-models v0.6.8 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/go-tpm v0.9.5 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/grafana/go-offsets-tracker v0.1.7 // indirect
	github.com/grafana/jvmtools v0.0.3 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.25.1 // indirect
	github.com/hashicorp/go-version v1.7.0 // indirect
	github.com/ianlancetaylor/demangle v0.0.0-20250628045327-2d64ad6b7ec5 // indirect
	github.com/imdario/mergo v0.3.15 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/klauspost/cpuid/v2 v2.2.7 // indirect
	github.com/knadh/koanf/maps v0.1.2 // indirect
	github.com/knadh/koanf/providers/confmap v1.0.0 // indirect
	github.com/knadh/koanf/v2 v2.2.0 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/mailru/easyjson v0.9.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/moby/spdystream v0.2.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/mostynb/go-grpc-compression v1.2.3 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/mxk/go-flowrate v0.0.0-20140419014527-cca7078d478f // indirect
	github.com/pelletier/go-toml/v2 v2.2.2 // indirect
	github.com/pierrec/lz4/v4 v4.1.22 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/power-devops/perfstat v0.0.0-20210106213030-5aafc221ea8c // indirect
	github.com/prometheus/procfs v0.17.0 // indirect
	github.com/rs/cors v1.11.1 // indirect
	github.com/shoenig/go-m1cpu v0.1.6 // indirect
	github.com/spf13/pflag v1.0.6 // indirect
	github.com/tklauser/go-sysconf v0.3.12 // indirect
	github.com/tklauser/numcpus v0.6.1 // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	github.com/ugorji/go/codec v1.2.12 // indirect
	github.com/vishvananda/netlink v1.3.1 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	github.com/xwb1989/sqlparser v0.0.0-20180606152119-120387863bf2 // indirect
	github.com/yl2chen/cidranger v1.0.2 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	go.mongodb.org/mongo-driver/v2 v2.2.2 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/collector v0.128.0 // indirect
	go.opentelemetry.io/collector/client v1.34.0 // indirect
	go.opentelemetry.io/collector/component v1.36.1 // indirect
	go.opentelemetry.io/collector/config/configauth v0.128.0 // indirect
	go.opentelemetry.io/collector/config/configcompression v1.34.0 // indirect
	go.opentelemetry.io/collector/config/configgrpc v0.128.0 // indirect
	go.opentelemetry.io/collector/config/confighttp v0.128.0 // indirect
	go.opentelemetry.io/collector/config/configmiddleware v0.128.0 // indirect
	go.opentelemetry.io/collector/config/confignet v1.34.0 // indirect
	go.opentelemetry.io/collector/config/configopaque v1.34.0 // indirect
	go.opentelemetry.io/collector/config/configretry v1.34.0 // indirect
	go.opentelemetry.io/collector/config/configtls v1.34.0 // indirect
	go.opentelemetry.io/collector/confmap v1.34.0 // indirect
	go.opentelemetry.io/collector/consumer/consumererror v0.128.0 // indirect
	go.opentelemetry.io/collector/consumer/consumererror/xconsumererror v0.128.0 // indirect
	go.opentelemetry.io/collector/consumer/xconsumer v0.128.0 // indirect
	go.opentelemetry.io/collector/exporter v0.128.0 // indirect
	go.opentelemetry.io/collector/exporter/exporterhelper/xexporterhelper v0.128.0 // indirect
	go.opentelemetry.io/collector/exporter/otlpexporter v0.128.0 // indirect
	go.opentelemetry.io/collector/exporter/otlphttpexporter v0.128.0 // indirect
	go.opentelemetry.io/collector/exporter/xexporter v0.128.0 // indirect
	go.opentelemetry.io/collector/extension v1.34.0 // indirect
	go.opentelemetry.io/collector/extension/extensionauth v1.34.0 // indirect
	go.opentelemetry.io/collector/extension/extensionmiddleware v0.128.0 // indirect
	go.opentelemetry.io/collector/extension/xextension v0.128.0 // indirect
	go.opentelemetry.io/collector/featuregate v1.36.1 // indirect
	go.opentelemetry.io/collector/internal/telemetry v0.130.1 // indirect
	go.opentelemetry.io/collector/pdata/pprofile v0.128.0 // indirect
	go.opentelemetry.io/collector/pipeline v0.130.1 // indirect
	go.opentelemetry.io/collector/pipeline/xpipeline v0.128.0 // indirect
	go.opentelemetry.io/contrib/bridges/otelzap v0.12.0 // indirect
	go.opentelemetry.io/contrib/detectors/aws/ec2 v1.28.0 // indirect
	go.opentelemetry.io/contrib/detectors/aws/eks v1.28.0 // indirect
	go.opentelemetry.io/contrib/detectors/azure/azurevm v0.0.1 // indirect
	go.opentelemetry.io/contrib/detectors/gcp v1.35.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.61.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.61.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc v1.34.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp v1.34.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.34.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.34.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.34.0 // indirect
	go.opentelemetry.io/otel/log v0.13.0 // indirect
	go.opentelemetry.io/otel/metric v1.37.0 // indirect
	go.opentelemetry.io/proto/otlp v1.5.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	go.yaml.in/yaml/v2 v2.4.2 // indirect
	go.yaml.in/yaml/v3 v3.0.3 // indirect
	golang.org/x/arch v0.18.0 // indirect
	golang.org/x/crypto v0.40.0 // indirect
	golang.org/x/mod v0.25.0 // indirect
	golang.org/x/oauth2 v0.30.0 // indirect
	golang.org/x/sys v0.34.0 // indirect
	golang.org/x/term v0.33.0 // indirect
	golang.org/x/text v0.27.0 // indirect
	golang.org/x/time v0.5.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20250324211829-b45e905df463 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250519155744-55703ea1f237 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	k8s.io/api v0.29.4 // indirect
	k8s.io/klog/v2 v2.130.1 // indirect
	k8s.io/kube-openapi v0.0.0-20240620174524-b456828f718b // indirect
	k8s.io/utils v0.0.0-20240502163921-fe8a2dddb1d0 // indirect
	sigs.k8s.io/controller-runtime v0.15.1 // indirect
	sigs.k8s.io/json v0.0.0-20221116044647-bc3834ca7abd // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.4.1 // indirect
	sigs.k8s.io/yaml v1.5.0 // indirect
)
