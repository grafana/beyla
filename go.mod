module github.com/grafana/beyla/v3

go 1.25.11

// opentelemetry-ebpf-instrumentation is not downloaded directly via go mod
// but included as a go submodule
replace go.opentelemetry.io/obi => ./.obi-src

require (
	github.com/caarlos0/env/v9 v9.0.0
	github.com/goccy/go-json v0.10.6
	github.com/google/uuid v1.6.0
	github.com/grafana/pyroscope-go/godeltaprof v0.1.12
	github.com/hashicorp/golang-lru/v2 v2.0.7
	github.com/invopop/jsonschema v0.14.0
	github.com/moby/moby/api v1.55.0
	github.com/moby/moby/client v0.5.1
	github.com/ory/dockertest/v4 v4.0.0
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.24.1
	github.com/prometheus/common v0.71.0
	github.com/prometheus/otlptranslator v1.0.0
	github.com/prometheus/procfs v0.22.0
	github.com/shirou/gopsutil/v3 v3.24.5
	github.com/stretchr/testify v1.12.1
	github.com/vladimirvivien/gexe v0.5.0
	go.opentelemetry.io/collector/component v1.66.0
	go.opentelemetry.io/collector/config/configgrpc v1.66.0
	go.opentelemetry.io/collector/config/confighttp v0.160.0
	go.opentelemetry.io/collector/config/configopaque v1.66.0
	go.opentelemetry.io/collector/config/configoptional v1.66.0
	go.opentelemetry.io/collector/config/configretry v1.66.0
	go.opentelemetry.io/collector/config/configtls v1.66.0
	go.opentelemetry.io/collector/consumer v1.66.0
	go.opentelemetry.io/collector/exporter v1.66.0
	go.opentelemetry.io/collector/exporter/exporterhelper v0.160.0
	go.opentelemetry.io/collector/exporter/otlpexporter v0.160.0
	go.opentelemetry.io/collector/exporter/otlphttpexporter v0.160.0
	go.opentelemetry.io/collector/pdata v1.66.0
	go.opentelemetry.io/obi v0.12.2
	go.opentelemetry.io/otel v1.46.0
	go.opentelemetry.io/otel/sdk v1.46.0
	go.opentelemetry.io/otel/sdk/metric v1.46.0
	go.opentelemetry.io/otel/trace v1.46.0
	go.uber.org/zap v1.28.0
	golang.org/x/mod v0.40.0
	golang.org/x/sync v0.22.0
	golang.org/x/sys v0.47.0
	google.golang.org/grpc v1.83.2
	google.golang.org/protobuf v1.36.12
	gopkg.in/yaml.v3 v3.0.1
	k8s.io/api v0.37.0
	k8s.io/apimachinery v0.37.0
	k8s.io/client-go v0.37.0
	sigs.k8s.io/e2e-framework v0.7.0
)

require (
	cloud.google.com/go/compute/metadata v0.9.0 // indirect
	github.com/AlessandroPomponio/go-gibberish v0.0.0-20191004143433-a2d4156f0396 // indirect
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/detectors/gcp v1.37.0 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/andybalholm/brotli v1.2.3 // indirect
	github.com/aws/aws-sdk-go-v2 v1.45.1 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.33.2 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.20.2 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.19.1 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.5.1 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.8.1 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.5.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.19 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.14.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.8.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.36.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.41.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.48.0 // indirect
	github.com/aws/smithy-go v1.28.1 // indirect
	github.com/bahlo/generic-list-go v0.2.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/buger/jsonparser v1.6.1 // indirect
	github.com/caarlos0/env/v11 v11.4.1 // indirect
	github.com/cenkalti/backoff/v5 v5.0.3 // indirect
	github.com/cenkalti/backoff/v7 v7.0.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cilium/ebpf v0.22.0 // indirect
	github.com/containerd/errdefs v1.0.0 // indirect
	github.com/containerd/errdefs/pkg v0.3.0 // indirect
	github.com/containers/common v0.64.2 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/docker/go-connections v0.8.1 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/ebitengine/purego v0.11.0 // indirect
	github.com/emicklei/go-restful/v3 v3.13.0 // indirect
	github.com/evanphx/json-patch/v5 v5.9.11 // indirect
	github.com/felixge/httpsnoop v1.1.0 // indirect
	github.com/foxboron/go-tpm-keyfiles v0.0.0-20260902202739-8c9c2d1005f4 // indirect
	github.com/fxamacker/cbor/v2 v2.9.3 // indirect
	github.com/gabriel-vasile/mimetype v1.4.15 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/go-openapi/jsonpointer v1.0.0 // indirect
	github.com/go-openapi/jsonreference v1.0.1 // indirect
	github.com/go-openapi/swag v0.29.1 // indirect
	github.com/go-openapi/swag/cmdutils v0.29.1 // indirect
	github.com/go-openapi/swag/conv v0.29.1 // indirect
	github.com/go-openapi/swag/fileutils v0.29.1 // indirect
	github.com/go-openapi/swag/jsonutils v0.29.1 // indirect
	github.com/go-openapi/swag/loading v0.29.1 // indirect
	github.com/go-openapi/swag/mangling v0.29.1 // indirect
	github.com/go-openapi/swag/netutils v0.29.1 // indirect
	github.com/go-openapi/swag/pools v0.29.1 // indirect
	github.com/go-openapi/swag/stringutils v0.29.1 // indirect
	github.com/go-openapi/swag/typeutils v0.29.1 // indirect
	github.com/go-openapi/swag/yamlutils v0.29.1 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-playground/validator/v10 v10.30.3 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/golang/snappy v1.0.0 // indirect
	github.com/google/gnostic-models v0.7.1 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/gorilla/websocket v1.5.4-0.20250319132907-e064f32e3674 // indirect
	github.com/grafana/go-offsets-tracker v0.1.7 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.30.0 // indirect
	github.com/hashicorp/go-version v1.9.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/compress v1.20.0 // indirect
	github.com/klauspost/cpuid/v2 v2.4.0 // indirect
	github.com/knadh/koanf/maps v0.1.3 // indirect
	github.com/knadh/koanf/providers/confmap v1.0.1 // indirect
	github.com/knadh/koanf/v2 v2.3.6 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/leodido/go-urn v1.5.0 // indirect
	github.com/lufia/plan9stats v0.0.0-20260802145828-341c2f0c90b5 // indirect
	github.com/mailru/easyjson v0.9.2 // indirect
	github.com/minio/sha256-simd v1.0.1 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/moby/spdystream v0.5.1 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.3-0.20250322232337-35a7c28c31ee // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/mxk/go-flowrate v0.0.0-20140419014527-cca7078d478f // indirect
	github.com/ohler55/ojg v1.28.5 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	github.com/oschwald/maxminddb-golang/v2 v2.5.0 // indirect
	github.com/pierrec/lz4/v4 v4.1.29 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/power-devops/perfstat v0.0.0-20260805114148-88456608a4f6 // indirect
	github.com/prometheus/client_model v0.6.3 // indirect
	github.com/rs/cors v1.11.1 // indirect
	github.com/shirou/gopsutil/v4 v4.26.8 // indirect
	github.com/shoenig/go-m1cpu v0.2.2 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/tklauser/go-sysconf v0.4.0 // indirect
	github.com/tklauser/numcpus v0.12.0 // indirect
	github.com/vektah/gqlparser/v2 v2.5.37 // indirect
	github.com/vishvananda/netlink v1.3.1 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	github.com/wk8/go-ordered-map/v2 v2.1.8 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/xwb1989/sqlparser v0.0.0-20180606152119-120387863bf2 // indirect
	github.com/yl2chen/cidranger v1.0.2 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	go.mongodb.org/mongo-driver/v2 v2.8.2 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/collector v0.160.0 // indirect
	go.opentelemetry.io/collector/client v1.66.0 // indirect
	go.opentelemetry.io/collector/config/configauth v1.66.0 // indirect
	go.opentelemetry.io/collector/config/configcompression v1.66.0 // indirect
	go.opentelemetry.io/collector/config/configmiddleware v1.66.0 // indirect
	go.opentelemetry.io/collector/config/confignet v1.66.0 // indirect
	go.opentelemetry.io/collector/config/configtelemetry v0.160.0 // indirect
	go.opentelemetry.io/collector/confmap v1.66.0 // indirect
	go.opentelemetry.io/collector/consumer/consumererror v0.160.0 // indirect
	go.opentelemetry.io/collector/consumer/consumererror/xconsumererror v0.160.0 // indirect
	go.opentelemetry.io/collector/consumer/xconsumer v0.160.0 // indirect
	go.opentelemetry.io/collector/exporter/debugexporter v0.160.0 // indirect
	go.opentelemetry.io/collector/exporter/exporterhelper/xexporterhelper v0.160.0 // indirect
	go.opentelemetry.io/collector/exporter/xexporter v0.160.0 // indirect
	go.opentelemetry.io/collector/extension v1.66.0 // indirect
	go.opentelemetry.io/collector/extension/extensionauth v1.66.0 // indirect
	go.opentelemetry.io/collector/extension/extensionmiddleware v0.160.0 // indirect
	go.opentelemetry.io/collector/extension/xextension v0.160.0 // indirect
	go.opentelemetry.io/collector/featuregate v1.66.0 // indirect
	go.opentelemetry.io/collector/internal/componentalias v0.160.0 // indirect
	go.opentelemetry.io/collector/pdata/pprofile v0.160.0 // indirect
	go.opentelemetry.io/collector/pdata/xpdata v0.160.0 // indirect
	go.opentelemetry.io/collector/pipeline v1.66.0 // indirect
	go.opentelemetry.io/collector/pipeline/xpipeline v0.160.0 // indirect
	go.opentelemetry.io/contrib/detectors/aws/ec2/v2 v2.5.3 // indirect
	go.opentelemetry.io/contrib/detectors/aws/eks v1.46.0 // indirect
	go.opentelemetry.io/contrib/detectors/azure/azurevm v0.18.0 // indirect
	go.opentelemetry.io/contrib/detectors/gcp v1.46.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.71.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.71.0 // indirect
	go.opentelemetry.io/ebpf-profiler v0.0.202636 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc v1.46.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp v1.46.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.46.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.46.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.46.0 // indirect
	go.opentelemetry.io/otel/metric v1.46.0 // indirect
	go.opentelemetry.io/proto/otlp v1.11.0 // indirect
	go.opentelemetry.io/proto/otlp/processcontext/v1development v0.4.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.yaml.in/yaml/v2 v2.4.4 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/arch v0.30.0 // indirect
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/oauth2 v0.36.0 // indirect
	golang.org/x/term v0.45.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260803160001-6ac0973c030d // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260803160001-6ac0973c030d // indirect
	gopkg.in/evanphx/json-patch.v4 v4.13.0 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	k8s.io/component-base v0.37.0 // indirect
	k8s.io/klog/v2 v2.140.0 // indirect
	k8s.io/kube-openapi v0.0.0-20260721132016-d427ff9ee9ad // indirect
	k8s.io/utils v0.0.0-20260707023825-cf1189d6abe3 // indirect
	sigs.k8s.io/controller-runtime v0.24.1 // indirect
	sigs.k8s.io/json v0.0.0-20250730193827-2d320260d730 // indirect
	sigs.k8s.io/randfill v1.0.0 // indirect
	sigs.k8s.io/structured-merge-diff/v6 v6.4.2 // indirect
	sigs.k8s.io/yaml v1.6.0 // indirect
)
