# Webhook Package

A Kubernetes mutating admission webhook that automatically injects OpenTelemetry instrumentation into pods. This package enables zero-code instrumentation by intercepting pod creation and modifying containers to use OpenTelemetry SDKs.

## Features

- **Automatic Instrumentation**: Injects OpenTelemetry SDK into Java, .NET, and Node.js applications
- **LD_PRELOAD Injection**: Uses shared library preloading for transparent instrumentation
- **Selective Targeting**: Match pods by namespace, labels, or annotations
- **Auto-Restart**: Automatically restarts existing deployments when instrumentation criteria are met
- **Resource Attribution**: Automatically configures service name, namespace, version, and Kubernetes attributes
- **Configurable Sampling**: Supports per-selector sampler configuration with fallback to default
- **Propagator Configuration**: Configure trace context propagators (e.g., W3C, B3)
- **Version Management**: Cleans up old SDK versions automatically

## Architecture

### Core Components

#### Server
The main webhook server that handles TLS setup and HTTP endpoints.

```go
server, err := webhook.NewServer(cfg, ctxInfo)
if err != nil {
    return err
}

err = server.Start(ctx)
```

Endpoints:
- `/mutate` - Handles pod mutation requests
- `/health` - Health check endpoint
- `/readyz` - Readiness check endpoint

#### PodMutator
Handles the actual mutation logic for intercepted pods. It:
- Injects LD_PRELOAD environment variables
- Mounts instrumentation volumes
- Configures OTLP exporters
- Sets resource attributes
- Configures samplers and propagators

#### PodMatcher
Matches pods against selection criteria using:
- Kubernetes metadata (namespace, deployment, etc.)
- Pod labels
- Pod annotations

#### PodBouncer
Restarts existing deployments that need instrumentation by patching their annotations with a restart timestamp.

#### LocalProcessScanner
Scans running processes on the node to:
- Find existing instrumented processes
- Detect programming languages (Java, .NET, Node.js, Python, Ruby)
- Track SDK versions in use

## Usage

### Basic Setup

```go
import (
    "context"
    "github.com/grafana/beyla/v2/pkg/beyla"
    "github.com/grafana/beyla/v2/pkg/webhook"
    "go.opentelemetry.io/obi/pkg/pipe/global"
)

func main() {
    cfg := &beyla.Config{
        Injector: beyla.InjectorConfig{
            Webhook: beyla.WebhookConfig{
                Port:     8443,
                CertPath: "/etc/webhook/certs/tls.crt",
                KeyPath:  "/etc/webhook/certs/tls.key",
                Timeout:  30 * time.Second,
            },
            HostPathVolumeDir: "/opt/otel-instrumentation",
            SDKPkgVersion:     "v1.0.0",
        },
        Traces: beyla.TracesConfig{
            Endpoint: "http://otel-collector:4318",
            Protocol: "http/protobuf",
        },
    }

    ctxInfo := &global.ContextInfo{
        K8sInformer: k8sProvider,
    }

    server, err := webhook.NewServer(cfg, ctxInfo)
    if err != nil {
        log.Fatal(err)
    }

    if err := server.Start(context.Background()); err != nil {
        log.Fatal(err)
    }
}
```

### Configuration Examples

#### Selective Instrumentation by Namespace

```go
cfg.Injector.Instrument = []services.Selector{
    {
        Metadata: map[string]*regexp.Regexp{
            "k8s.namespace.name": regexp.MustCompile("^production$"),
        },
    },
}
```

#### Match by Pod Labels

```go
cfg.Injector.Instrument = []services.Selector{
    {
        PodLabels: map[string]*regexp.Regexp{
            "app.kubernetes.io/name": regexp.MustCompile("^my-app$"),
        },
    },
}
```

#### Match by Deployment Name

```go
cfg.Injector.Instrument = []services.Selector{
    {
        Metadata: map[string]*regexp.Regexp{
            "k8s.deployment.name": regexp.MustCompile("^web-.*"),
        },
    },
}
```

#### Configure Sampling

```go
// Default sampler for all instrumented pods
cfg.Injector.DefaultSampler = &services.SamplerConfig{
    Name: "parentbased_traceidratio",
    Arg:  "0.1", // 10% sampling
}

// Or per-selector sampling
cfg.Injector.Instrument = []services.Selector{
    {
        Metadata: map[string]*regexp.Regexp{
            "k8s.namespace.name": regexp.MustCompile("^production$"),
        },
        SamplerConfig: &services.SamplerConfig{
            Name: "always_on",
        },
    },
}
```

#### Configure Propagators

```go
cfg.Injector.Propagators = []string{"tracecontext", "baggage", "b3"}
```

#### Resource Attributes

```go
cfg.Injector.Resources = beyla.ResourcesConfig{
    // Add custom resource attributes
    Attributes: map[string]string{
        "deployment.environment": "production",
        "team": "backend",
    },

    // Use pod labels for service name/version
    UseLabelsForResourceAttributes: true,

    // Include Kubernetes UID attributes
    AddK8sUIDAttributes: true,
}
```

### Advanced Usage

#### Disable Auto-Restart

Prevent automatic restart of existing deployments:

```go
cfg.Injector.NoAutoRestart = true
```

#### Custom TLS Configuration

The webhook server requires TLS certificates. The server will wait for certificates to be available:

```go
cfg.Injector.Webhook.CertPath = "/custom/path/tls.crt"
cfg.Injector.Webhook.KeyPath = "/custom/path/tls.key"
cfg.Injector.Webhook.Timeout = 60 * time.Second // Wait up to 60s for certs
```

## How It Works

### Injection Flow

1. **Pod Creation**: Kubernetes API server sends pod creation request to the webhook
2. **Matching**: `PodMatcher` checks if the pod matches selection criteria
3. **Mutation**: If matched, `PodMutator` modifies the pod:
   - Adds a hostPath volume mounting the instrumentation directory
   - Injects environment variables:
     - `LD_PRELOAD`: Path to the instrumentation library
     - `OTEL_EXPORTER_OTLP_ENDPOINT`: OTLP endpoint
     - `OTEL_TRACES_SAMPLER`: Sampler configuration
     - `OTEL_PROPAGATORS`: Propagator configuration
     - Resource attribute variables (service name, namespace, etc.)
   - Adds label `com.grafana.beyla/instrumented: <version>`
4. **Response**: Modified pod spec is returned to Kubernetes
5. **Pod Start**: Pod starts with instrumentation injected

### Auto-Restart Flow

When selection criteria are configured:

1. **Initial Scan**: `LocalProcessScanner` finds all running processes on the node
2. **Container Mapping**: Processes are mapped to container IDs
3. **Watch**: Server subscribes to Kubernetes pod events via informer
4. **Evaluation**: For each pod event:
   - Check if process is in a supported language (Java, .NET, Node.js)
   - Check if already instrumented (via label or env var)
   - Check if matches selection criteria
   - Check if has conflicting LD_PRELOAD
5. **Restart**: If instrumentation needed, `PodBouncer` patches the deployment:
   ```
   kubectl patch deployment <name> -n <namespace> \
     -p '{"spec":{"template":{"metadata":{"annotations":{"beyla.grafana.com/restartedAt":"<timestamp>"}}}}}'
   ```

### Language Detection

The scanner detects programming languages by:

1. **Module Maps** (primary): Checks `/proc/<pid>/maps` for:
   - `libcoreclr.so` → .NET
   - `libjvm.so` → Java
   - `/node` or `node` → Node.js
   - `ruby*` → Ruby
   - `python*` → Python

2. **Environment Variables** (fallback): Checks `/proc/<pid>/environ` for:
   - `ASPNET` or `DOTNET` → .NET

### Container Identification

Container information is extracted from `/proc/<pid>/cgroup` using multiple regex patterns to support:
- Docker
- containerd
- CRI-O
- GKE
- EKS
- Other Kubernetes distributions

## Environment Variables Injected

The webhook injects the following environment variables into instrumented containers.

Standard OpenTelemetry environment variables follow the [OTEL SDK Configuration](https://opentelemetry.io/docs/languages/sdk-configuration/general/) specification. Service name, version, and namespace derivation follows the [Kubernetes semantic conventions](https://opentelemetry.io/docs/specs/semconv/non-normative/k8s-attributes/).

| Variable                            | Description                        | Default / Source                                               | OTEL Default                                      | Example                                                        |
|-------------------------------------|------------------------------------|----------------------------------------------------------------|---------------------------------------------------|----------------------------------------------------------------|
| `BEYLA_INJECTOR_SDK_PKG_VERSION`    | SDK version being injected         | From `cfg.Injector.SDKPkgVersion` (required)                   | N/A                                               | `v1.0.0`                                                       |
| `LD_PRELOAD`                        | Path to instrumentation library    | `/__otel_sdk_auto_instrumentation__/injector/libotelinject.so` | N/A                                               | `/__otel_sdk_auto_instrumentation__/injector/libotelinject.so` |
| `OTEL_INJECTOR_CONFIG_FILE`         | Injector configuration file path   | `/__otel_sdk_auto_instrumentation__/injector/otelinject.conf`  | N/A                                               | `/__otel_sdk_auto_instrumentation__/injector/otelinject.conf`  |
| `OTEL_EXPORTER_OTLP_ENDPOINT`       | OTLP exporter endpoint             | From `cfg.Traces.Endpoint` (required)                          | `localhost:4318` (http) / `localhost:4317` (grpc) | `http://otel-collector:4318`                                   |
| `OTEL_EXPORTER_OTLP_PROTOCOL`       | OTLP protocol                      | From `cfg.Traces.Protocol` (required)                          | `http/protobuf`                                   | `http/protobuf`                                                |
| `OTEL_SEMCONV_STABILITY_OPT_IN`     | Semantic convention stability      | `http`                                                         | N/A                                               | `http`                                                         |
| `OTEL_TRACES_SAMPLER`               | Sampler type [1]                   | Not set (OTEL default used)                                    | `parentbased_always_on`                           | `parentbased_traceidratio`                                     |
| `OTEL_TRACES_SAMPLER_ARG`           | Sampler argument [1]               | Not set (unless configured)                                    | N/A                                               | `0.1`                                                          |
| `OTEL_PROPAGATORS`                  | Propagators to use [2]             | Not set (OTEL default used)                                    | `tracecontext,baggage`                            | `tracecontext,baggage,b3`                                      |
| `OTEL_INJECTOR_K8S_NAMESPACE_NAME`  | Pod namespace (from downward API)  | From `metadata.namespace`                                      | N/A                                               | `production`                                                   |
| `OTEL_INJECTOR_K8S_POD_NAME`        | Pod name (from downward API)       | From `metadata.name`                                           | N/A                                               | `my-app-abc123-xyz`                                            |
| `OTEL_INJECTOR_K8S_POD_UID`         | Pod UID (from downward API) [3]    | From `metadata.uid` (if enabled)                               | N/A                                               | `abc-123-def-456`                                              |
| `OTEL_INJECTOR_K8S_CONTAINER_NAME`  | Container name                     | From container spec                                            | N/A                                               | `main`                                                         |
| `OTEL_INJECTOR_SERVICE_NAME`        | Derived service name [4]           | See footnote 4                                                 | `unknown_service`                                 | `my-app`                                                       |
| `OTEL_INJECTOR_SERVICE_VERSION`     | Derived service version [5]        | See footnote 5                                                 | N/A                                               | `1.2.3`                                                        |
| `OTEL_INJECTOR_SERVICE_NAMESPACE`   | Derived service namespace [6]      | See footnote 6                                                 | N/A                                               | `production`                                                   |
| `OTEL_INJECTOR_RESOURCE_ATTRIBUTES` | Additional resource attributes [7] | See footnote 7                                                 | N/A                                               | `k8s.node.name=node-1,...`                                     |

### Configuration Notes

**[1] Sampler Configuration:**
Configured via `cfg.Injector.DefaultSampler` (applies to all) or per-selector via `selector.SamplerConfig` (takes precedence).
See [OTEL SDK Configuration - Sampler](https://opentelemetry.io/docs/languages/sdk-configuration/general/#otel_traces_sampler).

```go
// Default sampler for all
cfg.Injector.DefaultSampler = &services.SamplerConfig{
    Name: "parentbased_traceidratio",  // OTEL_TRACES_SAMPLER
    Arg:  "0.1",                        // OTEL_TRACES_SAMPLER_ARG
}

// Or per-selector (higher priority)
cfg.Injector.Instrument = []services.Selector{
    {
        Metadata: map[string]*regexp.Regexp{
            "k8s.namespace.name": regexp.MustCompile("^production$"),
        },
        SamplerConfig: &services.SamplerConfig{
            Name: "always_on",
        },
    },
}
```

Valid sampler names: `always_on`, `always_off`, `traceidratio`, `parentbased_always_on`, `parentbased_always_off`, `parentbased_traceidratio`.

**[2] Propagators Configuration:**
Configured via `cfg.Injector.Propagators`. Propagators determine how trace context is propagated across process boundaries.
See [OTEL SDK Configuration - Propagators](https://opentelemetry.io/docs/languages/sdk-configuration/general/#otel_propagators).

```go
cfg.Injector.Propagators = []string{"tracecontext", "baggage", "b3"}
```

Valid propagators: `tracecontext`, `baggage`, `b3`, `b3multi`, `jaeger`, `xray`, `ottrace`.

**[3] Kubernetes UID Attributes:**
Pod UID is only set when `cfg.Injector.Resources.AddK8sUIDAttributes = true`.

**[4] Service Name Derivation:**
Follows the [OpenTelemetry Kubernetes semantic conventions](https://opentelemetry.io/docs/specs/semconv/non-normative/k8s-attributes/). Priority order:
1. Annotation: `resource.opentelemetry.io/service.name`
2. Label: `app.kubernetes.io/name` (if `UseLabelsForResourceAttributes` enabled)
3. Label: `app.kubernetes.io/instance` (if `UseLabelsForResourceAttributes` enabled)
4. Deployment name (from `k8s.deployment.name` resource attribute)
5. ReplicaSet name (from `k8s.replicaset.name` resource attribute)
6. StatefulSet name (from `k8s.statefulset.name` resource attribute)
7. DaemonSet name (from `k8s.daemonset.name` resource attribute)
8. CronJob name (from `k8s.cronjob.name` resource attribute)
9. Job name (from `k8s.job.name` resource attribute)
10. Pod name (fallback)

**[5] Service Version Derivation:**
Follows the [OpenTelemetry Kubernetes semantic conventions](https://opentelemetry.io/docs/specs/semconv/non-normative/k8s-attributes/). Priority order:
1. Annotation: `resource.opentelemetry.io/service.version`
2. Label: `app.kubernetes.io/version` (if `UseLabelsForResourceAttributes` enabled)
3. Container image tag (extracted from image reference, e.g., `my-app:1.2.3` → `1.2.3`)
4. Container image digest (if no tag, e.g., `sha256:abc123...`)

**[6] Service Namespace Derivation:**
Follows the [OpenTelemetry Kubernetes semantic conventions](https://opentelemetry.io/docs/specs/semconv/non-normative/k8s-attributes/). Priority order:
1. Annotation: `resource.opentelemetry.io/service.namespace`
2. Kubernetes namespace name (fallback)

**[7] Resource Attributes:**
Additional resource attributes are collected from multiple sources and merged in order (later sources override earlier):
1. Base attributes from `cfg.Injector.Resources.Attributes` (lowest priority)
2. Kubernetes parent owner attributes (e.g., `k8s.deployment.name`, `k8s.replicaset.name`)
3. Node name from downward API (`k8s.node.name`)
4. Service instance ID (formatted as `<namespace>.<pod>.<container>`)
5. Pod annotations prefixed with `resource.opentelemetry.io/` (highest priority)

Example annotation override:
```yaml
metadata:
  annotations:
    resource.opentelemetry.io/deployment.environment: "production"
    resource.opentelemetry.io/team: "backend"
```

Configure via:
```go
cfg.Injector.Resources = beyla.ResourcesConfig{
    Attributes: map[string]string{
        "deployment.environment": "staging",
    },
    UseLabelsForResourceAttributes: true,
    AddK8sUIDAttributes: true,
}
```

## Testing

The package includes comprehensive tests for all components:

```bash
go test ./pkg/webhook/...
```

### Test Coverage

- Server initialization and lifecycle
- Pod mutation logic
- Selector matching
- Process scanning and language detection
- Container info extraction
- Deployment restart logic
- Version cleanup
- Environment variable configuration
- Resource attribute derivation

## Kubernetes Setup

### MutatingWebhookConfiguration

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: beyla-webhook
webhooks:
  - name: mutate.beyla.grafana.com
    clientConfig:
      service:
        name: beyla-webhook
        namespace: beyla-system
        path: "/mutate"
      caBundle: <base64-encoded-ca-cert>
    rules:
      - operations: ["CREATE"]
        apiGroups: [""]
        apiVersions: ["v1"]
        resources: ["pods"]
    admissionReviewVersions: ["v1"]
    sideEffects: None
    timeoutSeconds: 10
```

### Service

```yaml
apiVersion: v1
kind: Service
metadata:
  name: beyla-webhook
  namespace: beyla-system
spec:
  ports:
    - port: 443
      targetPort: 8443
  selector:
    app: beyla-webhook
```

### Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: beyla-webhook
  namespace: beyla-system
spec:
  replicas: 1
  selector:
    matchLabels:
      app: beyla-webhook
  template:
    metadata:
      labels:
        app: beyla-webhook
    spec:
      containers:
      - name: webhook
        image: grafana/beyla:latest
        ports:
        - containerPort: 8443
        volumeMounts:
        - name: webhook-certs
          mountPath: /etc/webhook/certs
          readOnly: true
        - name: instrumentation
          mountPath: /opt/otel-instrumentation
      volumes:
      - name: webhook-certs
        secret:
          secretName: beyla-webhook-certs
      - name: instrumentation
        hostPath:
          path: /opt/otel-instrumentation
          type: DirectoryOrCreate
```

## ArgoCD Integration

When using ArgoCD, add this to prevent double restarts:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: argocd-cm
  namespace: argocd
data:
  resource.customizations.ignoreDifferences.apps_Deployment: |
    jsonPointers:
    - /spec/template/metadata/annotations/beyla.grafana.com~1restartedAt
```

## Supported Languages

The webhook currently supports automatic instrumentation for:

- **Java**: Detected via `libjvm.so`
- **.NET**: Detected via `libcoreclr.so` or `ASPNET`/`DOTNET` environment variables
- **Node.js**: Detected via `node` executable

Note: Ruby and Python are detected but not currently instrumented (can be extended).

## Limitations

- Pods with existing `LD_PRELOAD` are skipped (unless it's from a previous Beyla injection)
- Requires hostPath volume access for instrumentation libraries
- TLS certificates must be available before server starts
- Only supports OTLP export protocol (HTTP or gRPC)

## Troubleshooting

### Pod not being instrumented

Check if the pod matches your selection criteria:

```go
// Enable debug logging
slog.SetLogLoggerLevel(slog.LevelDebug)
```

The matcher will log:
- `metadata does not match`
- `pod label does not match`
- `pod annotation does not match`

### Deployment not restarting

Ensure:
- Selection criteria are configured: `cfg.Injector.Instrument` is not empty
- Auto-restart is not disabled: `cfg.Injector.NoAutoRestart` is false
- The deployment name is correctly detected from pod owners
- The process is in a supported language

### Instrumentation not working

Check:
- LD_PRELOAD path is correct: `/__otel_sdk_auto_instrumentation__/injector/libotelinject.so`
- Volume is mounted correctly
- Instrumentation files exist on the node at `cfg.Injector.HostPathVolumeDir`
- Container has compatible architecture

### TLS issues

The server waits for TLS certificates. If it times out:
- Check certificate paths are correct
- Ensure certificates are valid
- Verify secret is mounted correctly
- Check timeout value: `cfg.Injector.Webhook.Timeout`

## License

See the main Beyla repository for license information.
