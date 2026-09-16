# AWS ECS non-Kubernetes service identity PoC

This PoC tests whether OBI can build a service graph on ECS without Kubernetes
metadata or application-level OpenTelemetry instrumentation.

The result is positive for ECS tasks that use `awsvpc` networking. OBI can use
the ECS API to translate the task IPs observed by eBPF into ECS service names.
The resulting service graph reports `storefront -> checkout` instead of an IP
address and a generated container name.

## Test topology

```text
EC2 host: caller                         EC2 host: checkout
├── standalone OBI                      ├── standalone OBI
└── storefront Go task :8081 ──────────>└── checkout Flask task :8080
            172.31.27.44                           172.31.23.66
```

Both applications are uninstrumented. They contain no OpenTelemetry SDK,
agent, manual spans, or OTLP exporter. Standalone OBI discovers and instruments
their running processes with eBPF.

The services run as separate ECS services on separate EC2 container instances.
The tasks use `awsvpc` networking and receive their own ENI addresses. The
storefront calls the checkout task by its literal private IP. The topology does
not use Kubernetes, Service Connect, Cloud Map, a load balancer, DNS-based
service discovery, or propagated service metadata.

## Baseline behavior

Released Beyla `v3.35.0` discovered both application processes and observed the
request between them. It did not know which ECS service owned the remote IP.

The server-side service graph used the caller IP and a generated checkout
container name:

```prometheus
traces_service_graph_request_total{
  client="172.31.27.44",
  server="ecs-beyla-nonk8s-poc-checkout-1-checkout-e681e3f28cf3a9ecf401",
  source="beyla"
} 18
```

This confirms the missing information is endpoint identity. eBPF already sees
the call, protocol, latency, and local process. It needs a source that maps the
observed IP to the platform service.

## ECS resolver

The OBI PoC adds `ecs` as a name resolver source. Each OBI process:

1. Calls `ListTasks` for running tasks in the configured ECS cluster.
2. Calls `DescribeTasks` in batches of up to 100 tasks.
3. Reads the ECS service name from the task group, such as
   `service:checkout`.
4. Reads `privateIPv4Address` from the task ENI attachment.
5. Builds an in-memory `IP -> service name` map.
6. Replaces the map every 30 seconds so stopped tasks disappear and replacement
   task addresses are learned.

The resolver updates automatically named local services and resolves remote
span endpoints before application and service graph metrics are recorded. An
explicitly configured service name still takes precedence.

The standalone configuration is:

```yaml
name_resolver:
  sources: [ecs]
  ecs:
    cluster: beyla-nonk8s-poc
    region: us-east-2
    refresh_interval: 30s
```

The EC2 instance role provides AWS credentials through IMDS. The resolver itself
needs `ecs:ListTasks` and `ecs:DescribeTasks`.

The resolver implementation currently lives in the OBI worktree and branch
`ecs-service-resolution`. The Terraform stack, applications, configuration,
and deployment helper live in this directory.

## Observed result

The custom OBI binary was deployed to both EC2 hosts. Both hosts independently
reported the expected edge.

Caller-side metric:

```prometheus
traces_service_graph_request_total{
  client="storefront",
  client_service_namespace="",
  connection_type="virtual_node",
  server="checkout",
  server_service_namespace="",
  source="obi"
} 949
```

Server-side metric:

```prometheus
traces_service_graph_request_total{
  client="storefront",
  client_service_namespace="",
  connection_type="",
  server="checkout",
  server_service_namespace="",
  source="obi"
} 858
```

The counters differ because each OBI instance started and scraped at a different
time. The client and server labels agree on the service identities.

The live ECS inventory used by the resolver was:

```text
172.31.27.44 -> storefront
172.31.23.66 -> checkout
```

## What this proves

- OBI can observe calls between uninstrumented services on separate ECS/EC2
  hosts.
- ECS control-plane metadata is sufficient to translate an observed task IP
  into an ECS service name when tasks use `awsvpc` networking.
- The same mapping resolves the local auto-generated service name and the
  remote endpoint name.
- Both sides emit a stable `storefront -> checkout` service graph edge.
- The inventory refresh can learn replacement task addresses without restarting
  OBI.

## Current limitations

- `target_info` is produced from process discovery before span name resolution.
  It still contains the generated ECS container name. A process metadata
  decorator is needed to apply the ECS identity there as well.
- This PoC requires the ECS cluster and AWS region in the OBI configuration.
  Automatic cluster and region detection are separate work.
- Each OBI instance currently queries the cluster-wide task inventory. A shared
  cache or a split local/remote lookup design may be needed for large clusters.
- The resolver currently uses IPv4 task ENIs and ECS service tasks. Standalone
  ECS tasks whose group is not `service:<name>` are ignored.
- The PoC does not yet cover bridge or host networking, multiple ECS clusters,
  IPv6, ECS Service Connect, or Fargate.

## Reproduce the experiment

See [RUNBOOK.md](./RUNBOOK.md) for setup, deployment, verification, replacement,
and cleanup instructions.
