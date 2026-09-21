# AWS ECS non-Kubernetes service identity PoC

This PoC tests whether OBI can build a service graph on ECS without Kubernetes
metadata or application-level OpenTelemetry instrumentation.

The original experiment proved that OBI can use the ECS API to translate task
IPs observed by eBPF into ECS service names. The first extension tested two
additional conditions:

- One standalone OBI instance instruments more than one service on the same
  EC2 container instance.
- Services communicate across two ECS clusters in the same VPC.

The extended deployment was run successfully in AWS on 2026-09-21.

A second extension tested an ECS destination with no Beyla or SDK, a private
RDS dependency, and service communication across peered VPCs. It was run
successfully in AWS on 2026-09-21.

## Validated topology

```text
ECS cluster: beyla-nonk8s-poc              ECS cluster: beyla-nonk8s-poc-backend
EC2 host: caller                           EC2 host: checkout
├── standalone OBI                         ├── standalone OBI
├── storefront Go task :8081               └── checkout Flask task :8080
└── catalog Go task :8082 ────────────────────────────────┘
         ▲                    catalog -> checkout
         │
         └── storefront -> catalog
```

All three applications are uninstrumented. They contain no OpenTelemetry SDK,
agent, manual spans, or OTLP exporter. Standalone OBI discovers and instruments
their running processes with eBPF.

The tasks use `awsvpc` networking and receive their own ENI addresses. The
applications call the next service by its literal private IP. The topology does
not use Kubernetes, Service Connect, Cloud Map, a load balancer, DNS-based
service discovery, or propagated service metadata.

## Baseline behavior

Released Beyla `v3.35.0` discovers the application processes and observes the
requests. It does not know which ECS service owns a remote IP.

In the original two-service experiment, the server-side graph contained the
caller IP and a generated checkout container name:

```prometheus
traces_service_graph_request_total{
  client="172.31.27.44",
  server="ecs-beyla-nonk8s-poc-checkout-1-checkout-e681e3f28cf3a9ecf401",
  source="beyla"
} 18
```

This confirms that the missing information is endpoint identity. eBPF already
sees the call, protocol, latency, and local process.

## ECS resolver

The OBI PoC adds `ecs` as a name resolver source. Each OBI process:

1. Calls `ListTasks` for every configured ECS cluster.
2. Calls `DescribeTasks` in batches of up to 100 tasks per cluster.
3. Reads the ECS service name from the task group, such as
   `service:checkout`.
4. Reads `privateIPv4Address` from the task ENI attachment.
5. Builds one in-memory `IP -> service name` map across the configured clusters.
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
    clusters: [beyla-nonk8s-poc, beyla-nonk8s-poc-backend]
    region: us-east-2
    refresh_interval: 30s
```

The earlier singular `cluster:` option remains supported. The EC2 instance role
provides AWS credentials through IMDS. The resolver needs `ecs:ListTasks` and
`ecs:DescribeTasks` for the configured clusters.

## Proven result from the original experiment

The custom OBI binary was deployed to both EC2 hosts in the original
single-cluster topology. Both hosts independently reported:

```prometheus
traces_service_graph_request_total{
  client="storefront",
  server="checkout",
  source="obi"
}
```

The live ECS inventory used by the resolver was:

```text
172.31.27.44 -> storefront
172.31.23.66 -> checkout
```

## Observed result for the extended test

The caller OBI instance reported both edges with stable ECS service names:

```prometheus
traces_service_graph_request_total{
  client="storefront",
  connection_type="",
  server="catalog",
  source="obi"
} 2721

traces_service_graph_request_total{
  client="storefront",
  connection_type="virtual_node",
  server="catalog",
  source="obi"
} 2721

traces_service_graph_request_total{
  client="catalog",
  connection_type="virtual_node",
  server="checkout",
  source="obi"
} 2721
```

The two `storefront -> catalog` series represent the client and server
observations made by the same OBI instance. They agree on both service names.
The backend OBI instance independently reported:

```prometheus
traces_service_graph_request_total{
  client="catalog",
  connection_type="",
  server="checkout",
  source="obi"
} 2883
```

The different counter values reflect the later backend snapshot while traffic
continued. No observed service-graph edge contained a task IP or generated
`ecs-...` container name after the resolver was installed.

This proves that one OBI instance can instrument and distinguish multiple ECS
services on the same EC2 host. It also proves that a combined inventory can
resolve an edge across two ECS clusters in the same VPC.

`target_info` remained unresolved. For example, the caller still exposed
generated service names for both local tasks:

```text
ecs-beyla-nonk8s-poc-storefront-2-storefront-aecef8e5c7d18fd11900
ecs-beyla-nonk8s-poc-catalog-1-catalog-babfa0d2829c97832d00
```

The current resolver decorates spans before service-graph metrics are created.
It does not yet decorate the process metadata used to create `target_info`.

## Observed result for the brownfield test

```text
frontend VPC                         backend/data VPC

storefront :8081 -> catalog :8082 -> checkout :8080
                                         |       |
                                         |       +-> RDS PostgreSQL :5432
                                         +-> legacy-api :8083
```

The second extension ran the custom resolver directly. OBI selected ports 8080
through 8082, so it instruments storefront, catalog, and checkout. The
`legacy-api` ECS task listens on port 8083 and has no SDK. It is absent from
OBI process discovery, but its task ENI remains in ECS inventory.

This separates two facts that were coupled in the earlier test:

- OBI can observe the outgoing HTTP call from checkout without instrumenting
  the destination process.
- The ECS resolver can map the remote task IP to `legacy-api` independently of
  process discovery.

The caller OBI instance resolved the edges across the peered VPCs:

```prometheus
traces_service_graph_request_total{
  client="catalog",
  connection_type="virtual_node",
  server="checkout",
  source="obi"
} 240

traces_service_graph_request_total{
  client="storefront",
  connection_type="",
  server="catalog",
  source="obi"
} 240

traces_service_graph_request_total{
  client="storefront",
  connection_type="virtual_node",
  server="catalog",
  source="obi"
} 240
```

The backend OBI instance resolved the remote `catalog` client and the
uninstrumented `legacy-api` destination:

```prometheus
traces_service_graph_request_total{
  client="catalog",
  connection_type="",
  server="checkout",
  source="obi"
} 61

traces_service_graph_request_total{
  client="checkout",
  connection_type="virtual_node",
  server="legacy-api",
  source="obi"
} 61
```

This proves that ECS inventory can identify a destination even when that
service has no Beyla or SDK instrumentation. The observed outgoing request and
the ECS task ENI are sufficient to produce `checkout -> legacy-api`.

RDS produced a different result:

```prometheus
traces_service_graph_request_total{
  client="checkout",
  connection_type="database",
  server="10.42.10.57",
  source="obi"
} 61
```

OBI identified the database connection, but the ECS resolver left the RDS
server as an IP address because RDS is not part of ECS inventory. Naming this
endpoint requires another metadata adapter, for example one that combines
`DescribeDBInstances` endpoint metadata with DNS resolution.

The two VPCs represent a common split between customer-facing services and a
private backend/data tier. This test checks that service identity follows ECS
inventory across a routed boundary. It also gives us a base for later tests
with load balancers, autoscaling replacements, bridge or host networking, and
mixed ECS and plain EC2 workloads.

## Current limitations

- `target_info` is produced from process discovery before span name resolution.
  It can still contain a generated ECS container name.
- ECS clusters and the AWS region must be supplied in the OBI configuration.
- Each OBI instance queries the combined task inventory. A shared cache may be
  needed for large deployments.
- The resolver currently uses IPv4 task ENIs and ECS service tasks.
- RDS endpoints remain IP addresses because the resolver only reads ECS
  inventory.
- The PoC does not cover bridge or host networking, IPv6, load balancers, mixed
  ECS and plain EC2 services, ECS Service Connect, or Fargate.

## Reproduce the experiment

See [RUNBOOK.md](./RUNBOOK.md) for setup, deployment, verification, and cleanup
instructions.
