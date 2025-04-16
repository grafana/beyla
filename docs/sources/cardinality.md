---
title: Beyla metrics cardinality
menuTitle: Metrics cardinality

description: Overview of how to calculate the cardinality of metrics produced by a default Beyla installation, considering the size and complexity of the instrumented environment.

weight: 24
keywords:
  - Beyla
  - eBPF
  - cardinality
---

# Beyla metrics cardinality

The cardinality of [Beyla metrics](../metrics/) highly depends on the size and complexity
of the instrumented environment, so there is no way to provide a simple and accurate formula.

This document tries to provide an approximation of the metrics cardinality that might
be produced by a default Beyla installation. It is divided into several sections for each type of
metric that Beyla can produce, as each metric family can be selectively enabled or disabled.

For simplicity, the formulas below assume a single cluster. You should multiply the cardinality for
each of your clusters.

## Terminology

Before continuing, we should clarify some terms that might be vague or subject to interpretation:

* **Instance**: is each instrumentation target. In application-level metrics, it would be the service or client instance.
  In Kubernetes, it would be a Pod.
  In process-level metrics, each instance is each reported process.
  An application instance might run in multiple processes.
  In network-level metrics, each instance is the Beyla instance that instruments all the network flows in a given host.
* **Instance Owner**: in Kubernetes, most instances (Pods) have an owner resource.
  Sometimes you might prefer to report data about the owners instead of the instances, to keep cardinality under control.
  Examples of instance owners are Deployments, DaemonSets, ReplicaSets, and StatefulSets,
  but if a Pod does not have any owner (standalone Pod), the Pod itself is reported as owner.
* **URL Path**: is the Raw path of a URL request, as sent by the client and received by the Server,
  for example: `/clients/348579843/command/833`.
* **URL Route**: is an aggregated path of a URL request, semantically grouped to keep the cardinality under control.
  It usually mimics the way that some web frameworks let you defining HTTP requests in code,
  for example: `/clients/{clientId}/command/{command_num}`.
* **Operation**: describes what functionality has been requested:
  * HTTP: all HTTP verbs, for example `GET`, followed by the URL route
  * gRPC: the path of the service
  * SQL: SQL commands, for example `SELECT`, `UPDATE` or other commands, followed by the target table
  * Kafka: Produce/Fetch
* **Server**: is any instance that receives and processes HTTP or gRPC requests. A server can be also a client.
* **Client**: is any instance that submits HTTP, gRPC, database or MQ requests. A client can be also a server.
* **Service**: in the Kubernetes context, is functionality provided by a group of servers that are accessed through a common host name and port.
* **Endpoint**: is an IP or hostname and port that identifies either a service, a server, or a client.
* **Return code:** returned by each service invocation, describes some meta-information about how the execution.
  For HTTP they are HTTP status codes, for other protocols it's usually 0 (success) or 1 (error).

## Process-level metrics

Process-level metrics are the simplest metrics to calculate, as processes are not connected between them, and a process
instance belongs to a unique application instance.

Cardinality, according to the default set of enabled attributes in Beyla:

```
#Instances * #Metrics * #AttributeValues
```

* Instances is the number of instrumented process
* Metrics are the number of reported metrics for each process, and AttributeValues are some instance-level attributes that need to multiply each metric instance:
  * `process.cpu.utilization`
    * `cpu.mode={user, system, wait}`
  * `Process.cpu.time`
    * `cpu.mode={user, system, wait}`
  * `Process.memory.usage`
  * `Process.memory.virtual`
  * `process.disk.io`
    * `disk.io.direction={read, write}`
  * `process.network.io`
    * `network.io.direction={receive, transmit}`

Summarizing, the formula to calculate the cardinality of processes is:

```
#ProcessInstances * 12
```

Where `12` is the number of the above enumerated `#Metrics * #AttributeValues`.

<!-- we are referring to Ok as HTTP status but Vale still complains. Disabling it -->
<!-- vale Grafana.OK = NO -->

## Application-level metrics

For application-level metrics, we can't follow a simple multiplication formula as we did for process-level metrics, as
there are multiple factors that influence cardinality, but they aren't linearly related.

For example, both the number of HTTP routes and Server addresses increase the cardinality, but we can't just multiply
them because not all the server instances accept the same HTTP routes.

The following formula could provide an extremely rough maximum limit, but in [our measurements](#case-study-cardinality-of-opentelemetry-demo), the actual
cardinality was 2 orders of magnitude lower than the calculation. For this reason we recommend a
measure-oriented approach rather than trying to calculate cardinality beforehand.

However, here is a list of factors that can influence the overall cardinality:

* **Instances**: the number of instrumented entities. They can be both services and clients.
* **MetricNames**: the number of application-level metric names. This varies depending on the type of applications that
  Beyla instruments. Count one for each metric that is going to be reported.
* Client-side metrics, when Beyla instruments applications that perform requests to other applications:
  * `http.client.request.duration`
  * `http.client.request.body.size`
  * `rpc.client.duration`
  * `sql.client.duration`
  * `redis.client.duration`
  * `messaging.publish.duration`
  * `messaging.process.duration`
* Server-side metrics, when Beyla instruments application that dispatches requests from other applications:
  * `http.server.request.duration`
  * `http.server.request.body.size`
  * `rpc.server.duration`
* **HistogramBuckets** need to be accounted and multiply each metric, as every Application-level metric is an
  histogram. The buckets are configurable in Beyla, but the default number is 15 for duration metrics and 11 for body
  size metrics, plus 2 more metrics (histogram sum and count).
* **Operations** is equivalent to the functionality that is invoked. In HTTP services, it would group the HTTP
  method and the HTTP route, in RPC it is the RPC method name.
* **Endpoints** is the count of server addresses and ports.
* **ReturnCodes** is the number of possible results of the operation. Typically Ok/Err in GRPC, or the HTTP status code.

### Example calculation

Operands in the presented cardinality formula might overlap. For example, an instrumented client application might send `/foo` and `/bar` HTTP requests, and connect
to both services A and B, so:

* Operations: 2
* Endpoints: 2

The `Operations * Endpoints` quotient would multiply cardinality by 4. However if the `/foo` route
is exclusive of service A and the `/bar` route is exclusive of service B, the actual cardinality
multiplier would be only 2.

When you calculate the cardinality, set optimistic and pessimistic bounds for your calculations.

The following example illustrates how to calculate the cardinality of the example system.
Both client and Backend are instrumented by Beyla. The other components are external:

![Example architecture](/media/docs/beyla/cardinality/cardinality_example.png)

The pessimistic calculation would be:

```
#Instances * #MetricNames * #HistoBuckets * #Operations * #Endpoints * #ReturnCodes =
= 2 * 5 * 177/3 * 37/3 =2771
```

The numbers taken as reference:

* 2 instances, client and backend
* 5 metric types, according to their role and protocols:
  * Client
    * `rpc.client.duration`
  * Backend as a RPC server
    * `rpc.server.duration`
  * Backend as an SQL and HTTP client
    * `http.client.request.duration`
    * `http.client.request.body.size`
    * `sql.client.duration`
* 17 histogram metrics, as most metrics are duration-based
* 7 operations: RPC Add/List/Delete, HTTP PUT, SQL Insert/Select/Delete
* 3 endpoints: backend, Identity provider, and DB
* 7 Return codes: RPC OK/Err, HTTP 200/401/500, SQL OK/Err

It might appear that cardinality should not grow beyond 163. However this number is not realistic nor accurate  since some multipliers might not apply to the whole system. For example, SQL methods should not multiply to the RPC and HTTP metrics.

In this simple scenario, we can manually count more the maximum cardinality to 396, which is far less than the initial count of 2771:

| #   | Instance | Metric                          | Endpoint      | Operation  | Code |
| --- | -------- | ------------------------------- | ------------- | ---------- | ---- |
| 1   | Client   | `rpc.client.duration`           | Backend       | Add        | Ok   |
| 2   | Client   | `rpc.client.duration`           | Backend       | Add        | Err  |
| 3   | Client   | `rpc.client.duration`           | Backend       | List       | Ok   |
| 4   | Client   | `rpc.client.duration`           | Backend       | List       | Err  |
| 5   | Client   | `rpc.client.duration`           | Backend       | Delete     | Ok   |
| 6   | Client   | `rpc.client.duration`           | Backend       | Delete     | Err  |
| 7   | Backend  | `rpc.server.duration`           |               | Add        | Ok   |
| 8   | Backend  | `rpc.server.duration`           |               | Add        | Err  |
| 9   | Backend  | `rpc.server.duration`           |               | List       | Ok   |
| 10  | Backend  | `rpc.server.duration`           |               | List       | Err  |
| 11  | Backend  | `rpc.server.duration`           |               | Delete     | Ok   |
| 12  | Backend  | `rpc.server.duration`           |               | Delete     | Err  |
| 13  | Backend  | `http.client.request.duration`  | Identity Prov | PUT /login | 200  |
| 14  | Backend  | `http.client.request.duration`  | Identity Prov | PUT /login | 401  |
| 15  | Backend  | `http.client.request.duration`  | Identity Prov | PUT /login | 500  |
| 16  | Backend  | `http.client.request.body.size` | Identity Prov | PUT /login | 200  |
| 17  | Backend  | `http.client.request.body.size` | Identity Prov | PUT /login | 401  |
| 18  | Backend  | `http.client.request.body.size` | Identity Prov | PUT /login | 500  |
| 19  | Backend  | `sql.client.duration`           | DB            | Insert     | Ok   |
| 20  | Backend  | `sql.client.duration`           | DB            | Insert     | Err  |
| 21  | Backend  | `sql.client.duration`           | DB            | Select     | Ok   |
| 22  | Backend  | `sql.client.duration`           | DB            | Select     | Err  |
| 23  | Backend  | `sql.client.duration`           | DB            | Delete     | Ok   |
| 24  | Backend  | `sql.client.duration`           | DB            | Delete     | Err  |

<!-- vale Grafana.OK = YES -->

For the sake of brevity, we haven't counted the histogram buckets. Next we multiply the metrics instances by the
histogram buckets, plus histogram `_count` and `_sum`:

* 3 body-size metric instances x 13 = 39
* 21 duration metric instances x 17 = 357

Total accounted cardinality: **396**

The above example illustrates that it's difficult to provide one formula to calculate the cardinality impact.
We were able to count the exact cardinality of a very simple example where all information is known.
This exercise would be impossible in a large Kubernetes cluster where we have little or no
information about the applications and how they are interconnected.

## Network-level metrics

It is simpler to calculate network-level metrics than application-level metrics, as Beyla only provides a single Counter:
`beyla.network.flow.bytes`. However the cardinality also depend on how much your applications are interconnected.

The default attributes for `beyla.network.flow.bytes` are:

* Direction (request/response)
* Source and destination endpoint owners in Kubernetes: `k8s_src_owner_name`, `k8s_dst_owner_name`,
  `k8s_src_owner_type`, `k8s_dst_owner_type`, `k8s_src_namespace`, `k8s_dst_namespace`
* `k8s_cluster_name`: unique for each cluster. We assume a single cluster, as for the rest of metrics.

The simplified, pessimistic formula, would be:

```
#Directions * #SourceOwners * #DestinationOwners
```

We've assumed that all the source owners are connected to all the destination owners.
It's more realistic to apply a connection factor, for example a cluster with 100
Deployments/DaemonSets/StatefulSets, where each owner is connected to 2 other owners on average, would have a
cardinality of:

2 directions x 100 SourceOwners x 2 Destination Owners = **400**

## Service Graph metrics

Service Graph metrics are produced for instances
that can be instrumented with Application metrics, for example HTTP, RPC, SQL, Redis, and Kafka.
Network Metrics are produced for any
instance with network traffic, whatever protocol it uses.

Service Graph Metrics produce the following metrics:

* `traces_service_graph_request_client`: histogram with 15 buckets
* `traces_service_graph_request_server`: histogram with 15 buckets
* `traces_service_graph_request_failed_total`: counter
* `traces_service_graph_request_total`: counter

Each metric also has the following attributes:

* `source`: Beyla
* `client` and `client_namespace`
* `server` and `server_namespace`

The calculation is similar to network metrics but with higher cardinality:

* Instead of a single counter metric, we are reporting a set of metrics/histograms with an overall cardinality of 36, two 15+2 histograms + 2 counters.
* Instead of aggregating by the owner of an instance, for example Deployment, the client is the instance that submits a
  request, while the server might be the Owner, as it's usually accessed through a single service instance.

## Span metrics

* `traces_spanmetrics_latency`: histogram with 15 + 2 buckets
* `traces_spanmetrics_calls_total`: counter
* `traces_spanmetrics_size_total`: counter
* `traces_spanmetrics_response_size_total`: counter

Attributes that might add cardinality to each metric are:

* Service/ServiceNamespace/Instance ID
* Span Kind: Client/Server/Internal
* Span Name: usually the name of the operation and might have high cardinality
* Return codes

Maximum cardinality could be roughly calculated as:

```
19 metric buckets * 3 span kinds * #Instances * #Operations * #ReturnCodes
```

As depicted in the [previous example of calculation for application metrics](#example-calculation),
we've made assumptions that the large number of HTTP return codes would only multiply to HTTP services,
or that some groups of instances would have only a subset of the total routes.

## Case study: cardinality of OpenTelemetry Demo

In this section we calculate the cardinality of the
[OpenTelemetry Demo](https://opentelemetry.io/docs/demo/architecture/) deployed in a local cluster of 3 nodes.
We disabled all the bundled OpenTelemetry instrumentation in the example applications,
and deployed Beyla to perform the instrumentation.

### Measure process-level metrics

It's difficult to determine the number of running processes unless you have a deep knowledge of the internals of your applications. We have experimentally measured that the OpenTelemetry demo runs around 140 processes.

Following the formula:

#Instances #Metrics #AttributeValues

Being 12 the sum of all the known process metrics and attribute values, we would analytically expect that the process-level metrics cardinality to be:

```
141 * 12 = 1680
```

Which is pretty close to our measured Cardinality value via PromQL:
`count({__name__=~"process_.*"})`: **~1,600**

### Measure application-level metrics

As most instrumented instances are both client and services, we ignore the #instances argument in the formula to be more accurate:

```
#MetricNames * (#HistoBuckets+2) * #Operations * #Endpoints * #ReturnCodes
```

To minimize the effects of attributes influencing non-linearly in the final cardinality, we calculate cardinality numbers for all the metric types separately (HTTP, gRPC and Kafka).

**Http metrics:**

* 4 metrics: client, server, request size, and time
* 15 histogram buckets on average
* Known operations: 75, measured from a running OTEL Demo with the PromQL query: `group by (http_request_method, http_route)({__name__=~"http_.*"})`
* 26 endpoints, measured from a running OTEL Demo with the PromQL query: `group by (server_address, server_port)({__name__=~"http_.*"})`
* 6 response status codes: 200, 301, 308, 403, 408 and 504, extracted from the running OTEL demo

The total, maximum calculated limit for HTTP metrics is:

```
4 x 15 x 75 x 26 x 6 =~ 702,000
```

This shows how ineffective the formula is for the application-level metrics, as the measured number is much lower, even for all the known application metric types:

`count({__name__=~"http_.*|rpc_.*|sql_.*|redis_.*|messaging_.*"})` **→ 9,600**

### Measure network-level metrics

For network-level metrics, if we assume 2 directions (request/response) and the 21 deployments asking for information to all the 21 deployments, we get the following cardinality numbers:

2×21×21 = 882

Knowing the architecture, we could get a lower estimation if we only count the arrows in the architecture diagram, and assume they are both directions:

2x29 = 58

Network metrics measure the OpenTelemetry Demo connections, other internal cluster connections, and instrumentation traffic, so the real cardinality is higher:

`count(beyla_network_flow_bytes_total)` **→ 330**

We can group traffic between namespaces to get a better idea of which part belongs to the OpenTelemetry demo with the following query:

```
count(beyla_network_flow_bytes_total) by (k8s_src_namespace, k8s_dst_namespace)
```

Which returns the following information:

| k8s_src_namespace | k8s_dst_namespace | count |
| ----------------- | ----------------- | ----- |
| default           | default           | 156   |
| kube-system       | default           | 47    |
| default           | kube-system       | 47    |
|                   | default           | 14    |
| default           |                   | 14    |
|                   | kube-system       | 13    |
| kube-system       |                   | 13    |
|                   | gmp-system        | 3     |
| gmp-system        |                   | 3     |
| default           | gmp-system        | 1     |
| gmp-system        | default           | 1     |

The number of network metrics generated by the OpenTelemetry demo for traffic between the demo components is 156.
The `default` namespace is both the source and destination.
There is other traffic to `kube-system`, `gmp-system`, or no namespace at all, which belongs to external connections, telemetry, or Kubernetes management.

### Measure service graph metrics

Network metrics are often used to build service graphs, but the actual Service graph metrics would have a different shape:

* Instead of a single counter metric, we have 2 counter metrics and 2 more histogram metrics with 16+2 buckets.
* Service Graph metrics usually ignore internal Kubernetes traffic or any traffic from instances that are not instrumented at an application level.

The measured number is:

`count({__name__=~".*service_graph.*"})` **→ 2300**

### Measure span metrics

In the application-level metrics calculation, we demonstrated that trying to get an analytical number was difficult due to the high number of involved parameters.
We can get a correct measurement of the cardinality measuring it with PromQL:

`count({__name__=~".*spanmetrics.*"})` **→ 3900**
