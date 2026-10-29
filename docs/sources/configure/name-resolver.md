---
title: Configure Beyla host name resolution
menuTitle: Name Resolver
description: Configure Beyla service host and peer name resolution
weight: 31
keywords:
  - Beyla
  - eBPF
---

# Configure Beyla service host and peer name resolution

Since Beyla instruments at the protocol level, it doesn't have access to programming language/framework information about host and peer names. Instead, Beyla has access to the IP addresses used for the communication between the services which are monitored. Therefore Beyla sources this information from metadata services, such as the Kubernetes API, or from information found in protocol headers, for example HTTP's Host header value.

## Name resolution configuration

YAML section: `name_resolver`

| YAML<p>environment variable</p>               | Description                                                                                               | Type    | Default |
| --------------------------------------------- | --------------------------------------------------------------------------------------------------------- | ------- | ------- |
| `sources`<p>`BEYLA_NAME_RESOLVER_SOURCES`</p> | A comma separated list of metadata sources to use for name resolution. More details below.                | list of strings    | ["k8s", "rdns"] |
| `cache_len`<p>`BEYLA_NAME_RESOLVER_CACHE_LEN`</p> | Size of the service name cache. Used to speed up reverse IP lookups.                | int    | (1024) |
| `cache_expiry`<p>`BEYLA_NAME_RESOLVER_CACHE_TTL`</p> | Time-to-live value for the service name cache.                | string    | "5m" |

The possible values for the name resolver sources are: 

- `k8s`. Use Kubernetes API metadata for reverse IP address lookup.
- `dns`. Use the host DNS for reverse IP address lookup. This option can cause flood of DNS requests in certain situations and should be used only on services that are not exposed to the Internet.
- `rdns`. Beyla tracks DNS requests for instrumentation purposes. This option uses that information to build internal cache of DNS resolved names.
- `ecs`. Resolve ECS task IP addresses through the ECS inventory. Requires detected ECS metadata and AWS credentials with `ecs:ListTasks` and `ecs:DescribeTasks` permissions.
- `route53`. Resolve IP addresses from configured Route53 hosted zones. Requires detected EC2 metadata and `route53:ListResourceRecordSets` permission for those zones.

- `gce`. Resolve Compute Engine VM addresses to managed instance group names. Requires detected GCE metadata and read access to the Compute Engine inventory.
- `azure`. Resolve Azure VM addresses to scale-set names. Requires detected Azure VM metadata and read access to VM, scale-set, and network-interface inventories.

Setting `sources` replaces the default `["k8s", "rdns"]` list. Include those entries explicitly if you want to keep them alongside cloud sources. ECS names take precedence over Route53 names for the same IP.

## Cloud metadata configuration

YAML section: `cloud_metadata`

| YAML option<p>Environment variable</p> | Description | Type | Default |
| --- | --- | --- | --- |
| `cluster_name`<p>`BEYLA_CLUSTER_NAME`</p> | Override the detected cloud cluster name, used to select the ECS cluster. | string | Detected |
| `region`<p>`BEYLA_CLOUD_REGION`</p> | Override the detected cloud region. | string | Detected |
| `refresh_interval`<p>`BEYLA_CLOUD_META_REFRESH_INTERVAL`</p> | Cloud inventory refresh interval. Must be greater than `0`. | Duration | `30s` |
| `route53.hosted_zone_ids`<p>`BEYLA_NAME_RESOLVER_ROUTE53_HOSTED_ZONE_IDS`</p> | Hosted zones to query. Required when `route53` is enabled. Environment values are comma-separated. | list of strings | `[]` |
| `route53.refresh_interval`<p>`BEYLA_NAME_RESOLVER_ROUTE53_REFRESH_INTERVAL`</p> | Independent Route53 polling interval. Must be greater than `0`. | Duration | `5m` |

For an ECS deployment:

```yaml
name_resolver:
  sources: ["k8s", "rdns", "ecs"]
cloud_metadata:
  cluster_name: production
  region: eu-central-1
  refresh_interval: 30s
```

The cluster and region overrides supply missing inventory scope or replace detected values. Cloud sources also require the corresponding cloud environment to be detected; setting an override alone does not activate a source.

For Route53:

```yaml
name_resolver:
  sources: ["k8s", "rdns", "route53"]
cloud_metadata:
  region: eu-central-1
  route53:
    hosted_zone_ids: ["Z0123456789EXAMPLE"]
    refresh_interval: 5m
```

Beyla reads A and AAAA records containing IP addresses from the specified zones. Names use lowercase and exported without the trailing dot. Alias records, CNAME records, and wildcard names are skipped. Choose zones that describe the services you want Beyla to resolve.

Route53 polling uses its own refresh interval, with jitter to spread requests and backoff when AWS throttles the client.

## Google Cloud and Azure discovery scopes

Beyla exposes provider scope settings under `name_resolver`. Empty values use the scope detected from cloud metadata.

| YAML option<p>Environment variable</p> | Description | Type | Default |
| --- | --- | --- | --- |
| `gce.project_id`<p>`BEYLA_NAME_RESOLVER_GCE_PROJECT_ID`</p> | Compute Engine project to query. | string | Detected |
| `gce.zone`<p>`BEYLA_NAME_RESOLVER_GCE_ZONE`</p> | Zone containing the managed instance groups. | string | Detected |
| `gce.endpoint`<p>`BEYLA_NAME_RESOLVER_GCE_ENDPOINT`</p> | Compute API base URL override for a proxy or emulator. | URL | Google Compute API |
| `azure.subscription_id`<p>`BEYLA_NAME_RESOLVER_AZURE_SUBSCRIPTION_ID`</p> | Azure subscription to query. | string | Detected |
| `azure.resource_group`<p>`BEYLA_NAME_RESOLVER_AZURE_RESOURCE_GROUP`</p> | Resource group containing the scale sets. | string | Detected |

For example, resolve GCE managed instance groups:

```yaml
name_resolver:
  sources: ["k8s", "rdns", "gce"]
  gce:
    project_id: production-project
    zone: europe-west3-a
```

The Google client uses application default credentials. The Compute Viewer role provides read access to the inventory. Scope discovery covers managed instance groups in the configured zone.

For Azure scale sets:

```yaml
name_resolver:
  sources: ["k8s", "rdns", "azure"]
  azure:
    subscription_id: "00000000-0000-0000-0000-000000000000"
    resource_group: production
```

The Azure client uses the default Azure credential chain. The Reader role at the relevant scope provides the required read access. Both Uniform and Flexible scale sets are supported. The cloud inventory refresh interval is controlled by `cloud_metadata.refresh_interval`.
