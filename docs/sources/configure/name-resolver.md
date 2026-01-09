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
| `sources`<p>`BEYLA_NAME_RESOLVER_SOURCES`</p> | A comma separated list of metadata sources to use for name resolution. More details below.                | list of strings    | ["k8s"] |
| `cache_len`<p>`BEYLA_NAME_RESOLVER_CACHE_LEN`</p> | Size of the service name cache. Used to speed up reverse IP lookups.                | int    | (1024) |
| `cache_expiry`<p>`BEYLA_NAME_RESOLVER_CACHE_TTL`</p> | Time-to-live value for the service name cache.                | string    | "5m" |

The possible values for the name resolver sources are: 

- `k8s`. Use Kubernetes API metadata for reverse IP address lookup.
- `dns`. Use the host DNS for reverse IP address lookup. This option can cause flood of DNS requests in certain situations and should be used only on services that are not exposed to the Internet.
- `rdns`. Beyla tracks DNS requests for instrumentation purposes. This option uses that information to build internal cache of DNS resolved names.