---
title: Observe Linux capabilities
menuTitle: Observe Linux capabilities
description: Log each time a process needs a Linux capability.
weight: 85
keywords:
  - Beyla
  - eBPF
  - Capability
---

# Observe Linux capabilities

When Beyla is configured to observe Linux capabilities, it logs a line each time a process uses a capability.

| YAML              | Environment Variable                     | Type   | Default             | Summary                                                      |
| ----------------- | ---------------------------------------- | ------ | ------------------- | ------------------------------------------------------------ |
| `enable`        | `BEYLA_CAPABILITIES_ENABLE`                | boolean   | `false`             | Enables observation of Linux capabilities.          |

Example log line:

```
TODO: Fill this in later
```

Example configuration:

```yaml
capabilities:
  enable: true
```
