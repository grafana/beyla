---
title: Configure Beyla language specific agents
menuTitle: Language specific agents
description: Configure the options related to Beyla's use of language specific agents
weight: 33
keywords:
  - Beyla
  - eBPF
---

# Language specific agents

Certain programming languages that Beyla instruments are using `managed runtimes` with complicated threading models, such that Beyla cannot perform correct thread context propagation solely by using eBPF based techniques. In certain situations, for example Java, capturing TLS traffic is also not possible by eBPF techniques, because the Java SDK has its own TLS implementation written in Java. A lot of these programming languages start program execution with interpreters, but later perform method or execution trace compilation using Just-In-Time(JIT) compilers, which generate code in anonymous memory regions. These anonymous regions cannot be attached to with eBPF uprobes, because there is no Linux `inode` number associated with them. Therefore, it's not possible to perform eBPF instrumentation on the generated code, without potentially unstable techniques of stopping the program with `ptrace` and remapping the anonymous regions to memory mapped files.

Because of the inherent limitation of certain programming languages and technologies, Beyla dynamically injects tiny language specific agents for certain languages, to be able to perform TLS traffic capture and context propagation. Currently, Beyla uses language agents for `Java` and `NodeJS`.

YAML section: `nodejs`

| YAML option<p>Environment variable</p>                    | Description                                                   | Type    | Default |
| --------------------------------------------------------- | ------------------------------------------------------------- | ------- | ------- |
| `enabled`<p>`BEYLA_NODEJS_ENABLED`</p> | Inject the Node.js agent for context propagation, runtime metrics, and manual spans. | boolean | `true` |
| `manual_spans`<p>`BEYLA_NODEJS_MANUAL_SPANS`</p> | Capture spans created through the OpenTelemetry API when no SDK is registered. Requires agent injection and Node.js 14 or later. | boolean | `false` |

Beyla injects the Node.js agent through the inspector interface. It connects to `127.0.0.1:9229`, opening the inspector with `SIGUSR1` when necessary. Injection is skipped if the signal would terminate the process or if Beyla detects a custom `SIGUSR1` handler. Set `enabled` to `false` if your application uses that signal.

Node.js uses `libssl` for TLS traffic, which Beyla captures with eBPF. The agent provides context propagation and runtime metrics. Disabling injection also disables those agent features.

Set `manual_spans` to `true` to capture spans that the application creates with the OpenTelemetry API before registering an SDK:

```yaml
nodejs:
  enabled: true
  manual_spans: true
```

The manual-span bridge requires Node.js 14 or later. Enabling it on an older runtime causes Beyla to skip the entire Node.js agent, including context propagation and runtime metric collection. The bridge stays inactive when an SDK is already registered. If the application registers an SDK later, the bridge yields to it.

YAML section: `javaagent`

| YAML option<p>Environment variable</p>                    | Description                                                   | Type    | Default |
| --------------------------------------------------------- | ------------------------------------------------------------- | ------- | ------- |
| `enabled`<p>`BEYLA_JAVAAGENT_ENABLED`</p>                 | Enable dynamic injection of the Java agent.                   | boolean | (true)  |
| `attach_timeout`<p>`BEYLA_JAVAAGENT_ATTACH_TIMEOUT`</p>   | Timeout for waiting on dynamic attach to succeed.             | string  | "10s"   |

The `Java` agent is used for both context propagation and for TLS traffic capture. The dynamic injection of the agent is supported for `OpenJDK Hotspot` JVM (and derivatives) and for `OpenJ9`. Minimum `Java` version supported is `Java 8`. If the JVM is busy during the agent attach process, the attach process may take longer than 10 seconds. You can use the `attach_timeout` option to increase the time Beyla waits for the dynamic attach to successfully complete.

Injection of the `Java` agent requires that the target process has writeable file system, for example, the injection process doesn't work for containers with read-only file systems.
