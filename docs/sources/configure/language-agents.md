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
| `enabled`<p>`BEYLA_NODEJS_ENABLED`</p>                    | Enable dynamic injection of the `NodeJS` agent.                 | boolean | (true)  |

The `NodeJS` agent provides context propagation and Node.js runtime metrics. It uses the debugger interface for injection. Setting `nodejs.enabled` to `false` also disables Node.js runtime metrics, even when the `application_runtime` feature is enabled. Disable the agent if your program has a handler attached on `SIGUSR1`.

YAML section: `javaagent`

| YAML option<p>Environment variable</p>                    | Description                                                   | Type    | Default |
| --------------------------------------------------------- | ------------------------------------------------------------- | ------- | ------- |
| `enabled`<p>`BEYLA_JAVAAGENT_ENABLED`</p>                 | Enable dynamic injection of the Java agent.                   | boolean | (true)  |
| `attach_timeout`<p>`BEYLA_JAVAAGENT_ATTACH_TIMEOUT`</p>   | Timeout for waiting on dynamic attach to succeed.             | string  | "10s"   |

The `Java` agent provides context propagation, TLS traffic capture, and agent-backed runtime metrics. Setting `javaagent.enabled` to `false` disables garbage collection duration, class, thread, and CPU metrics. HotSpot memory pool metrics remain available because Beyla collects them with eBPF USDT probes.

The dynamic injection of the agent is supported for `OpenJDK Hotspot` JVM (and derivatives) and for `OpenJ9`. Minimum `Java` version supported is `Java 8`. If the JVM is busy during the agent attach process, the attach process may take longer than 10 seconds. You can use the `attach_timeout` option to increase the time Beyla waits for the dynamic attach to successfully complete.

Injection of the `Java` agent requires that the target process has writeable file system, for example, the injection process doesn't work for containers with read-only file systems.
