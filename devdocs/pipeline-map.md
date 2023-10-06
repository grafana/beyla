# Beyla pipeline map

The whole Beyla pipeline is divided in two main connected pipelines. The reason for not having a
single pipeline is that there are plans to split Beyla into two: a finder/instrumenter executable
with high privileges and a reader/decorator executable with lesser privileges.

Check the in-code documentation for more information about each symbol.

```mermaid
flowchart TD
    subgraph discovery.Finder pipeline
        W(Watcher) --> |new/removed processes| CM(CriteriaMatcher)
        CM --> |processes matching the selection criteria| ET(ExecTyper)
        ET --> |ELFs and its metadata| TA(TraceAttacher)
        TA -.-> EBPF1(ebpf.Tracer)
        TA -.-> |creates one per executable| EBPF2(ebpf.Tracer)
        TA -.-> EBPF3(ebpf.Tracer)
    end

    subgraph Decoration and forwarding pipeline
        EBPF1 -.-> TR
        EBPF2 -.-> |"[]request.Span"| TR
        EBPF3 -.-> TR
        TR(traces.Reader) --> ROUT(Routes<br/>decorator)
    
        ROUT --> OTELM(OTEL<br/> metrics<br/> exporter)
        ROUT --> OTELT(OTEL<br/> traces<br/> exporter)
        ROUT --> PROM(Prometheus<br/>HTTP<br/>endpoint)
        style ROUT stroke-dasharray: 3 3;
        style OTELM stroke-dasharray: 3 3;
        style OTELT stroke-dasharray: 3 3;
        style PROM stroke-dasharray: 3 3;
    end
```