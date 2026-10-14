# Beyla pipeline map

The whole Beyla pipeline is divided in two main connected pipelines. The reason for not having a
single pipeline is that there are plans to split Beyla into two: a finder/instrumenter executable
with high privileges and a reader/decorator executable with lesser privileges.

The dashed boxes are optional stages that will run only under certain conditions/configurations.

Check the in-code documentation for more information about each symbol.

## Application instrumentation pipeline

```mermaid
flowchart TD
    classDef optional stroke-dasharray: 3 3;
    subgraph discovery.Finder pipeline
        PW(ProcessWatcher) --> |new/removed processes| KWE
        KWE(WatcherKubeEnricher):::optional --> |process enriched with k8s metadata| CM
        CM(CriteriaMatcher) --> |processes matching the selection criteria| ET(ExecTyper)
        ET --> |ELFs and its metadata| CU
        CU(ContainerDBUpdater):::optional --> |ELFs and its metadata| TA
        TA(TraceAttacher) -.-> EBPF1(ebpf.Tracer)
        TA -.-> |creates one per executable| EBPF2(ebpf.Tracer)
        TA -.-> EBPF3(ebpf.Tracer)
    end
    subgraph Decoration and forwarding pipeline
        EBPF1 -.-> TR
        EBPF2 -.-> |"[]request.Span"| TR
        EBPF3 -.-> TR
        TR(traces.ReadDecorator) --> ROUT(Routes<br/>decorator)
        ROUT:::optional --> KD(Kubernetes<br/>decorator)
        KD:::optional --> NR
        NR(Name resolver):::optional --> AF
        
        AF(Attributes filter):::optional --> OTELM(OTEL<br/> metrics<br/> exporter):::optional
        AF --> OTELT(OTEL<br/> traces<br/> exporter):::optional
        AF --> PROM(Prometheus<br/>HTTP<br/>endpoint):::optional
        AF --> ALLOY(Alloy<br/>connector):::optional
    end
    CU -.-> |New PIDs| KDB
    KDB(KubeDatabase):::optional <-.- | Aggregated & indexed Pod info | KD
    IF("Informer<br/>(Kube API)"):::optional -.-> |Pods & ReplicaSets status| KDB
    IF -.-> |new Kube objects| KWE
    AF ---> PC
    subgraph process metrics pipeline
        PC("process.Collector"):::optional --> POTEL
        PC --> PPROM
        POTEL("OTEL exporter"):::optional
        PPROM("Prometheus exporter"):::optional
    end
```

## Network metrics pipeline

```mermaid
flowchart TD
    classDef optional stroke-dasharray: 3 3;
    MT(eBPF<br/>Map Tracer) --> PF
    RT(eBPF<br/>Ringbuf Tracer) --> PF
    PF(Internet<br/>protocol filter):::optional --> DD
    DD(Flow Deduper):::optional --> K8S
    KIN(Kube informer):::optional --> KDB
    KDB(Kube Database):::optional --> K8S
    K8S(Kubernetes<br/>decorator):::optional --> RDNS
    RDNS(Reverse DNS):::optional --> CIDRS
    CIDRS(CIDRs<br/>redecorator):::optional --> FLTR
    FLTR(Attributes<br/>filter):::optional --> OTEL(OpenTelemetry<br/>metrics<br/>export):::optional
    FLTR --> PROM(Prometheus<br/>metrics<br/>export):::optional
```