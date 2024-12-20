{{/*
Define the default configuration.
*/}}
{{- define "beyla.defaultConfig" }}
{{- if eq .Values.preset "network" }}
network:
  enable: true
{{- end }}
{{- if eq .Values.preset "application" }}
discovery:
  services:
    - k8s_namespace: .
  exclude_services:
    - exe_path: ".*alloy.*|.*otelcol.*|.*beyla.*"
{{- end }}
prometheus_export:
  port: 9090
  path: /metrics
attributes:
  kubernetes:
    enable: true
  select:
    beyla_network_flow_bytes:
      include:
        - 'k8s.src.owner.type'
        - 'k8s.dst.owner.type'
        - 'direction'
filter:
  network:
    k8s_dst_owner_name:
      not_match: '{kube*,*jaeger-agent*,*prometheus*,*promtail*,*grafana-agent*}'
    k8s_src_owner_name:
      not_match: '{kube*,*jaeger-agent*,*prometheus*,*promtail*,*grafana-agent*}'
{{- end }}

{{/*
Merge default configuration with user configuration from values.
*/}}
{{- define "beyla.config" }}
{{- $defaultConfig := fromYaml (include "beyla.defaultConfig" . ) }}
{{- mergeOverwrite $defaultConfig .Values.config.data | default $defaultConfig  | toYaml | nindent 4}}
{{- end }}