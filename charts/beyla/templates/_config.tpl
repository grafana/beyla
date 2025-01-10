{{/*
Define the default configuration for discovery configuration.
*/}}
{{- define "beyla.discoveryDefault" }}
services:
  - k8s_namespace: .
{{- end }}

{{/*
Define the default exclusion for discovery configuration.
*/}}
{{- define "beyla.discoveryDefaultExclude" }}
exclude_services:
  - exe_path: ".*alloy.*|.*otelcol.*|.*beyla.*"
{{- end }}

{{/*
Define the discovery configuration.
*/}}
{{- define "beyla.discoveryConfig" }}
{{- $defaultDiscovery := fromYaml (include "beyla.discoveryDefault" . ) }}
{{- $defaultExclude := fromYaml (include "beyla.discoveryDefaultExclude" . )}}
{{- if not .Values.config.data.discovery }}
  {{- if .Values.config.discoveryExcludeDefault }}
    {{- mergeOverwrite $defaultDiscovery $defaultExclude | toYaml }}
  {{- else }}
    {{- $defaultDiscovery | toYaml }}
  {{- end }}
{{- else if .Values.config.discoveryExcludeDefault }}
  {{- $userDiscovery := .Values.config.data.discovery }}
  {{- merge $userDiscovery $defaultExclude | toYaml }}
{{- else }}
  {{- with .Values.config.data.discovery }}
    {{- toYaml . }}
  {{- end }}
{{- end }}
{{- end }}

{{/*
Define the rest of the configuration.
*/}}
{{- define "beyla.config" }}
{{- $userConfig := .Values.config.data }}
{{- if .Values.config.data.discovery }}
  {{- omit $userConfig "discovery" | toYaml }}
{{- else }}
  {{- $userConfig | toYaml }}
{{- end }}
{{- end }}
