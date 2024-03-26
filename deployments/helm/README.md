# beyla

![Version: 0.1.0](https://img.shields.io/badge/Version-0.1.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 1.2.0](https://img.shields.io/badge/AppVersion-1.2.0-informational?style=flat-square)

eBPF-based autoinstrumentation of HTTP and HTTPS services

## Source Code

* <https://github.com/grafana/beyla>

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{}` |  |
| configmapData | string | `nil` |  |
| env | object | `{}` |  |
| envValueFrom | object | `{}` |  |
| fullnameOverride | string | `""` |  |
| image.pullPolicy | string | `"IfNotPresent"` |  |
| image.repository | string | `"grafana/beyla"` |  |
| image.tag | string | `"latest"` |  |
| imagePullSecrets | list | `[]` |  |
| nameOverride | string | `""` |  |
| namespaceOverride | string | `""` |  |
| nodeSelector | object | `{}` |  |
| podSecurityContext | object | `{}` |  |
| rbac.create | bool | `true` |  |
| rbac.extraClusterRoleRules | list | `[]` |  |
| rbac.extraRoleRules | list | `[]` |  |
| rbac.namespaced | bool | `false` |  |
| rbac.pspEnabled | bool | `false` |  |
| rbac.pspUseAppArmor | bool | `false` |  |
| resources | object | `{}` |  |
| securityContext | object | `{}` |  |
| service.annotations | object | `{}` |  |
| service.appProtocol | string | `""` |  |
| service.clusterIP | string | `""` |  |
| service.enabled | bool | `false` |  |
| service.labels | object | `{}` |  |
| service.loadBalancerClass | string | `""` |  |
| service.loadBalancerIP | string | `""` |  |
| service.loadBalancerSourceRanges | list | `[]` |  |
| service.port | int | `80` |  |
| service.portName | string | `"service"` |  |
| service.targetPort | string | `"{{ include \"beyla.internalMetricsPort\" . }}"` |  |
| service.type | string | `"ClusterIP"` |  |
| serviceAccount.annotations | object | `{}` |  |
| serviceAccount.automount | bool | `true` |  |
| serviceAccount.create | bool | `true` |  |
| serviceAccount.labels | object | `{}` |  |
| serviceAccount.name | string | `""` |  |
| tolerations | list | `[]` |  |
| updateStrategy.type | string | `"RollingUpdate"` |  |
| volumeMounts | list | `[]` |  |
| volumes | list | `[]` |  |

