# beyla

![Version: 0.2.0](https://img.shields.io/badge/Version-0.2.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 1.4.1](https://img.shields.io/badge/AppVersion-1.4.1-informational?style=flat-square)

eBPF-based autoinstrumentation of HTTP and HTTPS services

## Source Code

* <https://github.com/grafana/beyla>

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{}` | used for scheduling of pods based on affinity rules |
| config.create | bool | `true` | set to true, to use the below default configurations |
| config.data | object | `{"attributes":{"kubernetes":{"enable":true}},"prometheus_export":{"path":"/metrics","port":9090}}` | default value of beyla configuration |
| config.name | string | `""` |  |
| env | object | `{}` | extra environment variables |
| envValueFrom | object | `{}` | extra environment variables to be set from resources such as k8s configMaps/secrets |
| fullnameOverride | string | `""` | Overrides the chart's computed fullname. |
| global.image.pullSecrets | list | `[]` | Optional set of global image pull secrets. |
| global.image.registry | string | `""` | Global image registry to use if it needs to be overridden for some specific use cases (e.g local registries, custom images, ...) |
| image.digest | string | `nil` | Beyla image's SHA256 digest (either in format "sha256:XYZ" or "XYZ"). When set, will override `image.tag`. |
| image.pullPolicy | string | `"IfNotPresent"` | Beyla image pull policy. |
| image.pullSecrets | list | `[]` | Optional set of image pull secrets. |
| image.registry | string | `"docker.io"` | Beyla image registry (defaults to docker.io) |
| image.repository | string | `"grafana/beyla"` | Beyla image repository. |
| image.tag | string | `nil` | Beyla image tag. When empty, the Chart's appVersion is used. |
| nameOverride | string | `""` | Overrides the chart's name |
| namespaceOverride | string | `""` | Override the deployment namespace |
| nodeSelector | object | `{}` | The nodeSelector field allows user to constrain which nodes your DaemonSet pods are scheduled to based on labels on the node |
| podAnnotations | object | `{}` | Adds custom annotations to the Beyla Pods. |
| podLabels | object | `{}` | Adds custom labels to the Beyla Pods. |
| podSecurityContext | object | `{}` |  |
| preset | string | `"application"` | Preconfigures some default properties for network or application observability. Accepted values are "network" or "application". |
| rbac.create | bool | `true` | Whether to create RBAC resources for Belya |
| rbac.extraClusterRoleRules | list | `[]` | Extra custer roles to be created for Belya |
| resources | object | `{}` |  |
| securityContext | object | `{}` |  |
| service.annotations | object | `{}` | Service annotations. |
| service.appProtocol | string | `""` | Adds the appProtocol field to the service. This allows to work with istio protocol selection. Ex: "http" or "tcp" |
| service.clusterIP | string | `""` | cluster IP |
| service.enabled | bool | `false` | whether to create a service for internal metrics |
| service.labels | object | `{}` | Service labels. |
| service.loadBalancerClass | string | `""` | loadbalancer class name |
| service.loadBalancerIP | string | `""` | loadbalancer IP |
| service.loadBalancerSourceRanges | list | `[]` | source ranges for loadbalancer |
| service.port | int | `80` | service port |
| service.portName | string | `"service"` | name of the port for internal metrics service. |
| service.targetPort | int | `9090` | targetPort has to be configured based on the values of `BEYLA_INTERNAL_METRICS_PROMETHEUS_PORT` environment variable or the value of `prometheus_export.port` from beyla configuration file. see more at https://grafana.com/docs/beyla/latest/configure/options/#internal-metrics-reporter |
| service.type | string | `"ClusterIP"` | type of the service |
| serviceAccount.annotations | object | `{}` | Annotations to add to the service account |
| serviceAccount.automount | bool | `true` | Automatically mount a ServiceAccount's API credentials? |
| serviceAccount.create | bool | `true` | Specifies whether a service account should be created |
| serviceAccount.labels | object | `{}` | ServiceAccount labels. |
| serviceAccount.name | string | `""` | The name of the service account to use. If not set and create is true, a name is generated using the fullname template |
| tolerations | list | `[]` | Tolerations allow pods to be scheduled on nodes with specific taints |
| updateStrategy.type | string | `"RollingUpdate"` | update strategy type |
| volumeMounts | list | `[]` | Additional volumeMounts on the output Deployment definition. |
| volumes | list | `[]` | Additional volumes on the output daemonset definition. |

