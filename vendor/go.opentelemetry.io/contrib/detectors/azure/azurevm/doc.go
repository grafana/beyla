// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

/*
Package azurevm provides a [resource.Detector] which supports detecting
attributes specific to Azure VMs.

According to semantic conventions for [host], [cloud], and [os] attributes,
each of the following attributes is added if it is available:

  - cloud.provider
  - cloud.platform
  - cloud.region
  - cloud.resource_id
  - host.id
  - host.name
  - host.type
  - os.type
  - os.version

[host]: https://github.com/open-telemetry/semantic-conventions/blob/main/docs/resource/host.md
[cloud]: https://github.com/open-telemetry/semantic-conventions/blob/main/docs/resource/cloud.md
[os]: https://github.com/open-telemetry/semantic-conventions/blob/main/docs/resource/os.md
*/
package azurevm // import "go.opentelemetry.io/contrib/detectors/azure/azurevm"
