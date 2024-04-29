# Contributing to Beyla helm chart

To make sure that the helm docs are properly generated, run this after your changes:

```
docker run --rm --volume "$(pwd):/helm-docs" -u "$(id -u)" jnorwood/helm-docs:v1.13.1
```