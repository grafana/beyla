# AWS ECS service identity PoC runbook

This runbook extends the validated ECS resolver experiment with a brownfield
topology. It puts frontend and backend services in peered VPCs, leaves one ECS
service outside OBI discovery, and adds a private RDS PostgreSQL instance.

The deployment is prepared but has not yet been run in AWS. The results section
in [README.md](./README.md) separates earlier observations from this test.

## Prerequisites

- Docker
- AWS CLI v2
- AWS Session Manager plugin
- SSH and SCP
- A refreshed `sandbox` SSO profile
- Permission to use EC2, ECS, ECR, IAM, VPC, RDS, Secrets Manager, SSM, and EC2
  Instance Connect

Refresh credentials from the `deployment_tools` checkout:

```bash
./scripts/sso/aws.sh dev
aws sts get-caller-identity --profile sandbox
```

The stack creates one VPC. Confirm that the region has a free VPC slot before
planning:

```bash
AWS_PROFILE=sandbox aws service-quotas get-service-quota \
  --region us-east-2 \
  --service-code vpc \
  --quota-code L-F678F1CE \
  --query 'Quota.Value'

AWS_PROFILE=sandbox aws ec2 describe-vpcs \
  --region us-east-2 \
  --query 'length(Vpcs)'
```

If the count equals the quota, request at least one additional VPC before
applying the stack.

`scripts/tf.sh` uses a local Terraform binary when available. Otherwise, it
runs the pinned Terraform container with host networking.

## Topology

```text
frontend VPC                         backend/data VPC

storefront :8081 -> catalog :8082 -> checkout :8080
                                         |       |
                                         |       +-> RDS PostgreSQL :5432
                                         +-> legacy-api :8083
```

OBI runs on both ECS container instances and selects ports 8080 through 8082.
It instruments `storefront`, `catalog`, and `checkout`. It does not select
`legacy-api`, and none of the applications contain an OpenTelemetry SDK.

## Configure and review

```bash
cd aws-ecs-poc
cp terraform.tfvars.example terraform.tfvars
```

Set `owner` and `expires` in `terraform.tfvars`. The frontend uses the selected
or default VPC. Terraform creates a second VPC with CIDR `10.42.0.0/16`, VPC
peering, one public ECS-host subnet, two private RDS subnets, and their routes
and security groups.

The current sandbox subnet inherits the frontend VPC's main route table. The
PoC adds the backend VPC route to that table. If `subnet_id` is changed to a
subnet with an explicit route-table association, `network.tf` must target that
route table instead.

Run the plan yourself and review all replacements and created resources:

```bash
AWS_PROFILE=sandbox ./scripts/tf.sh init
AWS_PROFILE=sandbox ./scripts/tf.sh plan
```

The existing checkout EC2 instance is expected to be replaced because it moves
to the backend VPC and backend ECS cluster. The plan should also create one RDS
instance, three backend subnets, VPC peering, and the `legacy-api` ECR
repository.

## Apply the infrastructure and build images

Apply the reviewed base plan with no deployment variables:

```bash
AWS_PROFILE=sandbox ./scripts/tf.sh apply
```

Build and push all four application images:

```bash
AWS_PROFILE=sandbox ./scripts/build-images.sh
```

## Deploy the applications

Deploy `legacy-api` first. It runs as an ECS task, but its port is outside the
OBI discovery selectors:

```bash
AWS_PROFILE=sandbox ./scripts/tf.sh apply \
  -var deploy_legacy=true

legacy_ip=$(AWS_PROFILE=sandbox \
  ./scripts/service-ip.sh legacy-api beyla-nonk8s-poc-backend)
echo "$legacy_ip"
```

Deploy checkout with the literal legacy task address. Checkout also receives
the private RDS endpoint and its RDS-managed password:

```bash
AWS_PROFILE=sandbox ./scripts/tf.sh apply \
  -var deploy_legacy=true \
  -var deploy_checkout=true \
  -var legacy_ip="$legacy_ip"

checkout_ip=$(AWS_PROFILE=sandbox ./scripts/checkout-ip.sh)
echo "$checkout_ip"
```

Deploy catalog in the frontend VPC:

```bash
AWS_PROFILE=sandbox ./scripts/tf.sh apply \
  -var deploy_legacy=true \
  -var deploy_checkout=true \
  -var legacy_ip="$legacy_ip" \
  -var checkout_ip="$checkout_ip"

catalog_ip=$(AWS_PROFILE=sandbox ./scripts/service-ip.sh catalog)
echo "$catalog_ip"
```

Deploy storefront last:

```bash
AWS_PROFILE=sandbox ./scripts/tf.sh apply \
  -var deploy_legacy=true \
  -var deploy_checkout=true \
  -var legacy_ip="$legacy_ip" \
  -var checkout_ip="$checkout_ip" \
  -var catalog_ip="$catalog_ip"

storefront_ip=$(AWS_PROFILE=sandbox ./scripts/service-ip.sh storefront)
echo "$storefront_ip"
```

Keep these variables on later applies while the services remain deployed. Do
not store live task IPs in `terraform.tfvars`.

## Deploy the custom OBI resolver directly

Build the `ecs-service-resolution` OBI worktree:

```bash
make generate
go test ./pkg/internal/ecs ./pkg/transform ./pkg/obi
go vet ./pkg/internal/ecs ./pkg/transform ./pkg/obi
make check-config-schema
make compile
```

Deploy that binary to both EC2 hosts. This test does not record a released-Beyla
baseline:

```bash
AWS_PROFILE=sandbox \
OBI_BINARY=/path/to/obi/bin/obi \
./scripts/deploy-obi-resolver.sh
```

The helper uploads the binary and multi-cluster configuration, verifies its
checksum, and runs it through the existing `beyla` systemd unit.

## Verify application traffic

Open an SSM session to the caller host and use the storefront address printed
above. The response should contain all four application and database results:

```bash
storefront_ip=<storefront task IP>
curl -fsS "http://${storefront_ip}:8081/"
```

A successful response ends with:

```json
{"database":1,"legacy":"legacy-api","service":"checkout"}
```

Then inspect process and service graph metrics:

```bash
curl -fsS http://127.0.0.1:8999/metrics \
  | grep -E '^(survey_info|target_info|traces_service_graph_request_total)'
```

Use CloudWatch logs if the request fails at any hop.

## Verify the three identity cases

The already validated edges should remain named across the VPC boundary:

```prometheus
traces_service_graph_request_total{client="storefront",server="catalog",source="obi"}
traces_service_graph_request_total{client="catalog",server="checkout",source="obi"}
```

The uninstrumented ECS destination should also resolve through ECS inventory:

```prometheus
traces_service_graph_request_total{client="checkout",server="legacy-api",source="obi"}
```

Confirm that `legacy-api` has no local process telemetry. Its name may appear as
a remote `server` label, but it must not appear as an OBI-instrumented process:

```bash
curl -fsS http://127.0.0.1:8999/metrics \
  | grep -E '^(survey_info|target_info)' \
  | grep 'legacy-api'
```

The expected result is no output. Also check that there is no server-side
`checkout -> legacy-api` observation, because OBI does not instrument port
8083.

For RDS, capture every graph series containing PostgreSQL port 5432 or the RDS
private address:

```bash
curl -fsS http://127.0.0.1:8999/metrics \
  | grep '^traces_service_graph_request_total' \
  | grep -E '5432|10\.42\.'
```

The ECS resolver has no RDS inventory. This observation tells us whether the
PostgreSQL span preserves a useful database endpoint or exposes only a private
address. If it exposes an address, an RDS resolver can read DB identifiers and
endpoint hostnames from `DescribeDBInstances`, resolve those hostnames, and
refresh the resulting IP mapping.

## Cleanup

Preserve every active variable while destroying the stack:

```bash
AWS_PROFILE=sandbox ./scripts/tf.sh destroy \
  -var deploy_legacy=true \
  -var deploy_checkout=true \
  -var legacy_ip="$legacy_ip" \
  -var checkout_ip="$checkout_ip" \
  -var catalog_ip="$catalog_ip"
```

After destruction, check AWS Resource Explorer or Tag Editor for resources
tagged `Project=beyla-nonk8s-poc`.
