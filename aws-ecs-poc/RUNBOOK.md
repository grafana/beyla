# AWS ECS service identity PoC runbook

This runbook reproduces the experiment described in [README.md](./README.md).

## Prerequisites

- Docker
- AWS CLI v2
- AWS Session Manager plugin
- SSH and SCP
- A refreshed `sandbox` SSO profile
- Permission to use EC2 Instance Connect and SSM sessions

Refresh credentials from the `deployment_tools` checkout:

```bash
./scripts/sso/aws.sh dev
aws sts get-caller-identity --profile sandbox
```

`scripts/tf.sh` uses a local Terraform binary when available. Otherwise, it
runs the pinned Terraform container with host networking.

## Configure

```bash
cd aws-ecs-poc
cp terraform.tfvars.example terraform.tfvars
```

Set `owner` and `expires` in `terraform.tfvars`. The stack uses the first subnet
in the default `us-east-2` VPC unless `vpc_id` and `subnet_id` are supplied.

The subnet must let the EC2 hosts reach ECS, ECR, SSM, GitHub, and the configured
telemetry endpoints. ECS task ENIs only need private addresses.

## Deploy the base infrastructure

Create the network resources, IAM roles, ECS cluster, EC2 hosts, ECR
repositories, and released Beyla installations:

```bash
AWS_PROFILE=sandbox ./scripts/tf.sh init
AWS_PROFILE=sandbox ./scripts/tf.sh apply
```

Build and push the application images:

```bash
AWS_PROFILE=sandbox ./scripts/build-images.sh
```

## Deploy the applications

Create checkout:

```bash
AWS_PROFILE=sandbox ./scripts/tf.sh apply -var deploy_checkout=true
```

Read the checkout task's ENI address:

```bash
checkout_ip=$(AWS_PROFILE=sandbox ./scripts/checkout-ip.sh)
echo "$checkout_ip"
```

Create storefront with that literal destination:

```bash
AWS_PROFILE=sandbox ./scripts/tf.sh apply \
  -var deploy_checkout=true \
  -var checkout_ip="$checkout_ip"
```

Keep both variables set on later applies while the services should remain
running. Do not store a live task IP in `terraform.tfvars`.

## Record the baseline

Open each instance through Session Manager and inspect its local metrics:

```bash
sudo systemctl status beyla --no-pager

curl -fsS http://127.0.0.1:8999/metrics \
  | grep -E '^(target_info|survey_info|traces_service_graph_)'
```

Before the ECS resolver is installed, service graph labels should contain the
remote task IP or a generated ECS container name.

## Build the OBI resolver

From the OBI `ecs-service-resolution` worktree:

```bash
make generate
go test ./pkg/internal/ecs ./pkg/transform ./pkg/obi
go vet ./pkg/internal/ecs ./pkg/transform ./pkg/obi
make check-config-schema
make compile
```

The resulting binary is `bin/obi`.

## Deploy the OBI resolver

The deployment helper defaults to the worktree path used during the original
experiment. Set `OBI_BINARY` when the binary is elsewhere:

```bash
AWS_PROFILE=sandbox \
OBI_BINARY=/path/to/obi/bin/obi \
./scripts/deploy-obi-resolver.sh
```

The helper:

1. Finds both running PoC EC2 instances by tag.
2. Opens an SSH tunnel through SSM.
3. Uploads the custom OBI binary and ECS resolver configuration.
4. Verifies the binary checksum.
5. Restarts the existing `beyla` systemd service with the OBI binary.
6. Restores the previous service and configuration if OBI does not remain
   active.

The original files are stored under `/var/lib/beyla/ecs-resolver-backup` on each
host.

## Verify the resolved graph

On both EC2 hosts:

```bash
sudo systemctl is-active beyla
sudo systemctl show beyla --no-pager -p ExecStart --value

curl -fsS http://127.0.0.1:8999/metrics \
  | grep '^traces_service_graph_'
```

Expected edge:

```prometheus
traces_service_graph_request_total{
  client="storefront",
  server="checkout",
  source="obi"
}
```

The actual metric also contains namespace and connection type labels. The edge
must not contain either task IP or an `ecs-...` generated container name.

## Test task replacement

Force checkout onto a new task ENI:

```bash
AWS_PROFILE=sandbox aws ecs update-service \
  --region us-east-2 \
  --cluster beyla-nonk8s-poc \
  --service checkout \
  --force-new-deployment

AWS_PROFILE=sandbox aws ecs wait services-stable \
  --region us-east-2 \
  --cluster beyla-nonk8s-poc \
  --services checkout
```

Read the replacement address and update storefront:

```bash
checkout_ip=$(AWS_PROFILE=sandbox ./scripts/checkout-ip.sh)

AWS_PROFILE=sandbox ./scripts/tf.sh apply \
  -var deploy_checkout=true \
  -var checkout_ip="$checkout_ip"
```

After the next 30-second inventory refresh, verify that the graph still reports
`server="checkout"`.

## Cleanup

Read the current checkout address before destroying the stack:

```bash
checkout_ip=$(AWS_PROFILE=sandbox ./scripts/checkout-ip.sh)

AWS_PROFILE=sandbox ./scripts/tf.sh destroy \
  -var deploy_checkout=true \
  -var checkout_ip="$checkout_ip"
```

After destruction, check AWS Resource Explorer or Tag Editor for resources
tagged `Project=beyla-nonk8s-poc`.
