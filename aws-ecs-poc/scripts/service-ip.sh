#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 SERVICE [CLUSTER]" >&2
  exit 2
fi

service=$1
cluster=${2:-beyla-nonk8s-poc}
aws_profile=${AWS_PROFILE:-sandbox}
aws_region=${AWS_REGION:-us-east-2}

task_arn=$(aws ecs list-tasks \
  --profile "${aws_profile}" \
  --region "${aws_region}" \
  --cluster "${cluster}" \
  --service-name "${service}" \
  --desired-status RUNNING \
  --query 'taskArns[0]' \
  --output text)

if [[ -z ${task_arn} || ${task_arn} == None ]]; then
  echo "no running ${service} task found in ${cluster}" >&2
  exit 1
fi

aws ecs describe-tasks \
  --profile "${aws_profile}" \
  --region "${aws_region}" \
  --cluster "${cluster}" \
  --tasks "${task_arn}" \
  --query "tasks[0].attachments[].details[?name=='privateIPv4Address'].value | [0]" \
  --output text
