#!/usr/bin/env bash
set -euo pipefail

aws_profile=${AWS_PROFILE:-sandbox}
aws_region=${AWS_REGION:-us-east-2}
cluster=${ECS_CLUSTER:-beyla-nonk8s-poc}

task_arn=$(aws ecs list-tasks \
  --profile "${aws_profile}" \
  --region "${aws_region}" \
  --cluster "${cluster}" \
  --service-name checkout \
  --desired-status RUNNING \
  --query 'taskArns[0]' \
  --output text)

if [[ -z ${task_arn} || ${task_arn} == None ]]; then
  echo "no running checkout task found" >&2
  exit 1
fi

aws ecs describe-tasks \
  --profile "${aws_profile}" \
  --region "${aws_region}" \
  --cluster "${cluster}" \
  --tasks "${task_arn}" \
  --query "tasks[0].attachments[].details[?name=='privateIPv4Address'].value | [0]" \
  --output text
