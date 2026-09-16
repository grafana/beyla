#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
project_dir=$(cd -- "${script_dir}/.." && pwd)
aws_profile=${AWS_PROFILE:-sandbox}
aws_region=${AWS_REGION:-us-east-2}

account_id=$(aws sts get-caller-identity \
  --profile "${aws_profile}" \
  --query Account \
  --output text)

aws ecr get-login-password --profile "${aws_profile}" --region "${aws_region}" \
  | docker login --username AWS --password-stdin \
    "${account_id}.dkr.ecr.${aws_region}.amazonaws.com"

for app in checkout storefront; do
  repository=$(
    "${script_dir}/tf.sh" output -json ecr_repository_urls \
      | python3 -c "import json, sys; print(json.load(sys.stdin)['${app}'])"
  )

  image_tag=1
  if [[ "${app}" == "checkout" ]]; then
    image_tag=2
  fi

  docker build --network host -t "${repository}:${image_tag}" "${project_dir}/apps/${app}"
  docker push "${repository}:${image_tag}"
done
