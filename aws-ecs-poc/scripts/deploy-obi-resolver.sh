#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
project_dir=$(cd -- "${script_dir}/.." && pwd)
aws_profile=${AWS_PROFILE:-sandbox}
aws_region=${AWS_REGION:-us-east-2}
instance_name=${INSTANCE_NAME:-beyla-nonk8s-poc-*}
obi_binary=${OBI_BINARY:-${project_dir}/../../wt/opentelemetry-ebpf-instrumentation/ecs-service-resolution/bin/obi}
obi_config=${OBI_CONFIG:-${project_dir}/configs/obi-ecs.yaml}

for command in aws scp ssh ssh-keygen python3; do
  command -v "${command}" >/dev/null || {
    echo "required command not found: ${command}" >&2
    exit 1
  }
done

[[ -x ${obi_binary} ]] || {
  echo "OBI binary not found or not executable: ${obi_binary}" >&2
  exit 1
}
[[ -f ${obi_config} ]] || {
  echo "OBI config not found: ${obi_config}" >&2
  exit 1
}

mapfile -t instance_ids < <(
  aws ec2 describe-instances \
    --profile "${aws_profile}" \
    --region "${aws_region}" \
    --filters \
      "Name=tag:Name,Values=${instance_name}" \
      "Name=instance-state-name,Values=running" \
    --query 'Reservations[].Instances[].InstanceId' \
    --output text \
    | tr '\t' '\n' \
    | sort
)

if [[ ${#instance_ids[@]} -ne 2 ]]; then
  echo "expected 2 running PoC instances, found ${#instance_ids[@]}" >&2
  printf '%s\n' "${instance_ids[@]}" >&2
  exit 1
fi

temp_dir=$(mktemp -d)
tunnel_pid=
cleanup() {
  if [[ -n ${tunnel_pid} ]]; then
    kill "${tunnel_pid}" 2>/dev/null || true
    wait "${tunnel_pid}" 2>/dev/null || true
  fi
  rm -rf "${temp_dir}"
}
trap cleanup EXIT

ssh_key=${temp_dir}/obi-resolver
ssh-keygen -q -t rsa -b 2048 -N '' -f "${ssh_key}"
binary_checksum=$(sha256sum "${obi_binary}" | awk '{print $1}')

send_ssh_key() {
  local instance_id=$1
  local availability_zone=$2
  aws ec2-instance-connect send-ssh-public-key \
    --profile "${aws_profile}" \
    --region "${aws_region}" \
    --instance-id "${instance_id}" \
    --availability-zone "${availability_zone}" \
    --instance-os-user ec2-user \
    --ssh-public-key "file://${ssh_key}.pub" \
    >/dev/null
}

for instance_id in "${instance_ids[@]}"; do
  availability_zone=$(
    aws ec2 describe-instances \
      --profile "${aws_profile}" \
      --region "${aws_region}" \
      --instance-ids "${instance_id}" \
      --query 'Reservations[0].Instances[0].Placement.AvailabilityZone' \
      --output text
  )
  local_port=$(
    python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
  )

  echo "Opening SSM tunnel to ${instance_id} on local port ${local_port}"
  aws ssm start-session \
    --profile "${aws_profile}" \
    --region "${aws_region}" \
    --target "${instance_id}" \
    --document-name AWS-StartPortForwardingSession \
    --parameters "portNumber=22,localPortNumber=${local_port}" \
    </dev/null >"${temp_dir}/${instance_id}.ssm.log" 2>&1 &
  tunnel_pid=$!

  for _ in {1..30}; do
    if (echo >/dev/tcp/127.0.0.1/"${local_port}") 2>/dev/null; then
      break
    fi
    sleep 1
  done
  if ! (echo >/dev/tcp/127.0.0.1/"${local_port}") 2>/dev/null; then
    cat "${temp_dir}/${instance_id}.ssm.log" >&2
    echo "SSM tunnel did not become ready for ${instance_id}" >&2
    exit 1
  fi

  send_ssh_key "${instance_id}" "${availability_zone}"
  scp \
    -P "${local_port}" \
    -i "${ssh_key}" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    "${obi_binary}" "${obi_config}" \
    ec2-user@127.0.0.1:/tmp/

  send_ssh_key "${instance_id}" "${availability_zone}"
  ssh \
    -p "${local_port}" \
    -i "${ssh_key}" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    ec2-user@127.0.0.1 \
    sudo sh -s -- "${binary_checksum}" <<'REMOTE'
set -eu

expected_checksum=$1
actual_checksum=$(sha256sum /tmp/obi | awk '{print $1}')
if [ "${actual_checksum}" != "${expected_checksum}" ]; then
  echo "uploaded OBI binary checksum does not match" >&2
  exit 1
fi

backup_dir=/var/lib/beyla/ecs-resolver-backup
mkdir -p "${backup_dir}"
if [ ! -f "${backup_dir}/beyla.yaml" ]; then
  cp /etc/beyla/beyla.yaml "${backup_dir}/beyla.yaml"
  cp /etc/systemd/system/beyla.service "${backup_dir}/beyla.service"
fi

install -m 0755 /tmp/obi /usr/local/bin/obi
install -m 0644 /tmp/obi-ecs.yaml /etc/beyla/beyla.yaml
sed -i 's#/usr/local/bin/beyla#/usr/local/bin/obi#' /etc/systemd/system/beyla.service
systemctl daemon-reload

if ! systemctl restart beyla || ! systemctl is-active --quiet beyla; then
  cp "${backup_dir}/beyla.yaml" /etc/beyla/beyla.yaml
  cp "${backup_dir}/beyla.service" /etc/systemd/system/beyla.service
  systemctl daemon-reload
  systemctl restart beyla
  echo "custom OBI failed to start; restored the previous service" >&2
  exit 1
fi

sleep 5
if ! systemctl is-active --quiet beyla; then
  cp "${backup_dir}/beyla.yaml" /etc/beyla/beyla.yaml
  cp "${backup_dir}/beyla.service" /etc/systemd/system/beyla.service
  systemctl daemon-reload
  systemctl restart beyla
  echo "custom OBI stopped after startup; restored the previous service" >&2
  exit 1
fi

systemctl status beyla --no-pager
REMOTE

  kill "${tunnel_pid}" 2>/dev/null || true
  wait "${tunnel_pid}" 2>/dev/null || true
  tunnel_pid=
done

echo "Custom OBI resolver is running on both PoC instances."
