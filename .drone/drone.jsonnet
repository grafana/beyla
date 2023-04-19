# Run "make drone" to regenerate drone.yml from this file
local archs = ['arm64','amd64'];

local onPRs = {
  event: ['pull_request'],
};

local onTagOrMain = {
  event: ['push', 'tag'],
};

local pipeline(name) = {
  kind: 'pipeline',
  name: name,
  steps: [],
  trigger: {
    // Only trigger pipelines for PRs, tags (v*), or pushes to "main".
    ref: ['refs/heads/main', 'refs/tags/v*'],
  },
};

local secret(name, vault_path, vault_key) = {
  kind: 'secret',
  name: name,
  get: {
    path: vault_path,
    name: vault_key,
  },
};
local docker_username_secret = secret('docker_username', 'infra/data/ci/docker_hub', 'username');
local docker_password_secret = secret('docker_password', 'infra/data/ci/docker_hub', 'password');

local docker(arch, app) = {
  name: '%s-image' % if $.settings.dry_run then 'build-' + app else 'publish-' + app,
  image: 'plugins/docker',
  settings: {
    repo: 'grafana/%s' % app,
    dockerfile: 'Dockerfile',
    username: { from_secret: docker_username_secret.name },
    password: { from_secret: docker_password_secret.name },
    dry_run: false,
  },
};

local autoinstrument(arch) = pipeline('ebpf-autoinstrument-' + arch) {
    steps+: [
        docker(arch, 'ebpf-autoinstrument') {
            when: onPRs,
            settings+: {
                dry_run: true,
            },
        },
    ] + [
        docker(arch, 'ebpf-autoinstrument') {
            when: onTagOrMain,
        },
    ]
};

[
    autoinstrument(arch) for arch in archs
] + [
    docker_username_secret,
    docker_password_secret,
]
