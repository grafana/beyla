// Run "make drone" to regenerate drone.yml from this file
local archs = ['arm64', 'amd64'];

local onPRs = {
  event: ['pull_request'],
};

local onTag = {
  event: ['tag'],
};

local onMain = {
  event: ['push'],
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

local buildx(stepName, app, auto_tag, tags) = {
  name: 'beyla-%s-docker-buildx' % stepName,
  image: 'thegeeklab/drone-docker-buildx:24',
  privileged: true,
  settings: {
    auto_tag: auto_tag,
    build_args_from_env: ['DRONE_TAG'],
    tags: tags,
    repo: 'grafana/%s' % app,
    dockerfile: 'Dockerfile',
    platforms: ['linux/%s' % arch for arch in archs],
    username: { from_secret: docker_username_secret.name },
    password: { from_secret: docker_password_secret.name },
    dry_run: false,
  },
};

local beyla() = pipeline('beyla') {
  steps+: [
    buildx('dryrun', 'beyla-dryrun', false, 'test') {
      when: onPRs,  // TODO: if container creation fails, make the PR fail
      settings+: {
        dry_run: true,
      },
    },
  ] + [
    // on each new version, it tags version `a.b.c` and `a.b`
    buildx('tagged', 'beyla', true, '') {
      when: onTag,
    },
  ] + [
    // on each new version, it tags version `latest`,
    // equivalent to the versions from the previous section
    buildx('latest', 'beyla', false, 'latest') {
      when: onTag,
    },
  ] + [
    buildx('main', 'beyla', false, 'main') {
      when: onMain,
    },
  ],
};

// TODO: don't create images if unit tests nor integration tests pass
[
  beyla(),
] + [
  docker_username_secret,
  docker_password_secret,
]
