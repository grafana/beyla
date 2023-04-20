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

local docker(prefix, arch, app) = {
  name: '%s-%s-image' % [prefix, if $.settings.dry_run then 'build-' + app else 'publish-' + app],
  image: 'plugins/docker',
  settings: {
    repo: 'grafana/%s' % app,
    dockerfile: 'Dockerfile',
    username: { from_secret: docker_username_secret.name },
    password: { from_secret: docker_password_secret.name },
    dry_run: false,
  },
};

local manifest(app) = pipeline('manifest') {
  steps+: [{
    name: 'manifest-' + app,
    image: 'plugins/manifest',
    settings: {
      // the target parameter is abused for the app's name,
      // as it is unused in spec mode. See docker-manifest.tmpl
      target: app,
      spec: '.drone/docker-manifest.tmpl',
      ignore_missing: false,
      username: { from_secret: docker_username_secret.name },
      password: { from_secret: docker_password_secret.name },
    },
    depends_on: ['clone'],
  }],
  depends_on: [
    'docker-%s' % arch
    for arch in archs
  ],
};

local arch_image(arch, tags='') = {
  platform: {
    os: 'linux',
    arch: arch,
  },
  steps: [{
    name: 'image-tag',
    image: 'alpine',
    commands: [
      'apk add --no-cache bash git',
      'git fetch origin --tags',
      'echo $(./tools/image-tag)-%s > .tags' % arch,
    ] + if tags != '' then ['echo ",%s" >> .tags' % tags] else [],
  }],
};

local multiarch_image(arch, app) = pipeline('docker-' + arch) + arch_image(arch) {
  steps+: [
    // dry run for everything that is not tag or main
    docker('pr', arch, app) {
      depends_on: ['image-tag'],
      when: onPRs,
      settings+: {
        dry_run: true,
      },
    },
    // publish after merge into main. Replace main image and add commit tag
    docker('main', arch, app) {
      depends_on: ['image-tag'],
      when: onMain,
      settings+: {
        force_tag: true,
        // TAG: first 8 characters of drone commit
        tags: ['${DRONE_COMMIT_SHA:0:8}', 'main'],
      },
    },
    // publish for new labels into main
    docker('tag', arch, app) {
      depends_on: ['image-tag'],
      when: onTag,
      settings+: {
        auto_tag: true,
      },
    },
  ],
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
  ],
};

// TODO: don't create images if unit tests nor integration tests pass
[
  multiarch_image(arch, 'ebpf-autoinstrument')
  for arch in archs
] + [
  manifest('ebpf-autoinstrument'),
] + [
  docker_username_secret,
  docker_password_secret,
]
