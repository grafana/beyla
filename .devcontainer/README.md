# Development container

DevContainers development environment bundling Bash, Go, Make, Git, mise, and the Docker CLI.

The container copies its Go toolchain and standalone mise executable from
pinned image stages rather than installing them separately. Keep the mise
image pin aligned with the main build Dockerfile and its version aligned with
`.github/actions/setup-mise/action.yml`, so local and CI tasks use the same mise
version. Mise provides the task runner for the repository's `mise run`
commands.

## Requirements

- A running Docker Engine and CLI, Docker Desktop, or compatible Docker host.
- For the CLI workflow, install the
  [Dev Container CLI](https://code.visualstudio.com/docs/devcontainers/devcontainer-cli):
  `npm install -g @devcontainers/cli`.

## How to run

### Visual Studio Code

1. Install the **Dev Containers** extension (`ms-vscode-remote.remote-containers`).
2. Open the repository folder and run **Dev Containers: Reopen in Container**.
3. Use the integrated terminal to run the commands below. The Go extension is
   installed in the container.

Run **Dev Containers: Rebuild Container** after changing the dev container's
Dockerfile or configuration.

### Terminal CLI

Run these commands on the host, from the repository root:

```sh
devcontainer up --workspace-folder .
devcontainer exec --workspace-folder . bash
```

### IntelliJ IDEA

1. Open the local checkout in IntelliJ IDEA. Enable the **Docker** and
   **Dev Containers** plugins and configure the local Docker connection under
   **Build, Execution, Deployment > Docker**.
2. Open `.devcontainer/devcontainer.json`, click its gutter action, and select
   **Create Dev Container and Mount Sources**. Select IntelliJ IDEA as the backend.
3. Once the container is ready, click **Connect** in the **Services** tool window.
4. Enable the Go plugin in the backend for Go code intelligence and select
   `/usr/local/go` as the Go SDK.

Use **Mount Sources** with this configuration so the checkout paths match those
on the Docker host. See JetBrains' [Dev Container instructions](https://www.jetbrains.com/help/idea/start-dev-container-inside-ide.html)
for the IDE workflow. Rebuild the container after changing its configuration.

## Other aspects to consider

Development sessions run as the non-root `vscode` user so permission-sensitive
unit tests work correctly. The mounted Docker socket is useful for building
images and running container-backed integration tests; local OBI generation uses
`mise run vendor:obi` and does not require Docker. Use `sudo` only for commands
that need elevated permissions.

After updating an existing root-based container, rebuild it in your IDE or run
`devcontainer up --workspace-folder . --remove-existing-container` from the host.
On Linux, files previously created as root may need their ownership corrected
before the non-root user can overwrite them.

The development container is not privileged. Running OBI and its integration
tests still requires the Linux kernel, BTF, and permissions described in
[Beyla requirements](../docs/sources/requirements-and-security/requirements.md). Some integration tests access sibling
containers through `localhost`; run those tests on the Linux Docker host, or
configure host networking for the development container. Docker Desktop needs
its host-networking option enabled for that workflow. Building on macOS or
Windows does not make their native kernels capable of running eBPF programs.
