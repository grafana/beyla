# Development container

This configuration builds `.obi-src/generator.Dockerfile` with `.obi-src` as its
build context. A local Dev Container Feature adds IDE dependencies, CGO build
tools, gopls and Delve without modifying the upstream submodule. The generator's
one-shot entrypoint is overridden so the container stays available for editing.

Install Git and Docker with BuildKit support on the host. On Windows, open the
checkout from WSL. Open the repository root, not `.obi-src`. A missing submodule
is initialized automatically; an existing OBI checkout is left in place. The
first build needs network access to download the image, packages and Go tools.

## VS Code

Install Microsoft's **Dev Containers** extension, then run **Dev Containers:
Reopen in Container**. The Go extension, language server, formatter and debugger
are configured automatically. Use **Go: Debug Test At Cursor** to debug a test.

## IntelliJ IDEA

Enable the **Docker** and **Dev Containers** plugins in a recent IntelliJ IDEA
release with Go plugin support. Open `.devcontainer/devcontainer.json` and use
the gutter action **Create Dev Container and Mount Sources**. The configuration
selects IntelliJ and requests the Go plugin. If prompted for a Go SDK, select
`/usr/local/go`; GOPATH is `/go`.

The image is Alpine-based. It includes the compatibility and runtime libraries
listed in [JetBrains' prerequisites](https://www.jetbrains.com/help/idea/prerequisites-for-dev-containers.html),
including gcompat. Backend compatibility depends on the IntelliJ version;
older backends may not support Alpine. JetBrains documents Docker as the
supported runtime; alternative runtimes such as OrbStack are not guaranteed.

## Terminal

Install Node.js and npm on the host in addition to Git and Docker. Start Docker
and, if using Docker Desktop, enable host networking as described below. Run
these commands from the repository root in a host terminal:

```sh
# Build the image, create/start the container, and run its setup hooks.
npx --yes @devcontainers/cli up --workspace-folder .

# Open an interactive shell as vscode in the mounted checkout.
npx --yes @devcontainers/cli exec --workspace-folder . bash
```

`npx` downloads and runs the Dev Containers CLI without a global installation.
The first `up` initializes a missing OBI submodule and builds the toolchain;
later calls reuse the existing container. Its startup hook enables Docker
access inside the container. The CLI does not launch an IDE.

Inside the shell, verify the environment and run commands normally:

```sh
go env GOROOT GOPATH
docker info
go test ./pkg/services
exit
```

You can also run a single command directly from the host:

```sh
npx --yes @devcontainers/cli exec --workspace-folder . go test ./pkg/services
```

After changing the dev container configuration or Dockerfile, recreate it from
the host terminal:

```sh
npx --yes @devcontainers/cli up --workspace-folder . --remove-existing-container
```

This replaces the CLI-managed container and its internal caches; files in the
mounted checkout remain on the host. Add `--build-no-cache` if you also want to
refresh cached image layers and tool downloads. Recreate IntelliJ-managed
containers through IntelliJ, since it tracks containers separately.

Exiting a shell leaves the container running. To stop it, use
`docker stop <containerId>` on the host, replacing `<containerId>` with the
`containerId` returned by `up`. Run `up` again before opening another shell;
this also reruns the Docker socket startup hook.

## Working in the container

The checkout is mounted at the same absolute path as on the host, so Docker
bind mounts from integration tests resolve correctly. Terminals run as the `vscode`
user (also for IntelliJ), with passwordless sudo for additional development
packages. Compatible clients adjust that user's UID to match the Linux host.
The container also defaults to that user, and exports `GOROOT=/usr/local/go`
and `GOPATH=/go` for terminals and IDE processes alike.
Shell startup also clears IntelliJ's injected host Go SDK overrides, so its
terminal uses the Linux SDK even when the local IDE uses a macOS SDK. For IDE
run configurations, select the container SDK at `/usr/local/go`.

```sh
make generate
go build ./cmd/beyla
go test ./pkg/...
```

Use `make generate` directly: the compiler and protobuf/eBPF tools are already
installed. Docker CLI, Compose and Buildx are also installed. The host Docker
socket is mounted and proxied to `/var/run/docker.sock` for the `vscode` user;
`docker info`, `make docker-generate` and integration tests use that daemon.
Containers launched here are siblings on the host daemon. This grants access
to the host daemon and its containers, so use this setup with trusted code.

Host networking lets tests reach sibling containers' published `localhost`
ports. On Docker Desktop, [enable host networking](https://docs.docker.com/engine/network/drivers/host/)
in its settings; native Linux
and OrbStack also support this layout. Avoid concurrent test suites that publish
the same ports. A remote daemon must have the checkout available at the same
absolute path. The socket mount assumes `/var/run/docker.sock` on the daemon
host; adjust its source for a rootless Docker installation.

After updating this configuration, recreate the dev container to apply the
socket mount, network mode and workspace path. Go caches live inside the
container and survive restarts, but are reset on rebuild. Editor tools are
resolved to their current releases when the feature is built.

Ptrace and an unconfined seccomp profile allow Delve debugging. Running Beyla's
eBPF instrumentation additionally requires suitable Linux kernel capabilities
and privileges; this editing/build container does not grant those by default.
On macOS and Windows, any container instrumentation targets the Docker Linux
VM, not the host OS.

Rebuild the container after changing the generator Dockerfile or this
configuration. See the [VS Code container documentation](https://code.visualstudio.com/docs/devcontainers/containers)
and [IntelliJ startup instructions](https://www.jetbrains.com/help/idea/start-dev-container-inside-ide.html).
