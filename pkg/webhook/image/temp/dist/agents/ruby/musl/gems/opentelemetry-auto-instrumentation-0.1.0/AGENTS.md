# Agent Instructions for opentelemetry-ruby-instrumentation

## Project Overview

This repository contains the `opentelemetry-auto-instrumentation` Ruby gem, which provides automatic zero-code instrumentation for Ruby applications by patching `Bundler::Runtime#require` to inject OpenTelemetry SDK initialization when gems are loaded.

**Key exported signals:** traces, metrics, and logs — all exported via OTLP to `http://localhost:4318` by default.

Before starting any task, read [CONTRIBUTING.md](CONTRIBUTING.md) and this file.

## Core Expectations

- Preserve OpenTelemetry specification compliance and idiomatic Ruby.
- Prefer minimal, surgical changes over broad refactors or speculative cleanup.
- Read the file you are editing and match its existing naming, error handling, comments, and test patterns.
- Keep telemetry resilient and loosely coupled — never introduce behavior that can unexpectedly interfere with the host application.
- Telemetry must be fail-safe: it should not raise, block indefinitely, or amplify attacker-controlled input.
- Keep dependencies minimal and justified.
- Write comments only for intent, invariants, and non-obvious constraints. Do not add comments that restate the code.

## Default Workflow

For new features and behavior changes, unless the task says otherwise:

1. Read the relevant file, its tests, and the `README.md`.
2. Add or update a failing unit test that captures the required behavior or regression.
3. Implement the smallest change that makes the test pass.
4. Refactor only after behavior is locked in, and only if it keeps the diff focused.
5. Update documentation (`README.md`, `CHANGELOG.md`) while the context is fresh.
6. Run `bundle exec rake test` before considering the work complete.

## Repository Structure

```console
lib/opentelemetry-auto-instrumentation.rb   # Main gem entry point; contains OTelBundlerPatch
lib/opentelemetry/auto_instrumentation/
  version.rb                                # Gem version
test/
  opentelemetry-auto-instrumentation_test.rb
  test_helper.rb
example/
  rails-example/                            # Rails usage example
  simple-example/                           # Plain Ruby usage example
.github/
  workflows/                                # CI, release, and Renovate automation
  renovate.json5                            # Dependency update config
```

## Development Environment

Always use Docker for development — do **not** install dependencies directly on the host:

```console
docker compose run app
```

This mounts the repo at `/app` with all Ruby dependencies pre-installed.

## Running Tests

```console
bundle exec rake test
```

All tests must pass before opening a pull request.

## Code Conventions

- All Ruby files must include `# frozen_string_literal: true` at the top.
- License header required: `# Copyright The OpenTelemetry Authors` / `# SPDX-License-Identifier: Apache-2.0`.
- Module/method names follow the `_otel_` prefix convention for internal OTel helpers (e.g., `_otel_snake_case`, `_otel_registry_aliases_for`).
- Environment variables use the `OTEL_RUBY_` prefix for gem-specific config; standard OTel env vars (e.g., `OTEL_SERVICE_NAME`) are passed through unchanged.

## Release Process

Releases are managed via GitHub Actions workflows (no `toys`/`toys-release`):

1. **`release-request.yml`** (`workflow_dispatch` with optional `version`/`changelog` inputs, or a weekly `schedule`) — bumps `lib/opentelemetry/auto_instrumentation/version.rb`, updates `CHANGELOG.md`, and opens a release PR labeled `release`. On the weekly schedule (and on manual runs without inputs), the version bump and changelog are auto-computed from conventional commit messages since the last release tag; the job is skipped if there are no new commits. Does **not** publish to RubyGems.
2. **`release.yml`** (triggered when a PR labeled `release` is merged) — builds the gem, publishes it to RubyGems.org using `GEM_HOST_API_KEY` (`RUBYGEMS_API_KEY` secret), and creates the GitHub release with the matching changelog notes.

Do not manually push gems or tag releases — always go through the workflow.

## Dependency Updates (Renovate)

Renovate runs on a weekly schedule:

- **Patch/digest updates:** before 6am on Monday
- **Minor updates:** before 7am on Monday
- **Major updates:** before 8am on Monday
- **Lock file maintenance:** before 4am on Tuesday

Ruby version updates in gemspecs and Dockerfile require dashboard approval (`dependencyDashboardApproval: true`) and a minimum release age of 820 days before a PR is opened.

## Key Environment Variables

| Variable | Purpose |
| --- | --- |
| `OTEL_RUBY_REQUIRE_BUNDLER` | Set `true` for frameworks that don't auto-call `Bundler.require` (e.g., Sinatra) |
| `OTEL_RUBY_ENABLED_INSTRUMENTATIONS` | Comma-separated list to load only specific instrumentations |
| `OTEL_RUBY_RESOURCE_DETECTORS` | Enable resource detectors: `container`, `azure`, `aws` |
| `OTEL_RUBY_ADDITIONAL_GEM_PATH` | Custom gem path for OpenTelemetry Operator environments |
| `DISALLOWED_LIB_PATH` | Exclude specific helper gems from `$LOAD_PATH` injection |
| `OTEL_RUBY_AUTO_INSTRUMENTATION_DEBUG` | Set `true` for debug output during initialization |

## Pull Request Guidelines

- One logical change per PR. Do not bundle multiple fixes, refactors, or features — split them so each can be reviewed and reverted independently.
- Keep AI-assisted PRs tightly scoped to the requested change; never include unrelated cleanup or opportunistic improvements unless strictly necessary for correctness.
- Add tests for any new functionality.
- Update documentation (README, CHANGELOG) as needed.
- Use [conventional commits](https://www.conventionalcommits.org/) — enforced by CI.

## AI Agent Rules

- **Never post AI-generated comments on issues or PRs.** Discussions on OpenTelemetry repositories are for humans only. You cannot comment on issue or PR threads on a user's behalf.
- If significant parts of a commit are produced by an AI tool, disclose it with an `Assisted-by:` commit message trailer (e.g., `Assisted-by: Claude Opus 4.8`).
- When catching exceptions from an instrumented library to record telemetry, re-raise the original exception unmodified. Do not raise new exceptions from instrumentation/telemetry code.

## Community

- Slack: [#otel-ruby](https://cloud-native.slack.com/archives/C01NWKKMKMY)
- Maintainers: [open-telemetry/ruby-instrumentation-approvers](https://github.com/orgs/open-telemetry/teams/ruby-instrumentation-approvers)
