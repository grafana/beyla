# Contributing to OpenTelemetry Ruby Instrumentation

We'd love your help! Use tags [good first issue](https://github.com/open-telemetry/opentelemetry-ruby-instrumentation/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) and [help wanted](https://github.com/open-telemetry/opentelemetry-ruby-instrumentation/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22) to get started with the project.

## How to Get Involved

The OpenTelemetry Ruby gems are maintained by the OpenTelemetry Ruby special interest group (SIG). You can get involved by:

- Joining us on [GitHub Discussions][discussions-url]
- Joining the [Slack Channel][slack-channel]
- Attending our weekly meeting — see the [meeting calendar][community-meetings] for dates and times

For more information on this and other language SIGs, see the OpenTelemetry [community page][ruby-sig].

## Development Setup

Build and start a development shell using Docker:

```console
docker compose run app
```

This mounts the repository at `/app` and provides a fully configured Ruby environment with all dependencies available.

## Running Tests

From inside the container (or via `docker compose run`):

```console
bundle exec rake test
```

## Opening Pull Requests

- Keep pull requests focused on a single concern.
- Add tests for any new functionality.
- Ensure all existing tests pass before submitting.
- Update documentation as needed.

## Code of Conduct

This project follows the [OpenTelemetry Community Code of Conduct](https://github.com/open-telemetry/community/blob/main/code-of-conduct.md).

[ruby-sig]: https://github.com/open-telemetry/community#ruby-sig
[community-meetings]: https://github.com/open-telemetry/community#community-meetings
[slack-channel]: https://cloud-native.slack.com/archives/C01NWKKMKMY
[discussions-url]: https://github.com/open-telemetry/opentelemetry-ruby-instrumentation/discussions
